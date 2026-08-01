"""Typer commands and application orchestration for Macaw."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import socket
import threading
from typing import Optional

import typer
from rich.prompt import Confirm, Prompt

from cli.interface import (
    banner,
    console,
    error,
    info,
    render_contacts,
    render_history,
    render_settings,
    success,
)
from cli.menu import run_interactive
from config.identity import Identity
from config.settings import DataPaths, Settings, default_data_dir
from contacts.contacts import Contact, ContactBook
from contacts.invitations import InvitationRegistry
from network.listener import IncomingMessage, IncomingPeer, MacawListener
from network.peer import PeerConnection
from storage.cleanup import cleanup_expired_messages
from storage.history import HistoryStore
from utils.address import MacawAddress
from utils.validation import ValidationError, validate_host, validate_port, validate_username

app = typer.Typer(
    name="macaw",
    help="A local-first, encrypted peer-to-peer terminal messenger.",
    add_completion=False,
    no_args_is_help=False,
)


@dataclass(frozen=True, slots=True)
class Profile:
    """The initialized local identity and settings required by network commands."""

    identity: Identity
    username: str
    settings: Settings


class MacawService:
    """Coordinates the local-only components behind the CLI."""

    def __init__(self, data_dir: Path | None = None) -> None:
        root = (data_dir or default_data_dir()).expanduser().resolve()
        self.paths = DataPaths(root)
        self.paths.ensure_exists()
        self.settings = Settings.load(self.paths)
        self.contact_book = ContactBook(self.paths.contacts_file)
        self.history = HistoryStore(self.paths.history_dir)
        self.invitations = InvitationRegistry(self.paths.invitations_file)
        self._contacts_lock = threading.Lock()

    def initialize(self, username: str, force: bool = False) -> Profile:
        """Create the device identity and first local configuration."""
        normalized = validate_username(username)
        if self.settings.username and self.settings.username != normalized and not force:
            raise RuntimeError(
                f"this profile is already named '{self.settings.username}'; use --force to rename it"
            )
        identity = Identity.load_or_create(self.paths)
        self.settings.username = normalized
        self.settings.save(self.paths)
        self._ensure_contact_file()
        return Profile(identity=identity, username=normalized, settings=self.settings)

    def profile(self) -> Profile:
        """Load an existing identity, running routine retention cleanup first."""
        if not self.settings.username or not self.paths.identity_private_key.exists():
            raise RuntimeError("Macaw has not been initialized. Run `macaw init` first.")
        identity = Identity.load(self.paths)
        cleanup_expired_messages(self.history, self.settings.retention_days)
        return Profile(identity=identity, username=self.settings.username, settings=self.settings)

    def issue_address(self, advertised_host: str | None = None) -> MacawAddress:
        profile = self.profile()
        host = self._advertised_host(advertised_host)
        invitation = self.invitations.create()
        return MacawAddress(profile.username, host, profile.settings.listen_port, invitation.code)

    def add_contact(self, address: MacawAddress) -> Contact:
        """Pair with a listener that issued *address* and save its verified identity."""
        profile = self.profile()
        with PeerConnection.connect(
            address,
            identity=profile.identity,
            username=profile.username,
            local_listen_port=profile.settings.listen_port,
        ) as peer:
            if not peer.session.is_new_pairing:
                raise RuntimeError("peer did not accept this address as a new invitation")
            contact = Contact.create(
                username=peer.session.remote_username,
                host=address.host,
                port=address.port,
                identity_key=base64.b64encode(peer.session.remote_identity_key).decode("ascii"),
            )
            with self._contacts_lock:
                return self.contact_book.add(contact)

    def resolve_contact(self, query: str) -> Contact:
        """Resolve a case-insensitive name or the displayed one-based contact number."""
        contacts = self.contact_book.list()
        if query.isdecimal():
            index = int(query) - 1
            if 0 <= index < len(contacts):
                return contacts[index]
        contact = self.contact_book.get(query)
        if contact is None:
            raise RuntimeError(f"no contact named '{query}'")
        return contact

    def connect_contact(self, query: str) -> tuple[Contact, PeerConnection]:
        profile = self.profile()
        contact = self.resolve_contact(query)
        connection = PeerConnection.connect_saved(
            contact,
            identity=profile.identity,
            username=profile.username,
            local_listen_port=profile.settings.listen_port,
        )
        return contact, connection

    def send_to_contact(self, query: str, body: str) -> Contact:
        contact, connection = self.connect_contact(query)
        with connection:
            connection.send(body)
        self.history.append(contact, "outgoing", body)
        return contact

    def remove_contact(self, query: str) -> Contact:
        contact = self.resolve_contact(query)
        with self._contacts_lock:
            removed = self.contact_book.remove(contact.username)
        if removed is None:
            raise RuntimeError(f"no contact named '{query}'")
        self.history.delete(removed)
        return removed

    def clear_history(self, query: str) -> tuple[Contact, int]:
        contact = self.resolve_contact(query)
        return contact, self.history.clear(contact)

    def update_settings(
        self,
        username: str | None = None,
        listen_host: str | None = None,
        listen_port: int | None = None,
        retention_days: int | None = None,
    ) -> Settings:
        if username is not None:
            self.settings.username = validate_username(username)
        if listen_host is not None:
            self.settings.listen_host = validate_host(listen_host)
        if listen_port is not None:
            self.settings.listen_port = validate_port(listen_port)
        if retention_days is not None:
            self.settings.retention_days = retention_days
        self.settings.save(self.paths)
        return self.settings

    def listen(self) -> None:
        """Run a direct listener until Ctrl-C, persisting incoming local messages."""
        profile = self.profile()
        cleanup_stop = threading.Event()

        def cleanup_loop() -> None:
            # Cleanup also runs before every command, but a long-running listener
            # should enforce retention even when no new peer connects.
            while not cleanup_stop.wait(60):
                cleanup_expired_messages(self.history, profile.settings.retention_days)

        def on_pairing(peer: IncomingPeer) -> None:
            contact = self._store_incoming_peer(peer)
            success(f"Paired with {contact.username}. Fingerprint: {contact.fingerprint}")

        def on_message(message: IncomingMessage) -> None:
            self.history.append(message.peer.session.remote_username, "incoming", message.body)
            console.print(f"\n[bold cyan]{message.peer.session.remote_username}:[/bold cyan] {message.body}")

        def on_listener_error(exc: Exception) -> None:
            text = str(exc)
            if text not in {"peer closed the connection", "timed out while waiting for peer data"}:
                error(f"Peer connection: {text}")

        listener = MacawListener(
            identity=profile.identity,
            username=profile.username,
            host=profile.settings.listen_host,
            port=profile.settings.listen_port,
            invitations=self.invitations,
            is_trusted_identity=self.contact_book.trusts,
            on_pairing=on_pairing,
            on_message=on_message,
            on_error=on_listener_error,
        )
        bound_port = listener.start()
        info(f"Listening directly on {profile.settings.listen_host}:{bound_port}. Press Ctrl-C to stop.")
        cleanup_thread = threading.Thread(target=cleanup_loop, name="macaw-retention", daemon=True)
        cleanup_thread.start()
        try:
            address = self.issue_address()
            info("A new one-time invitation (expires in 5 minutes):")
            console.print(f"[bold]{address}[/bold]")
            listener.serve_forever()
        except KeyboardInterrupt:
            console.print()
            info("Listener stopped.")
        finally:
            cleanup_stop.set()
            cleanup_thread.join(timeout=1)
            listener.close()

    def _store_incoming_peer(self, peer: IncomingPeer) -> Contact:
        """Save the other side of a successful invitation pairing."""
        encoded_key = base64.b64encode(peer.session.remote_identity_key).decode("ascii")
        with self._contacts_lock:
            existing = self.contact_book.get_by_identity_key(peer.session.remote_identity_key)
            contact = Contact(
                username=existing.username if existing else peer.session.remote_username,
                host=peer.host,
                port=peer.session.remote_listen_port,
                identity_key=encoded_key,
                added_at=existing.added_at if existing else datetime.now(UTC).isoformat(),
            )
            return self.contact_book.add(contact)

    def _ensure_contact_file(self) -> None:
        if self.paths.contacts_file.exists():
            return
        self.paths.contacts_file.parent.mkdir(parents=True, exist_ok=True)
        self.paths.contacts_file.write_text('{\n  "version": 1,\n  "contacts": []\n}\n', encoding="utf-8")
        self.paths.contacts_file.chmod(0o600)

    def _advertised_host(self, requested: str | None) -> str:
        if requested:
            return validate_host(requested)
        configured = self.settings.listen_host
        if configured not in {"0.0.0.0", "::"}:
            return configured
        # UDP connect assigns a local interface without sending application data.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))
            return str(probe.getsockname()[0])
        except OSError:
            return "127.0.0.1"
        finally:
            probe.close()


def _service(ctx: typer.Context) -> MacawService:
    service = ctx.obj
    if not isinstance(service, MacawService):
        raise RuntimeError("Macaw CLI was not initialized")
    return service


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    data_dir: Optional[Path] = typer.Option(
        None,
        "--data-dir",
        help="Directory for local keys, contacts, and history (never uploaded).",
    ),
) -> None:
    """Start the interactive menu when no command is supplied."""
    ctx.obj = MacawService(data_dir)
    if ctx.invoked_subcommand is None:
        run_interactive(ctx.obj)


@app.command("init")
def initialize(
    ctx: typer.Context,
    username: Optional[str] = typer.Argument(None, help="Your 3–32 character Macaw username."),
    force: bool = typer.Option(False, "--force", help="Rename an existing local profile."),
) -> None:
    """Create your local identity, keys, settings, and contact storage."""
    if username is None:
        username = Prompt.ask("Choose a username")
    profile = _service(ctx).initialize(username, force=force)
    banner(profile.username)
    success("Identity generated")
    success("Ed25519 public and private keys stored locally")
    success("Local database and contact storage ready")
    info(f"Identity fingerprint: {profile.identity.fingerprint}")


@app.command("address")
def address(
    ctx: typer.Context,
    host: Optional[str] = typer.Option(
        None,
        "--host",
        help="Reachable IP or hostname to place in the address (useful behind NAT).",
    ),
) -> None:
    """Create one five-minute, one-time invitation address."""
    invitation = _service(ctx).issue_address(host)
    banner()
    info("Copy this address to the person you want to pair with:")
    console.print(f"[bold cyan]{invitation}[/bold cyan]")
    info("It expires in 5 minutes and is deleted immediately after successful pairing.")


@app.command("add")
def add(
    ctx: typer.Context,
    invitation: Optional[str] = typer.Argument(None, help="A complete mcw://… address."),
) -> None:
    """Pair with a peer using a complete Macaw address."""
    if invitation is None:
        invitation = Prompt.ask("Paste Macaw Address")
    contact = _service(ctx).add_contact(MacawAddress.parse(invitation))
    success(f"Paired with {contact.username}")
    info(f"Identity fingerprint: {contact.fingerprint}")
    info("Compare the fingerprint with your contact over a separate trusted channel.")


@app.command("contacts")
def contacts(ctx: typer.Context) -> None:
    """List local contacts."""
    service = _service(ctx)
    service.profile()
    render_contacts(service.contact_book.list())


@app.command("chat")
def chat(
    ctx: typer.Context,
    contact: str = typer.Argument(..., help="Contact name or displayed number."),
    message: Optional[str] = typer.Option(None, "--message", "-m", help="Send one message and exit."),
) -> None:
    """Load local history and send encrypted messages to a contact."""
    service = _service(ctx)
    resolved = service.resolve_contact(contact)
    render_history(resolved.username, service.history.list(resolved))
    if message is not None:
        service.send_to_contact(resolved.username, message)
        success(f"Sent encrypted message to {resolved.username}.")
        return

    info("Type a message and press Enter. Submit a blank line to return.")
    try:
        connection_contact, connection = service.connect_contact(resolved.username)
        with connection:
            while True:
                body = console.input("[bold cyan]You:[/bold cyan] ")
                if not body.strip():
                    break
                connection.send(body)
                service.history.append(connection_contact, "outgoing", body)
    except KeyboardInterrupt:
        console.print()


@app.command("listen")
def listen(ctx: typer.Context) -> None:
    """Accept direct encrypted peer connections until Ctrl-C."""
    _service(ctx).listen()


@app.command("history")
def history(
    ctx: typer.Context,
    contact: str = typer.Argument(..., help="Contact name or displayed number."),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", min=1, help="Maximum messages to show."),
) -> None:
    """Show the local SQLite history for a contact."""
    service = _service(ctx)
    resolved = service.resolve_contact(contact)
    render_history(resolved.username, service.history.list(resolved, limit=limit))


@app.command("remove")
def remove(
    ctx: typer.Context,
    contact: str = typer.Argument(..., help="Contact name or displayed number."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
) -> None:
    """Remove a contact and its local conversation database."""
    service = _service(ctx)
    resolved = service.resolve_contact(contact)
    if not yes and not Confirm.ask(f"Remove {resolved.username} and local history?", default=False):
        raise typer.Exit()
    removed = service.remove_contact(resolved.username)
    success(f"Removed {removed.username} and local history.")


@app.command("clear")
def clear(
    ctx: typer.Context,
    contact: str = typer.Argument(..., help="Contact name or displayed number."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
) -> None:
    """Permanently delete a contact's local message history."""
    service = _service(ctx)
    resolved = service.resolve_contact(contact)
    if not yes and not Confirm.ask(f"Delete all local history with {resolved.username}?", default=False):
        raise typer.Exit()
    _, deleted = service.clear_history(resolved.username)
    success(f"Deleted {deleted} local message(s).")


@app.command("settings")
def settings(
    ctx: typer.Context,
    username: Optional[str] = typer.Option(None, "--username", help="Change local display username."),
    host: Optional[str] = typer.Option(None, "--host", help="IP or hostname to bind the listener to."),
    port: Optional[int] = typer.Option(None, "--port", min=1, max=65535, help="TCP port for direct connections."),
    retention_days: Optional[int] = typer.Option(
        None, "--retention-days", min=1, max=3650, help="Days to retain local messages."
    ),
) -> None:
    """View or update local-only settings."""
    service = _service(ctx)
    if any(value is not None for value in (username, host, port, retention_days)):
        service.update_settings(username, host, port, retention_days)
        success("Settings saved locally.")
    current = service.settings
    render_settings(current.username, current.listen_host, current.listen_port, current.retention_days)


@app.command("help")
def help_command(ctx: typer.Context) -> None:
    """Print the command reference."""
    console.print(ctx.parent.get_help() if ctx.parent is not None else ctx.get_help())


@app.command("exit")
def exit_command() -> None:
    """Exit successfully (useful from scripted command menus)."""
    raise typer.Exit()
