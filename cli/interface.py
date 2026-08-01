"""Rich presentation helpers for the terminal interface."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from contacts.contacts import Contact
from storage.database import StoredMessage

console = Console()


def banner(username: str | None = None) -> None:
    """Render the compact Macaw identity header."""
    subtitle = "Private P2P Messenger" if username is None else f"Private P2P Messenger • {username}"
    console.print(Panel("[bold cyan]MACAW[/bold cyan]", subtitle=subtitle, border_style="cyan", width=48))


def success(message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


def info(message: str) -> None:
    console.print(f"[cyan]•[/cyan] {message}")


def error(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")


def render_contacts(contacts: Iterable[Contact]) -> None:
    """Show a contact list without exposing their full identity key."""
    rows = list(contacts)
    if not rows:
        info("No contacts yet. Pair with someone using `macaw add ADDRESS`.")
        return
    table = Table(title="Contacts", header_style="bold cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Address")
    table.add_column("Identity fingerprint", style="dim")
    for index, contact in enumerate(rows, start=1):
        table.add_row(
            str(index),
            contact.username,
            f"{contact.host}:{contact.port}",
            contact.fingerprint,
        )
    console.print(table)


def render_history(contact_name: str, messages: Iterable[StoredMessage]) -> None:
    """Display persisted local history in chronological order."""
    entries = list(messages)
    console.print(Panel.fit(f"[bold]{contact_name}[/bold]", border_style="cyan"))
    if not entries:
        info("No local messages yet.")
        return
    for entry in entries:
        label = "You" if entry.direction == "outgoing" else contact_name
        local_time = entry.created_at.astimezone().strftime("%Y-%m-%d %H:%M")
        console.print(Text(f"{local_time}  {label}: {entry.body}"))


def render_settings(username: str | None, host: str, port: int, retention_days: int) -> None:
    table = Table(title="Settings", header_style="bold cyan")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("Username", username or "Not configured")
    table.add_row("Listen address", f"{host}:{port}")
    table.add_row("Message retention", f"{retention_days} days")
    console.print(table)
