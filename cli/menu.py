"""The optional interactive menu shown when `macaw` is run without a command."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.prompt import Prompt

from cli.interface import banner, console, error, render_contacts, render_settings, success
from utils.address import MacawAddress
from utils.validation import ValidationError

if TYPE_CHECKING:
    from cli.commands import MacawService


def run_interactive(service: "MacawService") -> None:
    """Offer the menu described in the project brief without hiding CLI commands."""
    settings = service.settings
    if settings.username is None:
        banner()
        username = Prompt.ask("Choose a username")
        try:
            service.initialize(username)
        except (RuntimeError, ValidationError) as exc:
            error(str(exc))
            return
        settings = service.settings
        success("Identity, keys, local database, and contact storage are ready.")

    assert settings.username is not None
    while True:
        banner(settings.username)
        console.print("[1] Contacts\n[2] Listen\n[3] Add Contact\n[4] Settings\n[5] Exit")
        choice = Prompt.ask("", choices=["1", "2", "3", "4", "5"], default="1")
        try:
            if choice == "1":
                render_contacts(service.contact_book.list())
            elif choice == "2":
                console.print("Listening until Ctrl-C. Use `macaw address` in another terminal to issue invitations.")
                service.listen()
            elif choice == "3":
                address = MacawAddress.parse(Prompt.ask("Paste Macaw Address"))
                contact = service.add_contact(address)
                success(f"Paired with {contact.username}. Verify fingerprint: {contact.fingerprint}")
            elif choice == "4":
                render_settings(
                    settings.username,
                    settings.listen_host,
                    settings.listen_port,
                    settings.retention_days,
                )
            else:
                return
        except KeyboardInterrupt:
            console.print()
        except (OSError, RuntimeError, ValidationError, ValueError) as exc:
            error(str(exc))

