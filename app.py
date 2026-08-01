"""Macaw command-line entry point."""

from __future__ import annotations

from cli.commands import app


def main() -> None:
    """Run the Typer command-line application."""
    app()


if __name__ == "__main__":
    main()

