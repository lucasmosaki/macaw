# Macaw

Macaw is a local-first, peer-to-peer terminal messenger. It stores messages only
on the computers that participate in a conversation: there is no server, relay,
cloud backup, telemetry, analytics, or advertising.

## What is implemented

- Ed25519 device identities and X25519 ephemeral key agreement
- ChaCha20-Poly1305 encrypted, signed direct TCP sessions
- One-time, five-minute Macaw invitations (`mcw://…` addresses)
- JSON contact storage and one SQLite history database per contact
- Automatic local history cleanup after the configured retention period (30 days
  by default)
- Rich terminal output and a Typer command-line interface

The first pairing uses the invitation code to authorize the connection and then
uses trust-on-first-use for the peer's identity key. Macaw displays a persistent
fingerprint for the contact. For sensitive use, compare that fingerprint over a
separate trusted channel before relying on it.

## Quick start

Install [uv](https://docs.astral.sh/uv/) and run:

```bash
cd macaw
uv sync --extra dev
uv run macaw --help
uv run macaw init
uv run macaw listen
```

In a second terminal or on another computer, make an invitation visible with
`macaw address`, then pair using `macaw add 'mcw://…'`. Open a conversation with
`macaw chat <name>`.

Use `--data-dir PATH` with any command to keep application data in a chosen
directory. By default it is stored in the platform's local data directory, never
in a cloud service.

## Project layout

The code is organized by responsibility, with the command-line entry point kept
at the repository root:

```text
macaw/
├── app.py                 # Entry point
├── requirements.txt
├── pyproject.toml
├── cli/
│   ├── menu.py
│   ├── commands.py
│   └── interface.py
├── crypto/
│   ├── encryption.py
│   ├── keys.py
│   ├── signatures.py
│   └── session.py
├── network/
│   ├── peer.py
│   ├── listener.py
│   ├── packets.py
│   └── protocol.py
├── contacts/
│   ├── contacts.py
│   └── invitations.py
├── storage/
│   ├── database.py
│   ├── history.py
│   └── cleanup.py
├── config/
│   ├── settings.py
│   └── identity.py
├── utils/
│   ├── address.py
│   ├── logger.py
│   └── validation.py
├── data/
│   ├── contacts.json
│   ├── settings.json
│   └── history/
└── tests/
```

`data/` is a runtime profile layout when passed via `--data-dir`; its contents
are created locally and are intentionally ignored by Git. Private identity keys
and short-lived invitation state remain in `data/config/` with restrictive file
permissions.

## Commands

```text
init [username]       Create a local identity
address               Create a one-time invitation address
listen                Accept peers and print incoming messages
add ADDRESS           Pair with a peer using an invitation
contacts              List paired contacts
chat CONTACT          Show history and send messages
history CONTACT       Show local message history
remove CONTACT        Remove a contact and its local history
clear CONTACT         Clear a contact's local history
settings              View or change local settings
```

## Security note

This project is an educational, working reference implementation. It has not
received a professional security audit, so it should not be relied upon for
high-risk communication.
