"""Persistent local contact records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable

from utils.validation import ValidationError, validate_host, validate_port, validate_username


def _validate_identity_key(value: str) -> str:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValidationError("contact identity key is not valid base64") from exc
    if len(decoded) != 32:
        raise ValidationError("contact identity key must be an Ed25519 public key")
    return value


@dataclass(frozen=True, slots=True)
class Contact:
    """A trusted peer's identity and last known direct connection details."""

    username: str
    host: str
    port: int
    identity_key: str
    added_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "username", validate_username(self.username))
        object.__setattr__(self, "host", validate_host(self.host))
        object.__setattr__(self, "port", validate_port(self.port))
        object.__setattr__(self, "identity_key", _validate_identity_key(self.identity_key))

    @classmethod
    def create(cls, username: str, host: str, port: int, identity_key: str) -> "Contact":
        return cls(
            username=username,
            host=host,
            port=port,
            identity_key=identity_key,
            added_at=datetime.now(UTC).isoformat(),
        )

    @property
    def fingerprint(self) -> str:
        key = base64.b64decode(self.identity_key)
        digest = hashlib.blake2b(key, digest_size=16).hexdigest().upper()
        return " ".join(digest[index : index + 4] for index in range(0, len(digest), 4))

    @property
    def identity_key_bytes(self) -> bytes:
        return base64.b64decode(self.identity_key)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Contact":
        return cls(
            username=str(value["username"]),
            host=str(value["host"]),
            port=int(value["port"]),
            identity_key=str(value["identity_key"]),
            added_at=str(value["added_at"]),
        )


class ContactBook:
    """A JSON-backed, local-only contact collection."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def list(self) -> list[Contact]:
        return sorted(self._load().values(), key=lambda contact: contact.username.casefold())

    def get(self, name: str) -> Contact | None:
        needle = name.casefold()
        return next((contact for contact in self._load().values() if contact.username.casefold() == needle), None)

    def get_by_identity_key(self, identity_key: bytes) -> Contact | None:
        encoded = base64.b64encode(identity_key).decode("ascii")
        return next(
            (contact for contact in self._load().values() if contact.identity_key == encoded),
            None,
        )

    def trusts(self, identity_key: bytes) -> bool:
        return self.get_by_identity_key(identity_key) is not None

    def add(self, contact: Contact) -> Contact:
        """Save a peer, rejecting a username that belongs to another identity."""
        contacts = self._load()
        name_key = contact.username.casefold()
        existing = contacts.get(name_key)
        if existing and existing.identity_key != contact.identity_key:
            raise ValidationError(
                f"a different identity is already stored as '{existing.username}'; remove it first"
            )
        same_identity = next(
            (item for item in contacts.values() if item.identity_key == contact.identity_key),
            None,
        )
        if same_identity and same_identity.username.casefold() != name_key:
            raise ValidationError(
                f"that identity is already stored as '{same_identity.username}'"
            )
        contacts[name_key] = contact
        self._save(contacts.values())
        return contact

    def remove(self, name: str) -> Contact | None:
        contacts = self._load()
        removed = contacts.pop(name.casefold(), None)
        if removed:
            self._save(contacts.values())
        return removed

    def _load(self) -> dict[str, Contact]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("version") != 1 or not isinstance(raw.get("contacts"), list):
                raise ValueError("unrecognized contacts file")
            contacts = [Contact.from_dict(item) for item in raw["contacts"]]
            result = {contact.username.casefold(): contact for contact in contacts}
            if len(result) != len(contacts):
                raise ValueError("duplicate contact names")
            return result
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"could not load contacts: {exc}") from exc

    def _save(self, contacts: Iterable[Contact]) -> None:
        document = {
            "version": 1,
            "contacts": [contact.to_dict() for contact in sorted(contacts, key=lambda c: c.username.casefold())],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

