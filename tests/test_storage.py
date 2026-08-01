from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from nacl.signing import SigningKey

from contacts.contacts import Contact, ContactBook
from storage.history import HistoryStore


def make_contact(name: str = "Alice") -> Contact:
    identity_key = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode("ascii")
    return Contact.create(name, "127.0.0.1", 45812, identity_key)


def test_contact_book_round_trips_and_rejects_identity_replacement(tmp_path) -> None:
    book = ContactBook(tmp_path / "contacts.json")
    alice = make_contact()
    book.add(alice)

    assert book.get("alice") == alice
    assert book.trusts(alice.identity_key_bytes)

    replacement = make_contact("Alice")
    try:
        book.add(replacement)
    except ValueError as exc:
        assert "different identity" in str(exc)
    else:
        raise AssertionError("expected identity replacement to be rejected")


def test_history_is_local_per_contact_and_cleanup_removes_old_messages(tmp_path) -> None:
    history = HistoryStore(tmp_path / "history")
    alice = make_contact()
    database = history.database_for(alice)
    database.append("incoming", "old", datetime.now(UTC) - timedelta(days=31))
    history.append(alice, "outgoing", "recent")

    assert [message.body for message in history.list(alice)] == ["old", "recent"]
    assert history.cleanup(retention_days=30) == 1
    assert [message.body for message in history.list(alice)] == ["recent"]
    assert history.path_for(alice).name == "Alice.db"

