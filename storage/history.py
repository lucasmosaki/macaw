"""High-level local message-history service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import re

from contacts.contacts import Contact
from storage.database import ConversationDatabase, MessageDirection, StoredMessage

_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9_-]")


class HistoryStore:
    """Keeps each conversation in its own SQLite file, with no remote copy."""

    def __init__(self, history_dir: Path) -> None:
        self.history_dir = history_dir
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, contact: Contact | str) -> Path:
        username = contact.username if isinstance(contact, Contact) else contact
        filename = _SAFE_FILENAME.sub("_", username)
        return self.history_dir / f"{filename}.db"

    def database_for(self, contact: Contact | str) -> ConversationDatabase:
        return ConversationDatabase(self.path_for(contact))

    def append(self, contact: Contact | str, direction: MessageDirection, body: str) -> StoredMessage:
        return self.database_for(contact).append(direction, body)

    def list(self, contact: Contact | str, limit: int | None = None) -> list[StoredMessage]:
        return self.database_for(contact).list(limit)

    def clear(self, contact: Contact | str) -> int:
        return self.database_for(contact).clear()

    def delete(self, contact: Contact | str) -> bool:
        path = self.path_for(contact)
        removed = False
        for candidate in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
            if candidate.exists():
                candidate.unlink()
                removed = True
        return removed

    def cleanup(self, retention_days: int, now: datetime | None = None) -> int:
        """Delete messages past the local retention window from every history DB."""
        if retention_days < 1:
            raise ValueError("retention_days must be positive")
        cutoff = (now or datetime.now(UTC)).astimezone(UTC) - timedelta(days=retention_days)
        deleted = 0
        for database_path in self.history_dir.glob("*.db"):
            deleted += ConversationDatabase(database_path).delete_before(cutoff)
        return deleted

