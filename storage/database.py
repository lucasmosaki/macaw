"""SQLite schema and low-level operations for an individual conversation."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import sqlite3
from typing import Iterator, Literal

MessageDirection = Literal["incoming", "outgoing"]


@dataclass(frozen=True, slots=True)
class StoredMessage:
    """A message retained on the local device."""

    id: int
    direction: MessageDirection
    body: str
    created_at: datetime


class ConversationDatabase:
    """A single SQLite database, one per contact."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    direction TEXT NOT NULL CHECK(direction IN ('incoming', 'outgoing')),
                    body TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)"
            )

    def append(self, direction: MessageDirection, body: str, created_at: datetime | None = None) -> StoredMessage:
        if direction not in ("incoming", "outgoing"):
            raise ValueError("direction must be incoming or outgoing")
        if not body or not body.strip():
            raise ValueError("message cannot be empty")
        if len(body) > 16_000:
            raise ValueError("message is too long (maximum 16000 characters)")
        timestamp = (created_at or datetime.now(UTC)).astimezone(UTC)
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO messages(direction, body, created_at) VALUES (?, ?, ?)",
                (direction, body, timestamp.timestamp()),
            )
            message_id = int(cursor.lastrowid)
        return StoredMessage(message_id, direction, body, timestamp)

    def list(self, limit: int | None = None) -> list[StoredMessage]:
        query = "SELECT id, direction, body, created_at FROM messages ORDER BY id ASC"
        values: tuple[object, ...] = ()
        if limit is not None:
            if limit <= 0:
                return []
            query += " LIMIT ?"
            values = (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return [
            StoredMessage(
                id=int(row["id"]),
                direction=row["direction"],
                body=row["body"],
                created_at=datetime.fromtimestamp(float(row["created_at"]), UTC),
            )
            for row in rows
        ]

    def delete_before(self, cutoff: datetime) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM messages WHERE created_at < ?", (cutoff.astimezone(UTC).timestamp(),)
            )
            return int(cursor.rowcount)

    def clear(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM messages")
            return int(cursor.rowcount)

