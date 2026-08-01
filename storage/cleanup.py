"""Retention cleanup entry point."""

from __future__ import annotations

from storage.history import HistoryStore


def cleanup_expired_messages(history: HistoryStore, retention_days: int) -> int:
    """Remove local messages older than the configured retention period."""
    return history.cleanup(retention_days)

