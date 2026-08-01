"""Short-lived, one-time invitation codes used to authorize first pairing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading

from utils.validation import INVITATION_ALPHABET, INVITATION_LENGTH, validate_invitation_code


@dataclass(frozen=True, slots=True)
class Invitation:
    """An in-memory invitation that is never written to disk."""

    code: str
    expires_at: datetime

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at


class InvitationRegistry:
    """Thread-safe registry for invitations issued by one running listener."""

    def __init__(self, storage_path: Path | None = None) -> None:
        self._invitations: dict[str, Invitation] = {}
        self._lock = threading.Lock()
        self._storage_path = storage_path
        self._load()

    def create(self, lifetime: timedelta = timedelta(minutes=5)) -> Invitation:
        """Create a cryptographically random invitation, valid for five minutes by default."""
        if lifetime.total_seconds() <= 0:
            raise ValueError("invitation lifetime must be positive")
        with self._lock:
            self._reload_locked()
            self._purge_expired_locked()
            while True:
                code = "".join(secrets.choice(INVITATION_ALPHABET) for _ in range(INVITATION_LENGTH))
                if code not in self._invitations:
                    invitation = Invitation(code, datetime.now(UTC) + lifetime)
                    self._invitations[code] = invitation
                    self._persist_locked()
                    return invitation

    def is_valid(self, code: str | None) -> bool:
        """Check whether a code can still authorize a pairing without consuming it."""
        if not code:
            return False
        try:
            checked = validate_invitation_code(code)
        except ValueError:
            return False
        with self._lock:
            self._reload_locked()
            changed = self._purge_expired_locked()
            if changed:
                self._persist_locked()
            return checked in self._invitations

    def consume(self, code: str) -> bool:
        """Atomically delete a valid code after a successful pairing."""
        try:
            checked = validate_invitation_code(code)
        except ValueError:
            return False
        with self._lock:
            changed = self._purge_expired_locked()
            consumed = self._invitations.pop(checked, None) is not None
            if changed or consumed:
                self._persist_locked()
            return consumed

    def _purge_expired_locked(self) -> bool:
        expired = [code for code, invitation in self._invitations.items() if invitation.expired]
        for code in expired:
            del self._invitations[code]
        return bool(expired)

    def _load(self) -> None:
        self._reload_locked()
        if self._purge_expired_locked():
            self._persist_locked()

    def _reload_locked(self) -> None:
        """Refresh a persisted registry so `macaw address` works while listening."""
        if self._storage_path is None or not self._storage_path.exists():
            return
        try:
            raw = json.loads(self._storage_path.read_text(encoding="utf-8"))
            entries = raw.get("invitations", [])
            if not isinstance(entries, list):
                raise ValueError("invitations must be a list")
            loaded: dict[str, Invitation] = {}
            for entry in entries:
                code = validate_invitation_code(str(entry["code"]))
                expires_at = datetime.fromisoformat(str(entry["expires_at"]))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=UTC)
                loaded[code] = Invitation(code, expires_at.astimezone(UTC))
            self._invitations = loaded
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"could not load invitations: {exc}") from exc

    def _persist_locked(self) -> None:
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "version": 1,
            "invitations": [
                {"code": invitation.code, "expires_at": invitation.expires_at.isoformat()}
                for invitation in self._invitations.values()
            ],
        }
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self._storage_path.name}.", dir=self._storage_path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self._storage_path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
