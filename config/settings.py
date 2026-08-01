"""Settings and portable local-data directory management."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import sys
import tempfile

from utils.validation import ValidationError, validate_port, validate_username


@dataclass(frozen=True, slots=True)
class DataPaths:
    """All on-disk state owned by one Macaw profile."""

    root: Path

    @property
    def config_dir(self) -> Path:
        return self.root / "config"

    @property
    def identity_private_key(self) -> Path:
        return self.config_dir / "identity.key"

    @property
    def identity_public_key(self) -> Path:
        return self.config_dir / "identity.pub"

    @property
    def settings_file(self) -> Path:
        """Return the visible, profile-level settings file.

        Keeping this alongside ``contacts.json`` makes a profile's mutable
        application data easy to find, while private key material remains in
        the protected ``config`` subdirectory.
        """
        return self.root / "settings.json"

    @property
    def legacy_settings_file(self) -> Path:
        """Return the pre-layout settings location for backwards-compatible reads."""
        return self.config_dir / "settings.json"

    @property
    def contacts_file(self) -> Path:
        return self.root / "contacts.json"

    @property
    def invitations_file(self) -> Path:
        return self.config_dir / "invitations.json"

    @property
    def history_dir(self) -> Path:
        return self.root / "history"

    def ensure_exists(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.history_dir.mkdir(parents=True, exist_ok=True)


def default_data_dir() -> Path:
    """Choose a non-cloud, platform-appropriate directory for local state."""
    override = os.environ.get("MACAW_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Macaw"
    if sys.platform.startswith("win"):
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Macaw"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "macaw"


@dataclass(slots=True)
class Settings:
    """User-configurable settings persisted only on the local device."""

    username: str | None = None
    listen_host: str = "0.0.0.0"
    listen_port: int = 45812
    retention_days: int = 30

    def validate(self) -> None:
        if self.username is not None:
            self.username = validate_username(self.username)
        self.listen_port = validate_port(self.listen_port)
        if not 1 <= int(self.retention_days) <= 3650:
            raise ValidationError("retention_days must be between 1 and 3650")
        self.retention_days = int(self.retention_days)

    @classmethod
    def load(cls, paths: DataPaths) -> "Settings":
        paths.ensure_exists()
        settings_file = paths.settings_file
        # Profiles created before settings.json was promoted to the data root
        # remain usable. A later save writes the file at its new location.
        if not settings_file.exists() and paths.legacy_settings_file.exists():
            settings_file = paths.legacy_settings_file
        if not settings_file.exists():
            return cls()
        try:
            content = json.loads(settings_file.read_text(encoding="utf-8"))
            settings = cls(**content)
            settings.validate()
            return settings
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"could not load settings: {exc}") from exc

    def save(self, paths: DataPaths) -> None:
        self.validate()
        paths.ensure_exists()
        _atomic_write_text(paths.settings_file, json.dumps(asdict(self), indent=2) + "\n", 0o600)


def _atomic_write_text(path: Path, content: str, mode: int) -> None:
    """Atomically replace a local state file with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
