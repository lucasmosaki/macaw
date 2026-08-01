"""Creation and persistence of a device's Ed25519 identity."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import os
from pathlib import Path
import tempfile

from nacl.signing import SigningKey, VerifyKey

from config.settings import DataPaths


@dataclass(frozen=True, slots=True)
class Identity:
    """A long-lived Ed25519 key pair owned by one Macaw installation."""

    signing_key: SigningKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls(SigningKey.generate())

    @property
    def verify_key(self) -> VerifyKey:
        return self.signing_key.verify_key

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self.verify_key)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    @property
    def fingerprint(self) -> str:
        digest = hashlib.blake2b(self.public_key_bytes, digest_size=16).hexdigest().upper()
        return " ".join(digest[index : index + 4] for index in range(0, len(digest), 4))

    def sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message).signature

    def save(self, paths: DataPaths) -> None:
        """Persist the private key with owner-only permissions."""
        paths.ensure_exists()
        _atomic_write_bytes(paths.identity_private_key, self.signing_key.encode(), 0o600)
        _atomic_write_bytes(paths.identity_public_key, self.public_key_bytes, 0o644)

    @classmethod
    def load(cls, paths: DataPaths) -> "Identity":
        try:
            private = paths.identity_private_key.read_bytes()
            identity = cls(SigningKey(private))
        except (OSError, ValueError) as exc:
            raise RuntimeError("could not load the local identity key") from exc
        if paths.identity_public_key.exists():
            public = paths.identity_public_key.read_bytes()
            if public != identity.public_key_bytes:
                raise RuntimeError("identity public key does not match private key")
        return identity

    @classmethod
    def load_or_create(cls, paths: DataPaths) -> "Identity":
        if paths.identity_private_key.exists():
            return cls.load(paths)
        identity = cls.generate()
        identity.save(paths)
        return identity


def _atomic_write_bytes(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
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

