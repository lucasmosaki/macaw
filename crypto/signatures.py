"""Ed25519 signature helpers."""

from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


class SignatureError(ValueError):
    """Raised when an identity signature cannot be verified."""


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify an Ed25519 signature or raise a domain-specific error."""
    if len(public_key) != 32:
        raise SignatureError("Ed25519 public key must be 32 bytes")
    try:
        VerifyKey(public_key).verify(message, signature)
    except (BadSignatureError, ValueError) as exc:
        raise SignatureError("invalid identity signature") from exc

