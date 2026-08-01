"""Ephemeral X25519 key agreement and session-key derivation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey


@dataclass(frozen=True, slots=True)
class EphemeralKeyPair:
    """A one-connection X25519 key pair that is discarded after handshaking."""

    private_key: PrivateKey

    @classmethod
    def generate(cls) -> "EphemeralKeyPair":
        return cls(PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self.private_key.public_key)

    def exchange(self, peer_public_key: bytes) -> bytes:
        if len(peer_public_key) != 32:
            raise ValueError("peer X25519 public key must be 32 bytes")
        return crypto_scalarmult(bytes(self.private_key), peer_public_key)


@dataclass(frozen=True, slots=True)
class SessionKeys:
    """Independent encryption keys for each TCP direction."""

    send_key: bytes
    receive_key: bytes


def derive_session_keys(
    shared_secret: bytes,
    transcript: bytes,
    role: Literal["client", "server"],
) -> SessionKeys:
    """Derive directional keys bound to a signed handshake transcript."""
    if len(shared_secret) != 32:
        raise ValueError("X25519 shared secret must be 32 bytes")
    transcript_hash = hashlib.sha256(transcript).digest()
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=transcript_hash,
        info=b"macaw/session-keys/v1",
    ).derive(shared_secret)
    client_to_server, server_to_client = material[:32], material[32:]
    if role == "client":
        return SessionKeys(send_key=client_to_server, receive_key=server_to_client)
    if role == "server":
        return SessionKeys(send_key=server_to_client, receive_key=client_to_server)
    raise ValueError("role must be client or server")

