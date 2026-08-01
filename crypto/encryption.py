"""Authenticated ChaCha20-Poly1305 encryption for ordered session packets."""

from __future__ import annotations

import hashlib
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class EncryptionError(ValueError):
    """Raised for tampered, replayed, or out-of-order encrypted data."""


class SessionCipher:
    """One-direction cipher with monotonically increasing, unique nonces."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
        self._aead = ChaCha20Poly1305(key)
        self._nonce_prefix = hashlib.blake2s(key + b"macaw nonce", digest_size=4).digest()
        self._next_send = 0
        self._next_receive = 0
        self._lock = threading.Lock()

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"macaw/secure-packet/v1") -> tuple[int, bytes]:
        """Encrypt bytes and return their sequence number and authenticated ciphertext."""
        with self._lock:
            counter = self._next_send
            if counter >= 2**64:
                raise EncryptionError("session send counter exhausted")
            ciphertext = self._aead.encrypt(self._nonce(counter), plaintext, associated_data)
            self._next_send += 1
            return counter, ciphertext

    def decrypt(
        self,
        counter: int,
        ciphertext: bytes,
        associated_data: bytes = b"macaw/secure-packet/v1",
    ) -> bytes:
        """Authenticate and decrypt only the exact next packet in the TCP stream."""
        if not isinstance(counter, int) or counter < 0:
            raise EncryptionError("invalid session packet counter")
        with self._lock:
            if counter != self._next_receive:
                raise EncryptionError("replayed, missing, or out-of-order session packet")
            try:
                plaintext = self._aead.decrypt(self._nonce(counter), ciphertext, associated_data)
            except (InvalidTag, ValueError) as exc:
                raise EncryptionError("unable to authenticate encrypted packet") from exc
            self._next_receive += 1
            return plaintext

    def _nonce(self, counter: int) -> bytes:
        return self._nonce_prefix + counter.to_bytes(8, "big")

