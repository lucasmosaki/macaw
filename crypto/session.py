"""State for an authenticated encrypted peer session."""

from __future__ import annotations

from dataclasses import dataclass

from crypto.encryption import SessionCipher
from crypto.keys import SessionKeys


@dataclass(slots=True)
class SecureSession:
    """Directional ciphers plus the remote device identity established in a handshake."""

    remote_username: str
    remote_identity_key: bytes
    remote_listen_port: int
    send_cipher: SessionCipher
    receive_cipher: SessionCipher
    is_new_pairing: bool

    @classmethod
    def from_keys(
        cls,
        remote_username: str,
        remote_identity_key: bytes,
        remote_listen_port: int,
        keys: SessionKeys,
        is_new_pairing: bool,
    ) -> "SecureSession":
        return cls(
            remote_username=remote_username,
            remote_identity_key=remote_identity_key,
            remote_listen_port=remote_listen_port,
            send_cipher=SessionCipher(keys.send_key),
            receive_cipher=SessionCipher(keys.receive_key),
            is_new_pairing=is_new_pairing,
        )
