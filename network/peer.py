"""Outbound direct connections to known or newly invited peers."""

from __future__ import annotations

from dataclasses import dataclass
import socket

from config.identity import Identity
from contacts.contacts import Contact
from crypto.session import SecureSession
from network.protocol import ProtocolError, client_handshake, receive_message, send_message
from utils.address import MacawAddress


@dataclass(slots=True)
class PeerConnection:
    """An open encrypted TCP connection to one Macaw peer."""

    sock: socket.socket
    session: SecureSession
    host: str
    port: int
    identity: Identity

    @classmethod
    def connect(
        cls,
        address: MacawAddress,
        identity: Identity,
        username: str,
        local_listen_port: int,
        expected_remote_identity_key: bytes | None = None,
        timeout: float = 15.0,
    ) -> "PeerConnection":
        """Connect, perform a signed handshake, and return an encrypted session."""
        sock = socket.create_connection((address.host, address.port), timeout=timeout)
        try:
            sock.settimeout(timeout)
            session = client_handshake(
                sock,
                identity=identity,
                username=username,
                invitation=address.invitation,
                expected_remote_identity_key=expected_remote_identity_key,
                listen_port=local_listen_port,
            )
            if session.remote_username.casefold() != address.username.casefold():
                raise ProtocolError(
                    f"address was for '{address.username}', but peer identified as '{session.remote_username}'"
                )
            sock.settimeout(None)
            return cls(sock=sock, session=session, host=address.host, port=address.port, identity=identity)
        except BaseException:
            sock.close()
            raise

    @classmethod
    def connect_saved(
        cls,
        contact: Contact,
        identity: Identity,
        username: str,
        local_listen_port: int,
        timeout: float = 15.0,
    ) -> "PeerConnection":
        """Reconnect to a stored contact without issuing another invitation."""
        sock = socket.create_connection((contact.host, contact.port), timeout=timeout)
        try:
            sock.settimeout(timeout)
            session = client_handshake(
                sock,
                identity=identity,
                username=username,
                invitation=None,
                expected_remote_identity_key=contact.identity_key_bytes,
                listen_port=local_listen_port,
            )
            if session.remote_username.casefold() != contact.username.casefold():
                raise ProtocolError("remote username does not match the saved contact")
            sock.settimeout(None)
            return cls(sock=sock, session=session, host=contact.host, port=contact.port, identity=identity)
        except BaseException:
            sock.close()
            raise

    def send(self, body: str) -> None:
        send_message(self.sock, self.session, body, self.identity)

    def receive(self) -> str:
        return receive_message(self.sock, self.session)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def __enter__(self) -> "PeerConnection":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
