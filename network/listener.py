"""Threaded direct TCP listener for incoming Macaw sessions."""

from __future__ import annotations

from dataclasses import dataclass
import socket
import threading
from typing import Callable

from config.identity import Identity
from contacts.invitations import InvitationRegistry
from crypto.session import SecureSession
from network.protocol import ProtocolError, receive_secure, send_secure, server_handshake, verify_message_payload
from utils.validation import validate_host, validate_port, validate_username


@dataclass(frozen=True, slots=True)
class IncomingPeer:
    """Information about a newly authenticated connection."""

    session: SecureSession
    host: str
    source_port: int


@dataclass(frozen=True, slots=True)
class IncomingMessage:
    """An encrypted message received from a direct peer."""

    peer: IncomingPeer
    body: str


class MacawListener:
    """Accepts direct peers without a relay or cloud component."""

    def __init__(
        self,
        identity: Identity,
        username: str,
        host: str,
        port: int,
        invitations: InvitationRegistry,
        is_trusted_identity: Callable[[bytes], bool],
        on_pairing: Callable[[IncomingPeer], None] | None = None,
        on_message: Callable[[IncomingMessage], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self.identity = identity
        self.username = validate_username(username)
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.invitations = invitations
        self.is_trusted_identity = is_trusted_identity
        self.on_pairing = on_pairing
        self.on_message = on_message
        self.on_error = on_error
        self._socket: socket.socket | None = None
        self._stop = threading.Event()
        self._client_sockets: set[socket.socket] = set()
        self._clients_lock = threading.Lock()

    @property
    def bound_port(self) -> int:
        if self._socket is None:
            raise RuntimeError("listener has not started")
        return int(self._socket.getsockname()[1])

    def start(self) -> int:
        """Bind the listening socket and return the port actually in use."""
        if self._socket is not None:
            return self.bound_port
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen()
            listener.settimeout(0.5)
            self._socket = listener
            return self.bound_port
        except BaseException:
            listener.close()
            raise

    def serve_forever(self) -> None:
        """Handle peers until :meth:`close` is called."""
        self.start()
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                client, raw_address = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._report_error(ProtocolError("listener socket failed"))
                break
            with self._clients_lock:
                self._client_sockets.add(client)
            host, source_port = str(raw_address[0]), int(raw_address[1])
            thread = threading.Thread(
                target=self._handle_client,
                args=(client, host, source_port),
                name=f"macaw-peer-{host}",
                daemon=True,
            )
            thread.start()

    def close(self) -> None:
        """Stop accepting peers and close active direct connections."""
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        with self._clients_lock:
            clients = list(self._client_sockets)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()

    def _handle_client(self, client: socket.socket, host: str, source_port: int) -> None:
        try:
            client.settimeout(15.0)
            session = server_handshake(
                client,
                identity=self.identity,
                username=self.username,
                invitations=self.invitations,
                is_trusted_identity=self.is_trusted_identity,
                listen_port=self.bound_port,
            )
            client.settimeout(None)
            peer = IncomingPeer(session=session, host=host, source_port=source_port)
            if session.is_new_pairing and self.on_pairing is not None:
                self.on_pairing(peer)
            while not self._stop.is_set():
                kind, payload = receive_secure(client, session)
                if kind == "message":
                    body = verify_message_payload(session, payload)
                    if self.on_message is not None:
                        self.on_message(IncomingMessage(peer=peer, body=body))
                elif kind == "ping":
                    send_secure(client, session, "pong", {})
                else:
                    raise ProtocolError(f"unsupported secure packet kind: {kind}")
        except (OSError, ProtocolError, ValueError) as exc:
            if not self._stop.is_set():
                self._report_error(exc)
        finally:
            with self._clients_lock:
                self._client_sockets.discard(client)
            try:
                client.close()
            except OSError:
                pass

    def _report_error(self, error: Exception) -> None:
        if self.on_error is not None:
            self.on_error(error)
