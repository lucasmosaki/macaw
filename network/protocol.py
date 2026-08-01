"""Signed ephemeral handshake and encrypted-message protocol."""

from __future__ import annotations

import hmac
import socket
from typing import Any, Callable

import msgpack

from config.identity import Identity
from contacts.invitations import InvitationRegistry
from crypto.encryption import EncryptionError
from crypto.keys import EphemeralKeyPair, derive_session_keys
from crypto.session import SecureSession
from crypto.signatures import SignatureError, verify_signature
from network.packets import PacketError, receive_frame, send_frame
from utils.validation import ValidationError, validate_invitation_code, validate_port, validate_username

PROTOCOL_VERSION = 1
_CONTEXT = b"macaw/direct-protocol/v1\x00"


class ProtocolError(ConnectionError):
    """Raised when pairing or encrypted communication violates the protocol."""


def client_handshake(
    sock: socket.socket,
    identity: Identity,
    username: str,
    invitation: str | None = None,
    expected_remote_identity_key: bytes | None = None,
    listen_port: int = 45812,
) -> SecureSession:
    """Authenticate a remote listener and establish a forward-secret session."""
    username = validate_username(username)
    listen_port = validate_port(listen_port)
    if invitation is not None:
        invitation = validate_invitation_code(invitation)
    if expected_remote_identity_key is not None and len(expected_remote_identity_key) != 32:
        raise ValueError("expected remote identity key must be 32 bytes")

    ephemeral = EphemeralKeyPair.generate()
    hello = {
        "type": "hello",
        "version": PROTOCOL_VERSION,
        "username": username,
        "listen_port": listen_port,
        "identity": identity.public_key_bytes,
        "ephemeral": ephemeral.public_key_bytes,
        "invitation": invitation,
    }
    hello["signature"] = identity.sign(_hello_bytes(hello))
    send_frame(sock, hello)

    response = _receive_or_raise(sock)
    if response.get("type") != "hello_ack":
        raise ProtocolError("peer did not return a handshake acknowledgement")
    _require_protocol_version(response)
    remote_username = _require_username(response.get("username"))
    remote_listen_port = _require_port(response.get("listen_port"))
    new_pairing = response.get("new_pairing")
    if not isinstance(new_pairing, bool):
        raise ProtocolError("handshake pairing status is invalid")
    remote_identity = _require_bytes(response.get("identity"), 32, "server identity")
    remote_ephemeral = _require_bytes(response.get("ephemeral"), 32, "server ephemeral key")
    signature = _require_bytes(response.get("signature"), None, "server signature")
    if expected_remote_identity_key is not None and not hmac.compare_digest(
        remote_identity, expected_remote_identity_key
    ):
        raise ProtocolError("remote identity key does not match the saved contact")
    transcript = _handshake_transcript(hello, response)
    try:
        verify_signature(remote_identity, b"server-ack\x00" + transcript, signature)
    except SignatureError as exc:
        raise ProtocolError("remote listener failed identity verification") from exc

    shared_secret = ephemeral.exchange(remote_ephemeral)
    keys = derive_session_keys(shared_secret, transcript, "client")
    session = SecureSession.from_keys(
        remote_username=remote_username,
        remote_identity_key=remote_identity,
        remote_listen_port=remote_listen_port,
        keys=keys,
        is_new_pairing=new_pairing,
    )
    finish = {
        "type": "finish",
        "signature": identity.sign(b"client-finish\x00" + transcript),
    }
    send_frame(sock, finish)
    kind, _ = receive_secure(sock, session)
    if kind != "ready":
        raise ProtocolError("peer did not confirm the secure session")
    return session


def server_handshake(
    sock: socket.socket,
    identity: Identity,
    username: str,
    invitations: InvitationRegistry,
    is_trusted_identity: Callable[[bytes], bool],
    listen_port: int = 45812,
) -> SecureSession:
    """Authorize a peer, verify its identity signature, and start a secure session."""
    username = validate_username(username)
    listen_port = validate_port(listen_port)
    hello = _receive_or_raise(sock)
    if hello.get("type") != "hello":
        raise ProtocolError("peer did not begin with a handshake")
    _require_protocol_version(hello)
    remote_username = _require_username(hello.get("username"))
    remote_listen_port = _require_port(hello.get("listen_port"))
    remote_identity = _require_bytes(hello.get("identity"), 32, "client identity")
    remote_ephemeral = _require_bytes(hello.get("ephemeral"), 32, "client ephemeral key")
    remote_signature = _require_bytes(hello.get("signature"), None, "client signature")
    invitation = hello.get("invitation")
    if invitation is not None and not isinstance(invitation, str):
        raise ProtocolError("invalid invitation in handshake")
    try:
        verify_signature(remote_identity, _hello_bytes(hello), remote_signature)
    except SignatureError as exc:
        raise ProtocolError("client failed identity verification") from exc

    new_pairing = bool(invitation and invitations.is_valid(invitation))
    trusted = is_trusted_identity(remote_identity)
    if not new_pairing and not trusted:
        _send_error(sock, "invitation is expired, used, or not recognized")
        raise ProtocolError("unauthorized peer")

    ephemeral = EphemeralKeyPair.generate()
    response = {
        "type": "hello_ack",
        "version": PROTOCOL_VERSION,
        "username": username,
        "listen_port": listen_port,
        "identity": identity.public_key_bytes,
        "ephemeral": ephemeral.public_key_bytes,
        "new_pairing": new_pairing,
    }
    transcript = _handshake_transcript(hello, response)
    response["signature"] = identity.sign(b"server-ack\x00" + transcript)
    send_frame(sock, response)

    finish = _receive_or_raise(sock)
    if finish.get("type") != "finish":
        raise ProtocolError("peer did not finish the handshake")
    finish_signature = _require_bytes(finish.get("signature"), None, "client finish signature")
    try:
        verify_signature(remote_identity, b"client-finish\x00" + transcript, finish_signature)
    except SignatureError as exc:
        raise ProtocolError("client handshake finish was invalid") from exc
    if new_pairing and not invitations.consume(invitation or ""):
        _send_error(sock, "invitation was already used")
        raise ProtocolError("invitation consumed concurrently")

    shared_secret = ephemeral.exchange(remote_ephemeral)
    keys = derive_session_keys(shared_secret, transcript, "server")
    session = SecureSession.from_keys(
        remote_username=remote_username,
        remote_identity_key=remote_identity,
        remote_listen_port=remote_listen_port,
        keys=keys,
        is_new_pairing=new_pairing,
    )
    send_secure(sock, session, "ready", {})
    return session


def send_secure(sock: socket.socket, session: SecureSession, kind: str, payload: dict[str, Any]) -> None:
    """Encrypt a typed application packet and send it over the established session."""
    if not kind or not isinstance(kind, str):
        raise ValueError("secure packet kind must be text")
    try:
        plaintext = msgpack.packb({"kind": kind, "payload": payload}, use_bin_type=True, strict_types=True)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("could not encode secure payload") from exc
    counter, ciphertext = session.send_cipher.encrypt(plaintext)
    send_frame(sock, {"type": "secure", "counter": counter, "ciphertext": ciphertext})


def receive_secure(sock: socket.socket, session: SecureSession) -> tuple[str, dict[str, Any]]:
    """Receive, authenticate, decrypt, and validate one application packet."""
    packet = _receive_or_raise(sock)
    if packet.get("type") != "secure":
        raise ProtocolError("expected encrypted packet")
    counter = packet.get("counter")
    ciphertext = packet.get("ciphertext")
    if not isinstance(counter, int):
        raise ProtocolError("encrypted packet has invalid counter")
    ciphertext = _require_bytes(ciphertext, None, "encrypted packet")
    try:
        plaintext = session.receive_cipher.decrypt(counter, ciphertext)
        unpacked = msgpack.unpackb(plaintext, raw=False, strict_map_key=True)
    except (EncryptionError, msgpack.ExtraData, msgpack.FormatError, msgpack.StackError, ValueError) as exc:
        raise ProtocolError("could not authenticate encrypted packet") from exc
    if not isinstance(unpacked, dict):
        raise ProtocolError("secure payload must be a map")
    kind = unpacked.get("kind")
    payload = unpacked.get("payload")
    if not isinstance(kind, str) or not isinstance(payload, dict):
        raise ProtocolError("secure payload has invalid shape")
    return kind, payload


def send_message(sock: socket.socket, session: SecureSession, body: str, identity: Identity) -> None:
    """Sign, encrypt, and send a bounded human text message."""
    if not isinstance(body, str) or not body.strip() or len(body) > 16_000:
        raise ValueError("message must contain 1–16000 non-blank characters")
    signature = identity.sign(_message_bytes(body))
    send_secure(sock, session, "message", {"body": body, "signature": signature})


def receive_message(sock: socket.socket, session: SecureSession) -> str:
    """Receive, authenticate, and verify the next human text message."""
    kind, payload = receive_secure(sock, session)
    if kind != "message":
        raise ProtocolError("expected a valid encrypted message")
    return verify_message_payload(session, payload)


def verify_message_payload(session: SecureSession, payload: dict[str, Any]) -> str:
    """Validate a signed message payload that was already decrypted by the session."""
    body = payload.get("body")
    if not isinstance(body, str) or not body.strip() or len(body) > 16_000:
        raise ProtocolError("expected a valid encrypted message")
    signature = _require_bytes(payload.get("signature"), None, "message signature")
    try:
        verify_signature(session.remote_identity_key, _message_bytes(body), signature)
    except SignatureError as exc:
        raise ProtocolError("message signature did not match the peer identity") from exc
    return body


def _receive_or_raise(sock: socket.socket) -> dict[str, Any]:
    try:
        packet = receive_frame(sock)
    except PacketError as exc:
        raise ProtocolError(str(exc)) from exc
    if packet.get("type") == "error":
        message = packet.get("message")
        raise ProtocolError(str(message) if isinstance(message, str) else "peer rejected the connection")
    return packet


def _send_error(sock: socket.socket, message: str) -> None:
    try:
        send_frame(sock, {"type": "error", "message": message})
    except OSError:
        pass


def _require_protocol_version(packet: dict[str, Any]) -> None:
    if packet.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("incompatible protocol version")


def _require_username(value: object) -> str:
    if not isinstance(value, str):
        raise ProtocolError("handshake username is invalid")
    try:
        return validate_username(value)
    except ValidationError as exc:
        raise ProtocolError("handshake username is invalid") from exc


def _require_port(value: object) -> int:
    if isinstance(value, bool):
        raise ProtocolError("handshake listening port is invalid")
    try:
        return validate_port(value)  # type: ignore[arg-type]
    except ValidationError as exc:
        raise ProtocolError("handshake listening port is invalid") from exc


def _require_bytes(value: object, length: int | None, description: str) -> bytes:
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        suffix = f" ({length} bytes)" if length is not None else ""
        raise ProtocolError(f"{description} is invalid{suffix}")
    return value


def _hello_bytes(hello: dict[str, Any]) -> bytes:
    """Canonical, length-prefixed bytes signed by the initiating peer."""
    invitation = hello.get("invitation")
    if invitation is not None and not isinstance(invitation, str):
        raise ProtocolError("invalid invitation in handshake")
    return _pack_fields(
        b"client-hello",
        _require_username(hello.get("username")).encode("utf-8"),
        str(_require_port(hello.get("listen_port"))).encode("ascii"),
        _require_bytes(hello.get("identity"), 32, "client identity"),
        _require_bytes(hello.get("ephemeral"), 32, "client ephemeral key"),
        (invitation or "").encode("utf-8"),
    )


def _handshake_transcript(hello: dict[str, Any], response: dict[str, Any]) -> bytes:
    return _pack_fields(
        _CONTEXT,
        _require_username(hello.get("username")).encode("utf-8"),
        str(_require_port(hello.get("listen_port"))).encode("ascii"),
        _require_bytes(hello.get("identity"), 32, "client identity"),
        _require_bytes(hello.get("ephemeral"), 32, "client ephemeral key"),
        str(hello.get("invitation") or "").encode("utf-8"),
        _require_username(response.get("username")).encode("utf-8"),
        str(_require_port(response.get("listen_port"))).encode("ascii"),
        _require_bytes(response.get("identity"), 32, "server identity"),
        _require_bytes(response.get("ephemeral"), 32, "server ephemeral key"),
        b"1" if response.get("new_pairing") is True else b"0",
    )


def _pack_fields(*fields: bytes) -> bytes:
    return b"".join(len(field).to_bytes(4, "big") + field for field in fields)


def _message_bytes(body: str) -> bytes:
    encoded = body.encode("utf-8")
    return _pack_fields(b"macaw/signed-message/v1", encoded)
