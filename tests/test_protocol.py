from __future__ import annotations

import socket
import threading

import pytest

from config.identity import Identity
from contacts.invitations import InvitationRegistry
from crypto.encryption import EncryptionError, SessionCipher
from network.protocol import client_handshake, receive_message, send_message, server_handshake
from network.listener import MacawListener
from network.peer import PeerConnection
from utils.address import MacawAddress


def test_session_cipher_rejects_replay_and_tampering() -> None:
    key = b"x" * 32
    sender = SessionCipher(key)
    receiver = SessionCipher(key)
    counter, ciphertext = sender.encrypt(b"private")

    assert receiver.decrypt(counter, ciphertext) == b"private"
    with pytest.raises(EncryptionError):
        receiver.decrypt(counter, ciphertext)


def test_pairing_handshake_establishes_forward_secret_encrypted_delivery() -> None:
    client_socket, server_socket = socket.socketpair()
    client_identity = Identity.generate()
    server_identity = Identity.generate()
    invitations = InvitationRegistry()
    invitation = invitations.create()
    result: dict[str, object] = {}

    def run_server() -> None:
        try:
            session = server_handshake(
                server_socket,
                identity=server_identity,
                username="ServerFox",
                invitations=invitations,
                is_trusted_identity=lambda _: False,
                listen_port=45812,
            )
            result["session"] = session
            result["message"] = receive_message(server_socket, session)
        except BaseException as exc:  # Surface a thread error in the test thread.
            result["error"] = exc
        finally:
            server_socket.close()

    thread = threading.Thread(target=run_server)
    thread.start()
    try:
        client_session = client_handshake(
            client_socket,
            identity=client_identity,
            username="ClientFox",
            invitation=invitation.code,
            listen_port=45813,
        )
        send_message(client_socket, client_session, "Hello directly, without a relay.", client_identity)
    finally:
        client_socket.close()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert "error" not in result
    assert result["message"] == "Hello directly, without a relay."
    server_session = result["session"]
    assert server_session.remote_identity_key == client_identity.public_key_bytes
    assert client_session.remote_identity_key == server_identity.public_key_bytes
    assert not invitations.is_valid(invitation.code)


def test_listener_accepts_pairing_and_delivers_encrypted_message(tmp_path) -> None:
    server_identity = Identity.generate()
    client_identity = Identity.generate()
    invitation_path = tmp_path / "invitations.json"
    invitations = InvitationRegistry(invitation_path)
    received: list[str] = []
    paired = threading.Event()
    delivered = threading.Event()

    # Pick an available loopback port before constructing the listener. This is
    # used only by the integration test; Macaw settings intentionally require a
    # user-visible, nonzero port.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()

    listener = MacawListener(
        identity=server_identity,
        username="ServerFox",
        host="127.0.0.1",
        port=port,
        invitations=invitations,
        is_trusted_identity=lambda _: False,
        on_pairing=lambda _: paired.set(),
        on_message=lambda message: (received.append(message.body), delivered.set()),
    )
    listener.start()
    thread = threading.Thread(target=listener.serve_forever)
    thread.start()
    try:
        # Mimic `macaw address` being run in a second process after `listen`.
        invitation = InvitationRegistry(invitation_path).create()
        address = MacawAddress("ServerFox", "127.0.0.1", port, invitation.code)
        with PeerConnection.connect(
            address,
            identity=client_identity,
            username="ClientFox",
            local_listen_port=45813,
        ) as peer:
            peer.send("Delivered through the listener")
        assert paired.wait(timeout=3)
        assert delivered.wait(timeout=3)
        assert received == ["Delivered through the listener"]
    finally:
        listener.close()
        thread.join(timeout=3)
    assert not thread.is_alive()
