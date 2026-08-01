"""Length-prefixed MessagePack framing for Macaw's TCP protocol."""

from __future__ import annotations

import socket
import struct
from typing import Any, Mapping

import msgpack

MAX_FRAME_SIZE = 1_048_576


class PacketError(ConnectionError):
    """Raised when a peer sends an invalid or incomplete protocol frame."""


def send_frame(sock: socket.socket, packet: Mapping[str, Any]) -> None:
    """Serialize and atomically write one bounded protocol packet."""
    try:
        payload = msgpack.packb(dict(packet), use_bin_type=True, strict_types=True)
    except (TypeError, ValueError) as exc:
        raise PacketError("could not serialize protocol packet") from exc
    if not 0 < len(payload) <= MAX_FRAME_SIZE:
        raise PacketError("protocol packet exceeds size limit")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_frame(sock: socket.socket) -> dict[str, Any]:
    """Read and validate one length-prefixed MessagePack map."""
    header = _receive_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if not 0 < length <= MAX_FRAME_SIZE:
        raise PacketError("peer sent an invalid frame length")
    raw_packet = _receive_exact(sock, length)
    try:
        packet = msgpack.unpackb(raw_packet, raw=False, strict_map_key=True)
    except (msgpack.ExtraData, msgpack.FormatError, msgpack.StackError, ValueError) as exc:
        raise PacketError("peer sent malformed MessagePack") from exc
    if not isinstance(packet, dict) or not all(isinstance(key, str) for key in packet):
        raise PacketError("protocol packet must be a map with text keys")
    return packet


def _receive_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise PacketError("timed out while waiting for peer data") from exc
        if not chunk:
            raise PacketError("peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

