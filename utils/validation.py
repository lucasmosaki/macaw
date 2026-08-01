"""Input validation that is shared by the CLI and the wire protocol."""

from __future__ import annotations

import ipaddress
import re

INVITATION_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*+-="
INVITATION_LENGTH = 12
_USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{1,30})[A-Za-z0-9]$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


class ValidationError(ValueError):
    """Raised when user-controlled data is outside Macaw's allowed format."""


def validate_username(value: str) -> str:
    """Validate and normalize a display name used in addresses and contacts."""
    username = value.strip()
    if not _USERNAME_RE.fullmatch(username):
        raise ValidationError(
            "username must be 3–32 characters using letters, numbers, '_' or '-', "
            "and cannot start or end with '_' or '-'"
        )
    return username


def validate_port(value: int | str) -> int:
    """Return a usable TCP port."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("port must be a number") from exc
    if not 1 <= port <= 65535:
        raise ValidationError("port must be between 1 and 65535")
    return port


def validate_host(value: str) -> str:
    """Accept a literal IP address or a conservative DNS hostname."""
    host = value.strip()
    if not host:
        raise ValidationError("host cannot be empty")
    unbracketed = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(unbracketed)
        return unbracketed
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        raise ValidationError("host must be a valid IP address or hostname")
    return host.lower()


def validate_invitation_code(value: str) -> str:
    """Validate a fixed-size, URL-safe-in-this-scheme pairing secret."""
    code = value.strip()
    if len(code) != INVITATION_LENGTH or any(char not in INVITATION_ALPHABET for char in code):
        raise ValidationError(
            f"invitation code must contain exactly {INVITATION_LENGTH} allowed characters"
        )
    return code

