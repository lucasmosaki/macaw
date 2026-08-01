"""Macaw address parsing and formatting."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from utils.validation import (
    ValidationError,
    validate_host,
    validate_invitation_code,
    validate_port,
    validate_username,
)

_ADDRESS_RE = re.compile(
    r"^mcw://(?P<username>[A-Za-z0-9][A-Za-z0-9_-]{1,30}[A-Za-z0-9])@"
    r"(?P<host>\[[^\]]+\]|[^/:\s]+):(?P<port>\d{1,5})/(?P<invitation>[^/\s]+)$"
)


@dataclass(frozen=True, slots=True)
class MacawAddress:
    """The single pasteable value used to invite a peer to pair."""

    username: str
    host: str
    port: int
    invitation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "username", validate_username(self.username))
        object.__setattr__(self, "host", validate_host(self.host))
        object.__setattr__(self, "port", validate_port(self.port))
        object.__setattr__(self, "invitation", validate_invitation_code(self.invitation))

    def __str__(self) -> str:
        try:
            ipaddress.IPv6Address(self.host)
            host = f"[{self.host}]"
        except ValueError:
            host = self.host
        return f"mcw://{self.username}@{host}:{self.port}/{self.invitation}"

    @classmethod
    def parse(cls, value: str) -> "MacawAddress":
        """Parse an address without requiring users to split it into fields."""
        match = _ADDRESS_RE.fullmatch(value.strip())
        if not match:
            raise ValidationError(
                "address must look like mcw://Name@host:port/INVITATIONCODE"
            )
        groups = match.groupdict()
        host = groups["host"]
        if host.startswith("["):
            host = host[1:-1]
        return cls(
            username=groups["username"],
            host=host,
            port=groups["port"],
            invitation=groups["invitation"],
        )

