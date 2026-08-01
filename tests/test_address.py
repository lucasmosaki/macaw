from __future__ import annotations

import pytest

from utils.address import MacawAddress
from utils.validation import ValidationError


def test_round_trips_ipv4_address() -> None:
    address = MacawAddress.parse("mcw://NightFox@203.0.113.25:45812/H7@rQ2$Lx9+P")

    assert address.username == "NightFox"
    assert address.host == "203.0.113.25"
    assert address.port == 45812
    assert str(address) == "mcw://NightFox@203.0.113.25:45812/H7@rQ2$Lx9+P"


def test_formats_ipv6_address_with_brackets() -> None:
    address = MacawAddress("Alice", "2001:db8::5", 45812, "N2$Tf8+AqL4Z")

    assert str(address) == "mcw://Alice@[2001:db8::5]:45812/N2$Tf8+AqL4Z"
    assert MacawAddress.parse(str(address)) == address


@pytest.mark.parametrize(
    "value",
    [
        "https://Alice@example.test:45812/N2$Tf8+AqL4",
        "mcw://Al@example.test:45812/N2$Tf8+AqL4",
        "mcw://Alice@example.test:0/N2$Tf8+AqL4",
        "mcw://Alice@example.test:45812/not-valid",
    ],
)
def test_rejects_invalid_addresses(value: str) -> None:
    with pytest.raises(ValidationError):
        MacawAddress.parse(value)
