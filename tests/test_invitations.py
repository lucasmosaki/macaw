from __future__ import annotations

from datetime import timedelta

from contacts.invitations import InvitationRegistry


def test_invitation_is_persisted_then_consumed(tmp_path) -> None:
    path = tmp_path / "invitations.json"
    first = InvitationRegistry(path)
    invitation = first.create(timedelta(minutes=5))

    restarted = InvitationRegistry(path)
    assert restarted.is_valid(invitation.code)
    assert restarted.consume(invitation.code)
    assert not restarted.is_valid(invitation.code)
    assert not InvitationRegistry(path).is_valid(invitation.code)


def test_running_registry_sees_an_invitation_issued_by_another_process(tmp_path) -> None:
    path = tmp_path / "invitations.json"
    listener_registry = InvitationRegistry(path)
    address_command_registry = InvitationRegistry(path)
    invitation = address_command_registry.create()

    assert listener_registry.is_valid(invitation.code)
    assert listener_registry.consume(invitation.code)


def test_invitation_has_expected_format() -> None:
    invitation = InvitationRegistry().create()

    assert len(invitation.code) == 12
    assert not invitation.expired
