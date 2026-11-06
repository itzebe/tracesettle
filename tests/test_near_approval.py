"""Human-approval tests.

An approval is a *human* decision about one exact payload. These tests assert the
binding (payload, service, expiry, single-use) and that no non-VALID state can
ever raise a decision to ALLOW. The approval authority is real; only its clock is
substituted, so the signature and binding logic all run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tracesettle.near.approval import (
    ApprovalAuthority,
    ApprovalState,
    CallbackChannel,
    DenyAllChannel,
)

KEY = bytes(range(32))
FINGERPRINT = "a" * 64


def _authority(*, ttl: int = 300) -> ApprovalAuthority:
    return ApprovalAuthority(key=KEY, key_id="approval", ttl_seconds=ttl)


def _request(authority: ApprovalAuthority, *, fingerprint: str = FINGERPRINT, service_id: str = "treasury-agent"):
    return authority.build_request(
        service_id=service_id,
        operation="WITHDRAWAL",
        chain="base",
        asset="USDC",
        amount="6000",
        destination="0xabc",
        payload_fingerprint=fingerprint,
        summary="withdraw 6000 USDC",
    )


def test_valid_approval_for_the_exact_payload():
    authority = _authority()
    request = _request(authority)
    approval = authority.approve(request, approver="ops-human")
    verification = authority.validate(
        approval, expected_payload_fingerprint=FINGERPRINT, expected_service_id="treasury-agent"
    )
    assert verification.state is ApprovalState.VALID
    assert verification.approver == "ops-human"


def test_changed_payload_is_rejected():
    authority = _authority()
    approval = authority.approve(_request(authority), approver="ops-human")
    verification = authority.validate(
        approval, expected_payload_fingerprint="b" * 64, expected_service_id="treasury-agent"
    )
    assert verification.state is ApprovalState.WRONG_PAYLOAD
    assert not verification.valid


def test_wrong_service_is_rejected():
    authority = _authority()
    approval = authority.approve(_request(authority), approver="ops-human")
    verification = authority.validate(
        approval, expected_payload_fingerprint=FINGERPRINT, expected_service_id="other-agent"
    )
    assert verification.state is ApprovalState.WRONG_SERVICE


def test_forged_signature_is_rejected():
    authority = _authority()
    approval = authority.approve(_request(authority), approver="ops-human")
    forged = type(approval)(**{**approval.__dict__, "signature": "0" * 64})
    verification = authority.validate(
        forged, expected_payload_fingerprint=FINGERPRINT, expected_service_id="treasury-agent"
    )
    assert verification.state is ApprovalState.BAD_SIGNATURE


def test_unknown_key_is_rejected():
    authority = _authority()
    approval = authority.approve(_request(authority), approver="ops-human")
    other = ApprovalAuthority(key=bytes(range(1, 33)), key_id="different")
    verification = other.validate(
        approval, expected_payload_fingerprint=FINGERPRINT, expected_service_id="treasury-agent"
    )
    assert verification.state is ApprovalState.BAD_SIGNATURE


def test_expired_approval_is_rejected():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    clock = [now]
    authority = ApprovalAuthority(key=KEY, key_id="approval", ttl_seconds=60, clock=lambda: clock[0])
    approval = authority.approve(_request(authority), approver="ops-human")
    clock[0] = now + timedelta(seconds=120)
    verification = authority.validate(
        approval, expected_payload_fingerprint=FINGERPRINT, expected_service_id="treasury-agent"
    )
    assert verification.state is ApprovalState.EXPIRED


def test_replayed_approval_is_rejected():
    authority = _authority()
    approval = authority.approve(_request(authority), approver="ops-human")
    first = authority.validate(
        approval,
        expected_payload_fingerprint=FINGERPRINT,
        expected_service_id="treasury-agent",
        consume=True,
    )
    second = authority.validate(
        approval,
        expected_payload_fingerprint=FINGERPRINT,
        expected_service_id="treasury-agent",
        consume=True,
    )
    assert first.state is ApprovalState.VALID
    assert second.state is ApprovalState.REPLAYED


def test_missing_approval_is_missing_not_valid():
    authority = _authority()
    verification = authority.validate(
        None, expected_payload_fingerprint=FINGERPRINT, expected_service_id="treasury-agent"
    )
    assert verification.state is ApprovalState.MISSING


def test_deny_all_channel_returns_no_approver():
    channel = DenyAllChannel()
    assert channel.request_approval(_request(_authority())) is None


def test_callback_channel_returns_the_approver():
    channel = CallbackChannel(lambda _req: "ops-human")
    assert channel.request_approval(_request(_authority())) == "ops-human"


def test_approval_requires_a_named_approver():
    authority = _authority()
    with pytest.raises(ValueError):
        authority.approve(_request(authority), approver="   ")


def test_approval_signature_domain_separated_from_guard_authorization():
    # The signed body carries a domain prefix, so an approval signature can never
    # verify as a guard authorization even if a deployment reused the key.
    authority = _authority()
    approval = authority.approve(_request(authority), approver="ops-human")
    assert b"tracesettle-approval" in approval.signing_payload()
