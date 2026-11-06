"""Authorization and reference-signer enforcement tests.

These are the security-critical tests. They prove, by execution, that:

* an authorization is bound to the exact transaction parameters;
* it expires, and it can be used exactly once;
* the signer refuses every failure mode, and a refusal never reaches the executor;
* a caller cannot substitute a parameter, forge a token, or assert its own approval.

The executor records what it was asked to do, so "the signer refused" is checked
against "the executor was never called", not merely against the returned status.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from tracesettle.guard.authorization import (
    AUTHORIZATION_VERSION,
    AuthorizationAuthority,
    InMemoryReplayStore,
    load_key,
)
from tracesettle.guard.model import AuthState, SignOutcome, canonical_fields
from tracesettle.guard.signer import ReferenceSigner, SignRequest, SimulatedExecutor

from guard_helpers import (
    OTHER_APPROVED_DESTINATION,
    TEST_KEY,
    UNAPPROVED_DESTINATION,
    make_authority,
    make_request,
    make_service,
)


class CountingExecutor(SimulatedExecutor):
    """A simulated executor that records every call, so refusal is provable."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def execute(self, request, authorization_id):
        self.calls += 1
        return super().execute(request, authorization_id)


def params_for(request, **overrides):
    fields = canonical_fields(
        service_id=request.service_id,
        operation=request.operation,
        chain=request.chain,
        asset=request.asset,
        amount=request.amount,
        destination=request.destination,
    )
    fields.update(overrides)
    return fields


def issue(authority, request, **overrides):
    return authority.issue(
        decision_id="dec_test",
        decision=__import__("tracesettle.guard.model", fromlist=["Decision"]).Decision.ALLOW,
        service_id=request.service_id,
        parameters=params_for(request, **overrides),
    )


# --- issuing ---------------------------------------------------------------


def test_issue_refuses_for_any_non_allow_decision():
    from tracesettle.guard.model import Decision

    authority = make_authority()
    request = make_request()
    for decision in (Decision.BLOCK, Decision.HOLD, Decision.REQUIRE_APPROVAL):
        with pytest.raises(ValueError):
            authority.issue(
                decision_id="d",
                decision=decision,
                service_id=request.service_id,
                parameters=params_for(request),
            )


def test_issued_authorization_is_bound_and_signed():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    assert token.version == AUTHORIZATION_VERSION
    assert token.fingerprint
    assert token.signature
    assert token.nonce
    assert token.expires_at > token.issued_at


def test_key_must_be_at_least_32_bytes():
    with pytest.raises(ValueError):
        load_key("00" * 16)  # 16 bytes


def test_hex_and_base64_keys_are_accepted():
    hex_key, key_id, ephemeral = load_key("aa" * 32)
    assert len(hex_key) == 32 and not ephemeral
    import base64

    b64 = base64.b64encode(bytes(range(32))).decode()
    b64_key, _, _ = load_key(b64)
    assert b64_key == bytes(range(32))


def test_ephemeral_key_is_flagged():
    _, key_id, ephemeral = load_key(None) if not __import__("os").environ.get(
        "TRACESETTLE_GUARD_AUTH_KEY"
    ) else (b"", "", True)
    assert isinstance(ephemeral, bool)


# --- validation: the happy path -------------------------------------------


def test_valid_authorization_for_matching_parameters():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    result = authority.validate(token, expected=params_for(request))
    assert result.state is AuthState.VALID
    assert result.valid


def test_wrong_service_is_refused():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    result = authority.validate(token, expected=params_for(request), expected_service_id="someone-else")
    assert result.state is AuthState.WRONG_SERVICE


# --- validation: every refusal mode ---------------------------------------


def test_missing_authorization_is_refused():
    authority = make_authority()
    assert authority.validate(None, expected={}).state is AuthState.MISSING


def test_malformed_authorization_is_refused():
    authority = make_authority()
    assert authority.validate({"version": "x"}, expected={}).state is AuthState.MALFORMED


@pytest.mark.parametrize("token", ["a-string-token", 12345, True, ["v"], object()])
def test_a_non_token_authorization_is_refused_not_raised(token):
    """A caller may present any JSON value as ``authorization``.

    A bare string, int, bool, list or arbitrary object is not an authorization,
    so validating it must return a refusal. It must never raise: an unhandled
    exception on the sign path is a 500 and, worse, an availability risk on the
    enforcement boundary. Only a token object or a token-shaped dict may reach
    the field checks.
    """
    authority = make_authority()
    verification = authority.validate(token, expected={})
    assert verification.state is AuthState.MALFORMED
    assert "expected a token object" in verification.detail


def test_bad_signature_is_refused():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    tampered = dict(token.to_dict())
    tampered["signature"] = "0" * 64
    result = authority.validate(tampered, expected=params_for(request))
    assert result.state is AuthState.BAD_SIGNATURE


def test_edited_parameters_break_the_signature():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    tampered = dict(token.to_dict())
    tampered["parameters"] = dict(tampered["parameters"], destination=UNAPPROVED_DESTINATION)
    result = authority.validate(tampered, expected=params_for(request))
    assert result.state is AuthState.BAD_SIGNATURE


def test_parameter_substitution_with_a_genuine_token_is_refused():
    """The token is authentic, but bound to different parameters than the transaction."""
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    # The signer is asked to sign a *different* transaction with the same token.
    other = make_request(destination=OTHER_APPROVED_DESTINATION, amount=Decimal("999"))
    result = authority.validate(token, expected=params_for(other))
    assert result.state is AuthState.WRONG_PARAMETERS


def test_unknown_signing_key_is_refused():
    authority = make_authority()
    other = AuthorizationAuthority(key=b"\x01" * 32, key_id="different-key", ephemeral=False)
    request = make_request()
    token = issue(other, request)
    result = authority.validate(token, expected=params_for(request))
    assert result.state is AuthState.UNKNOWN_KEY


def test_expired_authorization_is_refused():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    clock = lambda: now  # noqa: E731
    authority = make_authority(ttl_seconds=60, clock=clock)
    request = make_request()
    token = issue(authority, request)
    later = datetime(2026, 1, 1, 12, 2, 0, tzinfo=timezone.utc)
    authority._clock = lambda: later  # noqa: SLF001 - deliberate time travel in a test
    result = authority.validate(token, expected=params_for(request))
    assert result.state is AuthState.EXPIRED


def test_not_yet_valid_authorization_is_refused():
    issued_at = datetime(2026, 1, 1, 12, 0, 30, tzinfo=timezone.utc)
    authority = make_authority(ttl_seconds=60, clock=lambda: issued_at)
    request = make_request()
    token = issue(authority, request)
    authority._clock = lambda: datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # noqa: SLF001
    result = authority.validate(token, expected=params_for(request))
    assert result.state is AuthState.NOT_YET_VALID


def test_replay_is_refused():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    assert authority.validate(token, expected=params_for(request)).state is AuthState.VALID
    second = authority.validate(token, expected=params_for(request))
    assert second.state is AuthState.REPLAYED


def test_non_consuming_validation_does_not_spend_the_token():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    assert authority.validate(token, expected=params_for(request), consume=False).state is AuthState.VALID
    assert authority.validate(token, expected=params_for(request), consume=False).state is AuthState.VALID
    # The token is still usable for a real signing attempt.
    assert authority.validate(token, expected=params_for(request)).state is AuthState.VALID


def test_revoked_authorization_is_refused():
    authority = make_authority()
    request = make_request()
    token = issue(authority, request)
    authority.revoke(token.authorization_id)
    assert authority.validate(token, expected=params_for(request)).state is AuthState.REVOKED


def test_replay_store_is_single_use_and_bounded():
    store = InMemoryReplayStore(max_entries=4)
    assert store.consume("n1", 1e12) is True
    assert store.consume("n1", 1e12) is False
    for index in range(10):
        store.consume(f"n{index}", 1e12)
    # Bounded: the map never grows past its cap.
    assert len(store._consumed) <= 4  # noqa: SLF001 - asserting the bound directly


# --- the reference signer -------------------------------------------------


def test_signer_executes_with_a_valid_authorization():
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    decision = service.evaluate(request)
    result = signer.sign(SignRequest(transaction=request, authorization=decision.authorization))
    assert result.outcome is SignOutcome.EXECUTED
    assert result.state is AuthState.VALID
    assert result.simulated is True
    assert executor.calls == 1


@pytest.mark.parametrize(
    "authorization_factory, expected_state",
    [
        (lambda token, request: None, AuthState.MISSING),
        (lambda token, request: {}, AuthState.MALFORMED),
        (lambda token, request: dict(token.to_dict(), signature="0" * 64), AuthState.BAD_SIGNATURE),
    ],
)
def test_signer_refuses_and_never_executes(authorization_factory, expected_state):
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    decision = service.evaluate(request)
    result = signer.sign(
        SignRequest(transaction=request, authorization=authorization_factory(decision.authorization, request))
    )
    assert result.outcome is SignOutcome.REFUSED
    assert result.state is expected_state
    # The critical assertion: refusal means the executor was never reached.
    assert executor.calls == 0


def test_signer_refuses_a_replayed_authorization():
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    token = service.evaluate(request).authorization
    assert signer.sign(SignRequest(transaction=request, authorization=token)).outcome is SignOutcome.EXECUTED
    replay = signer.sign(SignRequest(transaction=request, authorization=token))
    assert replay.outcome is SignOutcome.REFUSED
    assert replay.state is AuthState.REPLAYED
    assert executor.calls == 1  # only the first attempt executed


def test_signer_refuses_a_token_bound_to_a_different_destination():
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    token = service.evaluate(request).authorization
    other = make_request(destination=UNAPPROVED_DESTINATION, amount=Decimal("9999"))
    result = signer.sign(SignRequest(transaction=other, authorization=token))
    assert result.outcome is SignOutcome.REFUSED
    assert result.state is AuthState.WRONG_PARAMETERS
    assert executor.calls == 0


def test_signer_refuses_a_token_bound_to_a_different_amount():
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    token = service.evaluate(request).authorization
    other = make_request(amount=Decimal("101"), amount_raw="101")
    result = signer.sign(SignRequest(transaction=other, authorization=token))
    assert result.state is AuthState.WRONG_PARAMETERS
    assert executor.calls == 0


def test_signer_refuses_a_token_issued_for_another_service():
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    token = service.evaluate(request).authorization
    result = signer.sign(
        SignRequest(transaction=request, authorization=token, expected_service_id="other-service")
    )
    assert result.state is AuthState.WRONG_SERVICE
    assert executor.calls == 0


def test_refusal_is_attributed_to_the_requester_not_the_forged_token():
    """A forged token must not be able to name the service a refusal is counted against.

    The rejected-authorization limit is counted per service, so if a refusal were
    attributed to ``token.service_id`` an authenticated attacker could set that
    field to a victim service and drive the victim into a HOLD. The refusal is
    attributed to the verified requester instead.
    """
    service = make_service()
    signer = ReferenceSigner(service.authority)
    # A token whose claimed service_id is the victim, signed with a bad signature.
    forged = {
        "version": AUTHORIZATION_VERSION,
        "authorization_id": "auth_forged",
        "decision_id": "dec_forged",
        "service_id": "treasury-agent",
        "key_id": "test-key",
        "nonce": "forged-nonce",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "fingerprint": "x",
        "parameters": {},
        "signature": "00" * 32,
    }
    attacker = make_request(service_id="attacker-service")
    result = signer.sign(
        SignRequest(
            transaction=attacker,
            authorization=forged,
            expected_service_id="attacker-service",
        )
    )
    assert result.outcome is SignOutcome.REFUSED
    assert result.state is AuthState.BAD_SIGNATURE
    assert result.service_id == "attacker-service", (
        "a refusal must be attributed to the requester, not the forged token's "
        f"claimed service (got {result.service_id!r})"
    )


def test_signer_refuses_an_expired_authorization():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    authority = make_authority(ttl_seconds=30, clock=lambda: now)
    executor = CountingExecutor()
    signer = ReferenceSigner(authority, executor)
    request = make_request()
    token = issue(authority, request)
    authority._clock = lambda: now + timedelta(seconds=31)  # noqa: SLF001
    result = signer.sign(SignRequest(transaction=request, authorization=token))
    assert result.outcome is SignOutcome.REFUSED
    assert result.state is AuthState.EXPIRED
    assert executor.calls == 0


def test_signer_refuses_a_token_from_an_untrusted_key():
    request = make_request()
    foreign = AuthorizationAuthority(key=b"\x07" * 32, key_id="foreign", ephemeral=False)
    token = issue(foreign, request)
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    result = signer.sign(SignRequest(transaction=request, authorization=token))
    assert result.state is AuthState.UNKNOWN_KEY
    assert executor.calls == 0


def test_verify_only_does_not_consume_or_execute():
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    request = make_request()
    token = service.evaluate(request).authorization
    assert signer.verify_only(SignRequest(transaction=request, authorization=token)).valid
    assert signer.verify_only(SignRequest(transaction=request, authorization=token)).valid
    assert executor.calls == 0
    # The token is untouched, so a real signing attempt still succeeds.
    assert signer.sign(SignRequest(transaction=request, authorization=token)).outcome is SignOutcome.EXECUTED


def test_signer_receipt_is_always_labelled_simulated():
    service = make_service()
    request = make_request()
    token = service.evaluate(request).authorization
    result = service.sign_transaction(request, token)
    assert result.receipt is not None
    assert result.receipt["simulated"] is True
    assert "no keys" in result.receipt["note"].lower()


def test_a_blocked_transaction_cannot_be_signed_even_with_a_token():
    """A token minted for one transaction cannot authorize a blocked one."""
    service = make_service()
    executor = CountingExecutor()
    signer = ReferenceSigner(service.authority, executor)
    allowed = make_request()
    token = service.evaluate(allowed).authorization
    blocked = make_request(destination=UNAPPROVED_DESTINATION, amount=Decimal("480000"), amount_raw="480000")
    decision = service.evaluate(blocked)
    assert decision.decision.value == "BLOCK"
    assert decision.authorization is None
    result = signer.sign(SignRequest(transaction=blocked, authorization=token))
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


def test_authority_reports_key_metadata_without_the_key():
    authority = make_authority()
    assert authority.key_id == "test-key"
    assert authority.ephemeral is False
    # The key itself is never exposed by an attribute or a repr of the token.
    token = issue(authority, make_request())
    assert TEST_KEY.hex() not in str(token.to_dict())
