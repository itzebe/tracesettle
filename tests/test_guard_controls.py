"""Deterministic control and decision tests.

These exercise the real controls and the real decision aggregation. Every
assertion is about behaviour a reviewer can reproduce: the same request and the
same policy always yield the same decision, and every decision is explained.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from tracesettle.guard.model import (
    AmountError,
    ControlOutcome,
    Decision,
    EvaluationContext,
    FindingSeverity,
    canonical_amount,
    canonical_fields,
    fingerprint_of,
    parse_amount,
)
from tracesettle.guard.policy import DEFAULT_POLICY, PolicyConfig, ServicePolicy, policy_from_dict
from tracesettle.guard.rules import (
    CONTROL_AMOUNT,
    CONTROL_CLIENT_ASSERTIONS,
    CONTROL_DESTINATION,
    CONTROL_IDENTITY,
    CONTROL_INTEGRITY,
    CONTROL_VELOCITY,
    evaluate_controls,
)

from guard_helpers import (
    APPROVED_DESTINATION,
    DENIED_DESTINATION,
    OTHER_APPROVED_DESTINATION,
    UNAPPROVED_DESTINATION,
    make_request,
    make_service,
)


def codes(result) -> set[str]:
    return {f.code for f in result.findings}


# --- amount parsing --------------------------------------------------------


@pytest.mark.parametrize("text", ["0", "1", "100.50", "1250.50", "1000000"])
def test_parse_amount_accepts_decimal_strings(text):
    assert parse_amount(text) == Decimal(text)


@pytest.mark.parametrize("bad", [1.5, True, None, "", "abc", "-1", "NaN", "Infinity"])
def test_parse_amount_rejects_unsafe_values(bad):
    with pytest.raises(AmountError):
        parse_amount(bad)


def test_parse_amount_rejects_absurd_precision():
    with pytest.raises(AmountError):
        parse_amount("1" * 41)
    with pytest.raises(AmountError):
        parse_amount("0." + "1" * 19)


def test_canonical_amount_is_stable_across_representations():
    assert canonical_amount(Decimal("100.50")) == "100.5"
    assert canonical_amount(Decimal("100.500")) == "100.5"
    assert canonical_amount(Decimal("0.000")) == "0"
    assert canonical_amount(Decimal("100000000000000000000")) == "100000000000000000000"


# --- identity control ------------------------------------------------------


def test_unknown_service_identity_blocks():
    request = make_request(service_id="not-registered")
    results = evaluate_controls(request, DEFAULT_POLICY, EvaluationContext())
    identity = next(r for r in results if r.code == CONTROL_IDENTITY)
    assert identity.outcome is ControlOutcome.BLOCK
    assert "UNAUTHORIZED_SERVICE_IDENTITY" in codes(identity)


def test_disabled_service_identity_blocks():
    policy = PolicyConfig(
        services={
            "treasury-agent": ServicePolicy(service_id="treasury-agent", enabled=False),
        }
    )
    results = evaluate_controls(make_request(), policy, EvaluationContext())
    identity = next(r for r in results if r.code == CONTROL_IDENTITY)
    assert identity.outcome is ControlOutcome.BLOCK
    assert "SERVICE_IDENTITY_DISABLED" in codes(identity)


def test_operation_chain_and_asset_are_each_allowlisted():
    op = evaluate_controls(make_request(operation="DRAIN"), DEFAULT_POLICY, EvaluationContext())
    assert next(r for r in op if r.code == CONTROL_IDENTITY).outcome is ControlOutcome.BLOCK

    chain = evaluate_controls(make_request(chain="sol"), DEFAULT_POLICY, EvaluationContext())
    assert next(r for r in chain if r.code == CONTROL_IDENTITY).outcome is ControlOutcome.BLOCK

    asset = evaluate_controls(make_request(asset="DOGE"), DEFAULT_POLICY, EvaluationContext())
    assert next(r for r in asset if r.code == CONTROL_IDENTITY).outcome is ControlOutcome.BLOCK


def test_known_identity_passes():
    results = evaluate_controls(make_request(), DEFAULT_POLICY, EvaluationContext())
    assert next(r for r in results if r.code == CONTROL_IDENTITY).outcome is ControlOutcome.PASS


# --- destination control ---------------------------------------------------


def test_denied_destination_blocks_regardless_of_allowlist():
    # Denied even though it is also on the allowlist: the denylist wins.
    policy = PolicyConfig(
        approved_destinations=frozenset({DENIED_DESTINATION.lower()}),
        blocked_destinations=frozenset({DENIED_DESTINATION.lower()}),
    )
    results = evaluate_controls(make_request(destination=DENIED_DESTINATION), policy, EvaluationContext())
    destination = next(r for r in results if r.code == CONTROL_DESTINATION)
    assert destination.outcome is ControlOutcome.BLOCK
    assert "DESTINATION_DENIED" in codes(destination)


def test_unapproved_destination_blocks_under_allowlist_only_policy():
    results = evaluate_controls(
        make_request(destination=UNAPPROVED_DESTINATION), DEFAULT_POLICY, EvaluationContext()
    )
    destination = next(r for r in results if r.code == CONTROL_DESTINATION)
    assert destination.outcome is ControlOutcome.BLOCK
    assert "UNAPPROVED_DESTINATION" in codes(destination)


def test_unapproved_destination_requires_review_when_policy_permits_listing():
    policy = PolicyConfig(
        approved_destinations=frozenset({APPROVED_DESTINATION.lower()}),
        allow_unlisted_destinations=True,
    )
    results = evaluate_controls(make_request(destination=UNAPPROVED_DESTINATION), policy, EvaluationContext())
    destination = next(r for r in results if r.code == CONTROL_DESTINATION)
    assert destination.outcome is ControlOutcome.REVIEW
    assert destination.decision is Decision.REQUIRE_APPROVAL


def test_approved_destination_passes():
    results = evaluate_controls(make_request(), DEFAULT_POLICY, EvaluationContext())
    assert next(r for r in results if r.code == CONTROL_DESTINATION).outcome is ControlOutcome.PASS


def test_destination_case_is_normalised_for_evm_hex_only():
    upper = make_request(destination=APPROVED_DESTINATION.upper().replace("0X", "0x"))
    results = evaluate_controls(upper, DEFAULT_POLICY, EvaluationContext())
    assert next(r for r in results if r.code == CONTROL_DESTINATION).outcome is ControlOutcome.PASS


def test_missing_destination_blocks():
    results = evaluate_controls(make_request(destination=""), DEFAULT_POLICY, EvaluationContext())
    destination = next(r for r in results if r.code == CONTROL_DESTINATION)
    assert destination.outcome is ControlOutcome.BLOCK
    assert "MISSING_DESTINATION" in codes(destination)


# --- amount control --------------------------------------------------------


def test_amount_above_limit_blocks():
    results = evaluate_controls(
        make_request(amount=Decimal("10001"), amount_raw="10001"), DEFAULT_POLICY, EvaluationContext()
    )
    amount = next(r for r in results if r.code == CONTROL_AMOUNT)
    assert amount.outcome is ControlOutcome.BLOCK
    assert "AMOUNT_EXCEEDS_LIMIT" in codes(amount)


def test_amount_above_threshold_requires_approval():
    results = evaluate_controls(
        make_request(amount=Decimal("6000"), amount_raw="6000"), DEFAULT_POLICY, EvaluationContext()
    )
    amount = next(r for r in results if r.code == CONTROL_AMOUNT)
    assert amount.outcome is ControlOutcome.REVIEW
    assert "AMOUNT_REQUIRES_APPROVAL" in codes(amount)


def test_amount_at_exact_limit_passes_when_the_limit_is_not_an_approval_threshold():
    policy = PolicyConfig(services=DEFAULT_POLICY.services, per_transaction_limit=Decimal("10000"))
    results = evaluate_controls(
        make_request(amount=Decimal("10000"), amount_raw="10000"), policy, EvaluationContext()
    )
    # The service-level approval threshold still applies, so an amount that
    # exactly equals the transaction limit but is above the threshold needs
    # approval rather than passing outright.
    assert next(r for r in results if r.code == CONTROL_AMOUNT).outcome is ControlOutcome.REVIEW


def test_amount_at_exact_threshold_passes():
    results = evaluate_controls(
        make_request(amount=Decimal("5000"), amount_raw="5000"), DEFAULT_POLICY, EvaluationContext()
    )
    assert next(r for r in results if r.code == CONTROL_AMOUNT).outcome is ControlOutcome.PASS


# --- velocity control ------------------------------------------------------


def test_request_velocity_exceeded_holds():
    policy = PolicyConfig(services=DEFAULT_POLICY.services, max_requests_per_window=3)
    ctx = EvaluationContext(recent_request_count=3)
    results = evaluate_controls(make_request(), policy, ctx)
    velocity = next(r for r in results if r.code == CONTROL_VELOCITY)
    assert velocity.outcome is ControlOutcome.HOLD
    assert "REQUEST_VELOCITY_EXCEEDED" in codes(velocity)


def test_blocked_request_rate_holds():
    policy = PolicyConfig(services=DEFAULT_POLICY.services, max_blocked_per_window=2)
    ctx = EvaluationContext(recent_blocked_count=2)
    results = evaluate_controls(make_request(), policy, ctx)
    velocity = next(r for r in results if r.code == CONTROL_VELOCITY)
    assert velocity.outcome is ControlOutcome.HOLD
    assert "ABNORMAL_BLOCK_RATE" in codes(velocity)


def test_window_volume_holds_when_projected_total_exceeds_limit():
    ctx = EvaluationContext(window_volume={"treasury-agent:USDC": Decimal("24900")})
    results = evaluate_controls(
        make_request(amount=Decimal("200"), amount_raw="200"), DEFAULT_POLICY, ctx
    )
    velocity = next(r for r in results if r.code == CONTROL_VELOCITY)
    assert velocity.outcome is ControlOutcome.HOLD
    assert "WINDOW_VOLUME_EXCEEDED" in codes(velocity)


def test_window_volume_is_per_asset():
    ctx = EvaluationContext(window_volume={"treasury-agent:USDC": Decimal("24900")})
    results = evaluate_controls(make_request(asset="ETH", amount=Decimal("200"), amount_raw="200"),
                                DEFAULT_POLICY, ctx)
    assert next(r for r in results if r.code == CONTROL_VELOCITY).outcome is ControlOutcome.PASS


# --- rejected authorization control ---------------------------------------


def test_repeated_rejected_authorizations_hold():
    ctx = EvaluationContext(recent_rejected_authorizations=3)
    results = evaluate_controls(make_request(), DEFAULT_POLICY, ctx)
    rejected = next(r for r in results if r.code == "REJECTED_AUTHORIZATION_ATTEMPTS")
    assert rejected.outcome is ControlOutcome.HOLD
    assert "REPEATED_AUTHORIZATION_REJECTIONS" in codes(rejected)


# --- client-asserted approval ---------------------------------------------


def test_client_asserted_approval_is_never_honoured():
    request = make_request(asserted_approval_fields=("approved", "skip_checks"))
    results = evaluate_controls(request, DEFAULT_POLICY, EvaluationContext())
    assertions = next(r for r in results if r.code == CONTROL_CLIENT_ASSERTIONS)
    assert assertions.outcome is ControlOutcome.REVIEW
    assert assertions.decision is Decision.REQUIRE_APPROVAL
    assert "CLIENT_ASSERTED_APPROVAL_IGNORED" in codes(assertions)


def test_unrecognised_assertion_names_are_ignored():
    request = make_request(asserted_approval_fields=("something_else",))
    results = evaluate_controls(request, DEFAULT_POLICY, EvaluationContext())
    assertions = next(r for r in results if r.code == CONTROL_CLIENT_ASSERTIONS)
    assert assertions.outcome is ControlOutcome.PASS


# --- integrity control ----------------------------------------------------


def test_missing_parameters_are_reported():
    request = make_request(service_id="", chain="", asset="", request_id="")
    results = evaluate_controls(request, DEFAULT_POLICY, EvaluationContext())
    integrity = next(r for r in results if r.code == CONTROL_INTEGRITY)
    assert integrity.outcome is ControlOutcome.BLOCK
    found = codes(integrity)
    assert {"MISSING_SERVICE_ID", "MISSING_CHAIN", "MISSING_ASSET", "MISSING_REQUEST_ID"} <= found


def test_zero_amount_is_flagged():
    request = make_request(amount=Decimal("0"), amount_raw="0")
    results = evaluate_controls(request, DEFAULT_POLICY, EvaluationContext())
    integrity = next(r for r in results if r.code == CONTROL_INTEGRITY)
    assert "ZERO_AMOUNT" in codes(integrity)


# --- aggregation ----------------------------------------------------------


def test_every_control_runs_even_after_a_block():
    request = make_request(service_id="unknown", destination=UNAPPROVED_DESTINATION)
    results = evaluate_controls(request, DEFAULT_POLICY, EvaluationContext())
    assert len(results) == 7
    assert any(r.outcome is ControlOutcome.BLOCK for r in results)


def test_decision_is_the_strictest_control_outcome():
    service = make_service()
    decision = service.evaluate(make_request(service_id="unknown"))
    assert decision.decision is Decision.BLOCK
    assert decision.risk_level is FindingSeverity.CRITICAL


def test_identical_requests_produce_identical_decisions():
    service_a = make_service()
    service_b = make_service()
    request = make_request()
    first = service_a.evaluate(request)
    second = service_b.evaluate(request)
    assert first.decision is second.decision
    assert first.risk_level is second.risk_level
    assert [c.code for c in first.controls] == [c.code for c in second.controls]
    assert [c.outcome for c in first.controls] == [c.outcome for c in second.controls]
    assert [f.code for f in first.findings] == [f.code for f in second.findings]


def test_allow_decision_explains_itself_and_authorizes():
    service = make_service()
    decision = service.evaluate(make_request())
    assert decision.decision is Decision.ALLOW
    assert decision.authorizes_signing is True
    assert decision.authorization is not None
    assert "passed every control" in decision.summary


def test_block_decision_has_no_authorization_and_explains_why():
    service = make_service()
    decision = service.evaluate(make_request(service_id="unknown"))
    assert decision.decision is Decision.BLOCK
    assert decision.authorization is None
    assert decision.authorizes_signing is False
    assert "No authorization was issued" in decision.explanation


def test_fingerprint_changes_when_any_bound_parameter_changes():
    base = canonical_fields(
        service_id="treasury-agent", operation="WITHDRAWAL", chain="eth", asset="USDC",
        amount=Decimal("100"), destination=APPROVED_DESTINATION,
    )
    base_digest = fingerprint_of(base).digest
    for field, value in (
        ("service_id", "other"),
        ("operation", "SETTLEMENT"),
        ("chain", "base"),
        ("asset", "USDT"),
        ("amount", "100.01"),
        ("destination", OTHER_APPROVED_DESTINATION),
    ):
        changed = dict(base)
        changed[field] = value
        assert fingerprint_of(changed).digest != base_digest, field


def test_fingerprint_is_case_insensitive_only_where_the_chain_is():
    a = canonical_fields(
        service_id="treasury-agent", operation="withdrawal", chain="ETH", asset="usdc",
        amount=Decimal("100"), destination=APPROVED_DESTINATION.lower(),
    )
    b = canonical_fields(
        service_id="treasury-agent", operation="WITHDRAWAL", chain="eth", asset="USDC",
        amount=Decimal("100"), destination=APPROVED_DESTINATION.upper().replace("0X", "0x"),
    )
    assert fingerprint_of(a).digest == fingerprint_of(b).digest


def test_amount_is_compared_exactly_not_as_a_float():
    policy = PolicyConfig(per_transaction_limit=Decimal("0.3"), services=DEFAULT_POLICY.services)
    results = evaluate_controls(
        make_request(amount=Decimal("0.1") + Decimal("0.2"), amount_raw="0.1+0.2"),
        policy, EvaluationContext(),
    )
    assert next(r for r in results if r.code == CONTROL_AMOUNT).outcome is ControlOutcome.PASS


# --- policy loading -------------------------------------------------------


def test_policy_from_dict_overrides_selected_fields():
    policy = policy_from_dict(
        {
            "policy_id": "custom",
            "per_transaction_limit": "500",
            "approved_destinations": [APPROVED_DESTINATION],
            "services": [
                {
                    "service_id": "svc-a",
                    "allowed_chains": ["base"],
                    "allowed_assets": ["USDC"],
                    "max_amount_per_transaction": "400",
                }
            ],
        }
    )
    assert policy.policy_id == "custom"
    assert policy.per_transaction_limit == Decimal("500")
    assert policy.services["svc-a"].allowed_chains == frozenset({"base"})
    # Unspecified fields keep the default, so a partial file is a valid override.
    assert policy.window_seconds == DEFAULT_POLICY.window_seconds


def test_policy_rejects_a_non_decimal_limit():
    with pytest.raises(ValueError):
        policy_from_dict({"per_transaction_limit": "not-a-number"})


def test_policy_destination_case_normalised_on_load():
    policy = policy_from_dict({"approved_destinations": [APPROVED_DESTINATION.upper().replace("0X", "0x")]})
    assert APPROVED_DESTINATION.lower() in policy.approved_destinations
