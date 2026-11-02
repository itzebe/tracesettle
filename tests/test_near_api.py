"""Tests for the NEAR HTTP surface and the TEE research module.

The HTTP tests go through the real socket handler and the real GuardAPI. They
assert that the NEAR endpoints exist, that the agent-evaluate endpoint returns
one of the five outcomes, and that a client-supplied approval flag is not
honoured. No network call is made.
"""

from __future__ import annotations

import pathlib

from tracesettle.guard.api import GuardAPI
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.policy import PolicyConfig, ServicePolicy
from tracesettle.guard.service import GuardService
from tracesettle.near.tee import (
    AttestationStatus,
    NEAR_AI_CLOUD_NOTES,
    OUTLAYER_NOTES,
    assess_verifiable_execution,
)
from decimal import Decimal

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "near"

APPROVED = "0x1111111111111111111111111111111111111111"
ATTACKER = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def _service() -> GuardService:
    policy = PolicyConfig(
        policy_id="near-api-test",
        name="near api test",
        version="1",
        approved_destinations=frozenset({APPROVED}),
        blocked_destinations=frozenset(),
        services={
            "treasury-agent": ServicePolicy(
                service_id="treasury-agent",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"base"}),
                allowed_assets=frozenset({"USDC"}),
                max_amount_per_transaction=Decimal("10000"),
                approval_threshold=Decimal("5000"),
            )
        },
        per_transaction_limit=Decimal("10000"),
        approval_threshold=Decimal("5000"),
        allow_unlisted_destinations=False,
    )
    return GuardService(
        policy=policy,
        authority=AuthorizationAuthority(
            key=bytes(range(32)), key_id="t", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )


def _api() -> GuardAPI:
    return GuardAPI(_service())


def _tx(destination: str = APPROVED, **overrides) -> dict:
    base = {
        "service_id": "treasury-agent",
        "operation": "WITHDRAWAL",
        "chain": "base",
        "asset": "USDC",
        "amount": "1250.50",
        "destination": destination,
        "scope": "INTENTS",
        "policy_action": "withdraw",
    }
    base.update(overrides)
    return base


# --- GET endpoints ----------------------------------------------------------


def test_near_scenarios_endpoint_reports_all_passed():
    response = _api().dispatch("GET", "/api/guard/near/scenarios", {}, None)
    assert response.status == 200
    assert response.payload["all_passed"] is True
    assert len(response.payload["results"]) == 9
    assert "simulat" in response.payload["note"].lower()


def test_near_access_keys_endpoint_analyses_the_documented_shapes():
    response = _api().dispatch("GET", "/api/guard/near/access-keys", {}, None)
    assert response.status == 200
    keys = response.payload["keys"]["keys"]
    assert keys["full_access"]["can_transfer_near"] is True
    assert keys["function_call_scoped"]["can_transfer_near"] is False
    assert "no private key material" in response.payload["keys"]["note"].lower()


def test_near_policy_scope_endpoint_states_the_gap():
    response = _api().dispatch("GET", "/api/guard/near/policy-scope", {}, None)
    assert response.status == 200
    scope = response.payload["scope"]
    assert "destinations" in scope["INTENTS"]["applicable_controls"]
    assert "destinations" in scope["NATIVE_NEAR"]["non_applicable_controls"]
    assert "native" in response.payload["note"].lower()


# --- agent-evaluate endpoint ------------------------------------------------


def test_agent_evaluate_allows_a_legitimate_intents_request():
    response = _api().dispatch(
        "POST", "/api/guard/near/agent-evaluate", {}, {"transaction": _tx()}
    )
    assert response.status == 200
    assert response.payload["outcome"] == "ALLOW"
    assert response.payload["permits_signing"] is True
    assert response.payload["simulated"] is True


def test_agent_evaluate_blocks_an_unapproved_destination():
    response = _api().dispatch(
        "POST", "/api/guard/near/agent-evaluate", {}, {"transaction": _tx(ATTACKER)}
    )
    assert response.status == 200
    assert response.payload["outcome"] == "BLOCK"
    assert response.payload["permits_signing"] is False


def test_agent_evaluate_returns_one_of_the_five_outcomes():
    from tracesettle.near.agent_wrapper import AGENT_DECISION_OUTCOMES

    response = _api().dispatch(
        "POST", "/api/guard/near/agent-evaluate", {}, {"transaction": _tx()}
    )
    assert response.payload["outcome"] in AGENT_DECISION_OUTCOMES


def test_agent_evaluate_requires_a_transaction_object():
    response = _api().dispatch("POST", "/api/guard/near/agent-evaluate", {}, {})
    assert response.status == 400


def test_agent_evaluate_rejects_an_unknown_scope():
    response = _api().dispatch(
        "POST",
        "/api/guard/near/agent-evaluate",
        {},
        {"transaction": _tx(scope="SOMEWHERE_ELSE")},
    )
    assert response.status == 400


def test_agent_evaluate_does_not_return_the_authorization_by_default():
    response = _api().dispatch(
        "POST", "/api/guard/near/agent-evaluate", {}, {"transaction": _tx()}
    )
    assert "authorization" not in response.payload["guard_decision"]


def test_agent_evaluate_can_return_the_authorization_when_asked():
    response = _api().dispatch(
        "POST",
        "/api/guard/near/agent-evaluate",
        {},
        {"transaction": _tx(), "return_authorization": True},
    )
    assert response.payload["guard_decision"]["authorization"] is not None


def test_agent_evaluate_uses_a_policy_fixture_when_supplied():
    fixture = str(FIXTURE_DIR / "policy_in_force.json")
    response = _api().dispatch(
        "POST",
        "/api/guard/near/agent-evaluate",
        {},
        {"transaction": _tx(), "policy_fixture": fixture},
    )
    assert response.status == 200
    assert response.payload["policy"]["local_fixture"] is True


def test_agent_evaluate_never_honours_a_client_approval_flag():
    response = _api().dispatch(
        "POST",
        "/api/guard/near/agent-evaluate",
        {},
        {"transaction": _tx(approved=True, skip_checks=True)},
    )
    assert response.payload["permits_signing"] is False
    assert response.payload["outcome"] in {"REQUIRE_APPROVAL", "BLOCK"}


# --- TEE research -----------------------------------------------------------


def test_outlayer_is_not_attempted_because_it_requires_payment():
    assessment = assess_verifiable_execution("outlayer", requires_payment=True)
    assert assessment.status is AttestationStatus.NOT_ATTEMPTED
    assert assessment.claims_protection is False
    assert assessment.requires_payment is True


def test_an_absent_attestation_is_not_protection():
    assessment = assess_verifiable_execution("near-ai-cloud", attestation=None)
    assert assessment.status is AttestationStatus.ABSENT
    assert assessment.claims_protection is False


def test_an_unverifiable_attestation_is_not_protection():
    assessment = assess_verifiable_execution("outlayer", attestation={"sig": "x"})
    assert assessment.status is AttestationStatus.UNVERIFIABLE
    assert assessment.claims_protection is False


def test_a_verified_attestation_claims_protection():
    assessment = assess_verifiable_execution(
        "outlayer", attestation={"sig": "x"}, verifier=lambda a: True
    )
    assert assessment.status is AttestationStatus.VERIFIED
    assert assessment.claims_protection is True


def test_a_rejecting_verifier_is_not_protection():
    assessment = assess_verifiable_execution(
        "outlayer", attestation={"sig": "x"}, verifier=lambda a: False
    )
    assert assessment.status is AttestationStatus.UNVERIFIABLE
    assert assessment.claims_protection is False


def test_a_raising_verifier_is_not_protection():
    def boom(_):
        raise RuntimeError("no key")

    assessment = assess_verifiable_execution("outlayer", attestation={"sig": "x"}, verifier=boom)
    assert assessment.status is AttestationStatus.UNVERIFIABLE
    assert assessment.claims_protection is False


def test_the_research_notes_record_the_payment_decision():
    assert "financial commitment" in OUTLAYER_NOTES
    assert "does not verify" in NEAR_AI_CLOUD_NOTES


def test_near_settlement_demo_reports_a_provider_claim_as_unverified():
    """A provider success claim with no evidence must not be VERIFIED."""
    response = _api().dispatch("GET", "/api/guard/near/settlement-demo", {}, None)
    assert response.status == 200
    assurance = response.payload["assurance"]
    assert assurance["independently_verified"] is False
    assert assurance["level"] in {"UNKNOWN", "UNAVAILABLE"}
    assert "REPORTED claim" in response.payload["note"]
