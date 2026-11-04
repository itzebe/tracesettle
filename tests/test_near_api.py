"""Tests for the NEAR HTTP surface and the TEE research module.

The HTTP tests go through the real socket handler and the real GuardAPI. They
assert that the NEAR endpoints exist, that the agent-evaluate endpoint returns
one of the five outcomes, and that a client-supplied approval flag is not
honoured. No network call is made.
"""

from __future__ import annotations

import json
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

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "tracesettle" / "near" / "fixtures"

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
        # Intents lifecycle fields (ignored by agent-evaluate).
        "origin_asset": "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
        "destination_asset": "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
        "refund_to": destination,
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


def test_agent_evaluate_ignores_a_client_supplied_policy_fixture(monkeypatch):
    """A caller must not be able to choose the policy it is judged against.

    Honouring ``policy_fixture`` by default let a client replace the operator's
    restrictive policy with a permissive one and turn a BLOCK into an ALLOW.
    """
    fixture = str(FIXTURE_DIR / "policy_in_force.json")
    response = _api().dispatch(
        "POST",
        "/api/guard/near/agent-evaluate",
        {},
        {"transaction": _tx(), "policy_fixture": fixture},
    )
    assert response.status == 200
    policy = response.payload.get("policy")
    assert policy is None or policy.get("local_fixture") is not True


def test_a_client_policy_fixture_cannot_flip_a_block_to_allow(monkeypatch, tmp_path):
    """The bypass this guards: permissive fixture overrides a restrictive policy."""
    permissive = {
        "agent_id": "treasury-agent",
        "revision": 99,
        "status": "APPLIED",
        "provider_policy_synced": True,
        "frozen": False,
        "actions": ["withdraw"],
        "destinations": {"mode": "any", "list": []},
        "limits": {},
    }
    path = tmp_path / "permissive.json"
    path.write_text(json.dumps(permissive))
    # A destination the guard policy does NOT approve.
    response = _api().dispatch(
        "POST",
        "/api/guard/near/agent-evaluate",
        {},
        {"transaction": _tx(destination=ATTACKER), "policy_fixture": str(path)},
    )
    assert response.payload["outcome"] != "ALLOW"
    assert response.payload["permits_signing"] is False


def test_operator_policy_fixture_is_honoured(monkeypatch, tmp_path):
    """The operator's configured fixture still applies; only the client's is ignored."""
    from tracesettle import config

    fixture = FIXTURE_DIR / "policy_in_force.json"
    monkeypatch.setattr(config, "NEAR_POLICY_FIXTURE", str(fixture))
    response = _api().dispatch(
        "POST", "/api/guard/near/agent-evaluate", {}, {"transaction": _tx()}
    )
    assert response.status == 200
    assert response.payload["policy"]["local_fixture"] is True


def test_client_policy_selection_is_off_by_default(monkeypatch):
    from tracesettle import config

    assert config.NEAR_ALLOW_CLIENT_POLICY_SELECTION is False


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


# --- NEAR Intents lifecycle surface -----------------------------------------


def _lifecycle_api(tmp_path):
    from tracesettle.intents_store import IntentStore
    from tracesettle.near.lifecycle import NearIntentsLifecycle

    from conftest import FakeOpener, client_for

    opener = FakeOpener()
    store = IntentStore(tmp_path / "intents.db")
    lifecycle = NearIntentsLifecycle(
        guard_service=_service(), http_client=client_for(opener), store=store
    )
    return GuardAPI(_service(), lifecycle=lifecycle), lifecycle, opener


def test_lifecycle_routes_are_absent_when_not_enabled():
    """A deployment without the lifecycle must not expose the routes."""
    api = _api()
    for method, path, body in [
        ("GET", "/api/guard/near/lifecycle", None),
        ("GET", "/api/guard/near/lifecycle/tokens", None),
        ("POST", "/api/guard/near/lifecycle", {"transaction": {}}),
        ("POST", "/api/guard/near/lifecycle/list", {}),
    ]:
        response = api.dispatch(method, path, {}, body)
        assert response.status == 404
        assert "not enabled" in response.payload["error"]


def test_lifecycle_create_then_list_and_get(tmp_path):
    api, _, _ = _lifecycle_api(tmp_path)
    created = api.dispatch(
        "POST",
        "/api/guard/near/lifecycle",
        {},
        {"transaction": _tx(amount="1000", operation="WITHDRAWAL", chain="base", asset="USDC")},
    )
    assert created.status == 200
    intent_id = created.payload["intent_id"]
    assert created.payload["permits_signing"] is True

    listed = api.dispatch("POST", "/api/guard/near/lifecycle/list", {}, {})
    assert listed.status == 200
    assert any(i["intent_id"] == intent_id for i in listed.payload["intents"])

    fetched = api.dispatch("GET", f"/api/guard/near/lifecycle/{intent_id}", {}, None)
    assert fetched.status == 200
    assert fetched.payload["intent"]["intent_id"] == intent_id


def test_lifecycle_live_quote_refused_without_authorization(tmp_path):
    api, _, _ = _lifecycle_api(tmp_path)
    created = api.dispatch(
        "POST",
        "/api/guard/near/lifecycle",
        {},
        {"transaction": _tx(destination=ATTACKER, amount="1000000")},
    )
    assert created.status == 200
    assert created.payload["permits_signing"] is False
    intent_id = created.payload["intent_id"]
    live = api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/quote", {}, {"dry": False})
    assert live.status == 400
    assert "does not permit signing" in live.payload["error"]


def test_lifecycle_owner_isolation_over_the_api(tmp_path):
    api, _, _ = _lifecycle_api(tmp_path)
    created = api.dispatch(
        "POST",
        "/api/guard/near/lifecycle",
        {},
        {"owner": "alice", "transaction": _tx(amount="1000", operation="WITHDRAWAL")},
    )
    intent_id = created.payload["intent_id"]
    # A different owner cannot read it.
    other = api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/get", {}, {"owner": "bob"})
    assert other.status == 404
    mine = api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/get", {}, {"owner": "alice"})
    assert mine.status == 200


def test_lifecycle_identity_binding_rejects_a_mismatched_credential(tmp_path):
    api, _, _ = _lifecycle_api(tmp_path)
    response = api.dispatch(
        "POST",
        "/api/guard/near/lifecycle",
        {},
        {"transaction": _tx(service_id="treasury-agent")},
        authenticated_service_id="some-other-service",
    )
    assert response.status == 403


def test_lifecycle_top_level_idempotency_key_dedupes_a_resend(tmp_path):
    """A retried create with the same key resolves to one intent.

    The console derives this key from the transaction parameters, so a double
    submit or a resend cannot create a second transaction record.
    """
    api, _, _ = _lifecycle_api(tmp_path)
    body = {"transaction": _tx(amount="1000", operation="WITHDRAWAL"), "idempotency_key": "ui-abc123"}
    first = api.dispatch("POST", "/api/guard/near/lifecycle", {}, body)
    second = api.dispatch("POST", "/api/guard/near/lifecycle", {}, body)
    assert first.status == 200 and second.status == 200
    assert first.payload["intent_id"] == second.payload["intent_id"]
    assert first.payload["created"] is True
    assert second.payload["created"] is False
    listed = api.dispatch("POST", "/api/guard/near/lifecycle/list", {}, {})
    matching = [i for i in listed.payload["intents"] if i["intent_id"] == first.payload["intent_id"]]
    assert len(matching) == 1


def test_lifecycle_transaction_level_key_wins_over_the_top_level_key(tmp_path):
    api, _, _ = _lifecycle_api(tmp_path)
    tx = _tx(amount="1000", operation="WITHDRAWAL", idempotency_key="tx-level")
    created = api.dispatch(
        "POST", "/api/guard/near/lifecycle", {}, {"transaction": tx, "idempotency_key": "top-level"}
    )
    assert created.status == 200
    # A later call with only the top-level key must not collide with the tx-level key.
    other = api.dispatch(
        "POST",
        "/api/guard/near/lifecycle",
        {},
        {"transaction": _tx(amount="1000", operation="WITHDRAWAL"), "idempotency_key": "top-level"},
    )
    assert other.payload["intent_id"] != created.payload["intent_id"]


def test_lifecycle_verify_origin_action(tmp_path):
    """The verify-origin action independently checks the recorded deposit hash."""
    api, lifecycle, opener = _lifecycle_api(tmp_path)
    created = api.dispatch(
        "POST",
        "/api/guard/near/lifecycle",
        {},
        {"transaction": _tx(amount="1000000")},
    )
    assert created.status == 200
    intent_id = created.payload["intent_id"]
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": APPROVED}, "correlationId": "c"})
    api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/quote", {}, {"dry": False})
    api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/approve", {}, {"approve": True})
    opener.json("POST", "/v0/deposit/submit", {"status": "ok"})
    api.dispatch(
        "POST",
        f"/api/guard/near/lifecycle/{intent_id}/deposit",
        {},
        {"deposit_tx_hash": "0xuserdeposit"},
    )
    # The origin asset is USDC on base (an ERC-20), so the receipt must carry a
    # matching Transfer of that token to the deposit address.
    token = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    word = "0x" + APPROVED.lower().replace("0x", "").rjust(64, "0")
    opener.json("POST", "base-rpc", {
        "jsonrpc": "2.0", "id": 1, "result": {
            "transactionHash": "0xuserdeposit", "status": "0x1",
            "from": APPROVED, "to": token, "blockNumber": "0x1",
            "logs": [{"address": token, "topics": [topic, word, word],
                      "data": hex(1000000), "logIndex": "0x1"}],
        },
    })
    out = api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/verify-origin", {}, {})
    assert out.status == 200
    assert out.payload["origin_verification"]["level"] == "VERIFIED"


def test_lifecycle_verify_origin_without_a_hash_is_a_bad_request(tmp_path):
    api, _, _ = _lifecycle_api(tmp_path)
    created = api.dispatch(
        "POST", "/api/guard/near/lifecycle", {}, {"transaction": _tx(amount="1000000")}
    )
    intent_id = created.payload["intent_id"]
    out = api.dispatch("POST", f"/api/guard/near/lifecycle/{intent_id}/verify-origin", {}, {})
    assert out.status == 400
