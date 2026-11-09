"""The independent provider-policy layer on the *execution* boundary.

The NEAR Intents Agent API policy is a second policy the agent's operator holds,
distinct from this server's operator policy. These tests drive the real boundary,
the real guard and the real provider-policy gate; the only substitutions are the
RPC transport and the policy adapter (a network boundary), so every line of
``execution.py`` and ``provider_policy_gate.py`` runs.

They assert the whole point of the layer: it can only ever *tighten* the guard's
decision, and a policy that is not in force / unreadable / for another agent
discards the authorization so nothing can reach a signer.
"""

from __future__ import annotations

import pytest

from near_helpers import RECIPIENT, make_boundary, public_key_for_test
from tracesettle.guard.model import Decision
from tracesettle.near.policy import PolicyAdapter
from tracesettle.near.execution import ExecutionError


PUBLIC_KEY = public_key_for_test()

#: A native NEAR transfer the operator policy allows, so the guard's own verdict
#: is ALLOW and the provider-policy layer is the only thing under test.
_APPROVED_DEST = RECIPIENT


def _policy_body(**overrides):
    body = {
        "agent_id": "treasury-agent",
        "revision": 3,
        "status": "APPLIED",
        "provider_policy_synced": True,
        "frozen": False,
        "native": {"near": {"sign_message": False, "transfer": True, "call": False}},
    }
    body.update(overrides)
    return body


class _FakePolicyAdapter:
    """A policy adapter whose read is fixed, so the gate is driven deterministically."""

    def __init__(self, body):
        self._read = PolicyAdapter.from_fixture(body)
        self.base_url = "https://provider.invalid"

    def read_policy(self, agent_id):  # noqa: ARG002 - fixed read
        return self._read


def _boundary_with_provider_policy(body, *, require=False):
    boundary, rpc = make_boundary()
    boundary._policy_adapter = _FakePolicyAdapter(body)
    boundary._provider_policy_agent_id = "treasury-agent"
    boundary._require_provider_policy = require
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    boundary._policy_gate = ProviderPolicyGate(
        boundary._policy_adapter, agent_id="treasury-agent", require=require, native_chain="near"
    )
    return boundary, rpc


def _prepare(boundary, **overrides):
    kwargs = dict(
        service_id="treasury-agent",
        account_id="agent.testnet",
        public_key=PUBLIC_KEY,
        receiver_id=_APPROVED_DEST,
        asset_identifier="near:native",
        amount_human="1",
    )
    kwargs.update(overrides)
    return boundary.prepare(**kwargs)


# -- the layer tightens -------------------------------------------------------


def test_provider_policy_in_force_still_authorizes():
    """A policy that is applied, synced, and enables native.near.transfer allows."""
    boundary, _ = _boundary_with_provider_policy(_policy_body())
    prepared = _prepare(boundary)
    assert prepared.decision.decision is Decision.ALLOW
    assert prepared.authorized
    assert prepared.provider_policy is not None
    assert prepared.provider_policy.outcome.value == "IN_FORCE"


def test_a_policy_not_in_force_blocks_even_though_the_guard_allows():
    """The guard ALLOWs; the provider policy is only REQUESTED, so the result is not ALLOW."""
    # Confirm the operator policy alone would allow, so the test is not vacuous.
    plain, _ = make_boundary()
    assert _prepare(plain).decision.decision is Decision.ALLOW

    boundary, _ = _boundary_with_provider_policy(_policy_body(status="REQUESTED"))
    prepared = _prepare(boundary)
    assert prepared.decision.decision is not Decision.ALLOW
    assert not prepared.authorized
    assert prepared.authorization is None


def test_a_frozen_policy_blocks():
    boundary, _ = _boundary_with_provider_policy(_policy_body(frozen=True))
    prepared = _prepare(boundary)
    assert not prepared.authorized


def test_a_policy_that_disables_native_transfer_blocks():
    body = _policy_body()
    body["native"] = {"near": {"sign_message": False, "transfer": False, "call": False}}
    boundary, _ = _boundary_with_provider_policy(body)
    prepared = _prepare(boundary)
    assert not prepared.authorized


def test_an_unreadable_policy_blocks_when_required():
    boundary, _ = _boundary_with_provider_policy(_policy_body(), require=True)
    # Break the adapter so the read cannot be established.
    boundary._policy_adapter = _FakePolicyAdapter({"detail": "provider down"})
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    boundary._policy_gate = ProviderPolicyGate(
        boundary._policy_adapter, agent_id="treasury-agent", require=True, native_chain="near"
    )
    prepared = _prepare(boundary)
    assert not prepared.authorized


# -- required-but-unconstructed refuses ---------------------------------------


def test_a_required_layer_with_no_adapter_refuses_authorization():
    """A required provider policy with no adapter is a refusal, never a silent pass."""
    boundary, _ = make_boundary()
    boundary._require_provider_policy = True
    boundary._policy_gate = None
    with pytest.raises(ExecutionError):
        _prepare(boundary)


def test_an_optional_layer_with_no_adapter_is_reported_not_applied():
    boundary, _ = make_boundary()
    info = boundary.provider_policy_info()
    assert info["applied"] is False
    assert info["required"] is False


def test_a_required_layer_with_no_adapter_is_reported_not_applied():
    boundary, _ = make_boundary()
    boundary._require_provider_policy = True
    info = boundary.provider_policy_info()
    assert info["applied"] is False
    assert info["required"] is True
    assert "refused" in info["note"].lower()


def test_a_configured_gate_is_reported_as_applied():
    boundary, _ = _boundary_with_provider_policy(_policy_body())
    info = boundary.provider_policy_info()
    assert info["applied"] is True
    assert info["agent_id"] == "treasury-agent"


# -- the wallet path uses the same layer --------------------------------------


def test_wallet_prepare_applies_the_provider_policy_layer():
    """A wallet operation is judged by the same second policy, and it can only tighten."""
    body = _policy_body()
    body["native"] = {"near": {"sign_message": False, "transfer": False, "call": False}}
    boundary, _ = _boundary_with_provider_policy(body)
    prepared = boundary.prepare_wallet_operation(
        service_id="treasury-agent",
        account_id="agent.testnet",
        receiver_id=_APPROVED_DEST,
        asset_identifier="near:native",
        amount_human="1",
    )
    assert not prepared.authorized
    assert prepared.provider_policy is not None


def test_wallet_prepare_still_authorizes_when_the_policy_is_in_force():
    boundary, _ = _boundary_with_provider_policy(_policy_body())
    prepared = boundary.prepare_wallet_operation(
        service_id="treasury-agent",
        account_id="agent.testnet",
        receiver_id=_APPROVED_DEST,
        asset_identifier="near:native",
        amount_human="1",
    )
    assert prepared.authorized


# -- provenance is carried on the prepared operation --------------------------


def test_prepared_operation_reports_provider_policy_provenance():
    boundary, _ = _boundary_with_provider_policy(_policy_body())
    prepared = _prepare(boundary)
    payload = prepared.to_dict()
    assert payload["provider_policy"] is not None
    assert payload["provider_policy"]["agent_id"] == "treasury-agent"


# -- real parser -> real gate -> real boundary (no substituted parser) --------


class _FakeHttpClient:
    """A transport stand-in that returns one canned provider response.

    Only the network boundary is substituted; the real ``PolicyAdapter`` (its
    URL building, header handling, status classification) and the real
    ``parse_policy`` run.
    """

    def __init__(self, result):
        self._result = result
        self.calls: list[str] = []

    def get_json(self, url, params=None, headers=None):
        self.calls.append(url)
        return self._result


class _FakeResult:
    def __init__(self, *, ok, data=None, http_status=None, status=None):
        self.ok = ok
        self.data = data
        self.http_status = http_status
        self.status = status


def _policy_view_envelope(**overrides):
    """The documented PolicyView shape: lifecycle at the top level, rules nested."""
    body = {
        "wallet_id": "treasury-agent.near",
        "revision": 4,
        "status": "APPLIED",
        "provider_policy_synced": True,
        "applied_at": "2026-11-08T00:00:00Z",
        "policy_hash": "c" * 64,
        "policy": {
            "agent_id": "treasury-agent",
            "actions": ["transfer"],
            "asset_ids": ["near:native"],
            "max_actions_per_hour": 5,
            "native": {"near": {"transfer": True, "call": [], "sign_message": []}},
        },
    }
    body.update(overrides)
    return body


def _boundary_with_real_adapter(envelope, *, require=True):
    boundary, rpc = make_boundary()
    adapter = PolicyAdapter(
        base_url="https://provider.invalid",
        api_key="secret",
        http_client=_FakeHttpClient(_FakeResult(ok=True, data=envelope, http_status=200)),
    )
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    boundary._policy_adapter = adapter
    boundary._provider_policy_agent_id = "treasury-agent"
    boundary._require_provider_policy = require
    boundary._policy_gate = ProviderPolicyGate(
        adapter, agent_id="treasury-agent", require=require, native_chain="near"
    )
    return boundary, rpc


def test_the_real_parser_connects_a_documented_policy_view_to_enforcement():
    """The corrected PolicyView parser feeds the real gate: an in-force policy allows."""
    boundary, _ = _boundary_with_real_adapter(_policy_view_envelope())
    prepared = _prepare(boundary)
    assert prepared.decision.decision is Decision.ALLOW
    assert prepared.authorized
    assert prepared.provider_policy is not None
    assert prepared.provider_policy.outcome.value == "IN_FORCE"


def test_a_documented_policy_view_that_is_not_synced_is_refused_by_the_gate():
    """The envelope's top-level ``provider_policy_synced`` must be honoured."""
    envelope = _policy_view_envelope(provider_policy_synced=False)
    boundary, _ = _boundary_with_real_adapter(envelope)
    prepared = _prepare(boundary)
    assert not prepared.authorized
    assert prepared.decision.decision is not Decision.ALLOW


def test_a_documented_policy_view_with_native_transfer_off_is_blocked():
    envelope = _policy_view_envelope()
    envelope["policy"]["native"] = {"near": {"transfer": False, "call": [], "sign_message": []}}
    boundary, _ = _boundary_with_real_adapter(envelope)
    prepared = _prepare(boundary)
    assert not prepared.authorized


def test_the_retrieved_policy_changes_the_decision_for_the_same_transaction():
    """The strongest requirement: identical transaction, opposite outcomes.

    The same approved transaction is prepared twice; the *only* difference is the
    policy the provider returned. An in-force policy that enables the transfer
    authorizes; the same policy with the transfer disabled does not. So the
    retrieved provider policy demonstrably changes the authorization decision.
    """
    enabled = _boundary_with_real_adapter(_policy_view_envelope())[0]
    disabled_env = _policy_view_envelope()
    disabled_env["policy"]["native"] = {"near": {"transfer": False, "call": [], "sign_message": []}}
    disabled = _boundary_with_real_adapter(disabled_env)[0]

    allowed = _prepare(enabled)
    refused = _prepare(disabled)

    assert allowed.decision.decision is Decision.ALLOW
    assert allowed.authorized
    assert refused.decision.decision is not Decision.ALLOW
    assert not refused.authorized
    # The prepared request is byte-for-byte the same; only the policy differed.
    assert allowed.transaction.tx_hash_bytes == refused.transaction.tx_hash_bytes


def test_a_provider_outage_fails_closed_on_the_execution_path():
    """A transport failure is HOLD (cannot establish), never an authorization."""
    boundary, _ = make_boundary()
    adapter = PolicyAdapter(
        base_url="https://provider.invalid",
        api_key="secret",
        http_client=_FakeHttpClient(_FakeResult(ok=False, data=None, http_status=503)),
    )
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    boundary._policy_adapter = adapter
    boundary._provider_policy_agent_id = "treasury-agent"
    boundary._require_provider_policy = True
    boundary._policy_gate = ProviderPolicyGate(
        adapter, agent_id="treasury-agent", require=True, native_chain="near"
    )
    prepared = _prepare(boundary)
    assert not prepared.authorized
    assert prepared.decision.decision is not Decision.ALLOW


def test_a_malformed_provider_body_fails_closed_on_the_execution_path():
    boundary, _ = _boundary_with_real_adapter({"not": "a policy view"})
    prepared = _prepare(boundary)
    assert not prepared.authorized
    assert prepared.decision.decision is not Decision.ALLOW
