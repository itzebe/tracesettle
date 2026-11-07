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
