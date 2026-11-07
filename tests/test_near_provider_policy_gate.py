"""The independent NEAR provider-policy gate, and its wiring into custody.

Every test drives the **real** gate, the **real** guard service, and the
**real** :class:`~tracesettle.near.outlayer_execution.OutLayerCustodyBoundary`.
The only substitution is the provider transport (a ``FakeOpener``-backed
``HttpClient``) and the NEAR RPC; "the provider was never reached" is therefore
asserted against a provider that records its calls.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from conftest import FakeOpener
from near_helpers import TEST_SEED, FakeNearRpc, near_policy
from tracesettle.guard.audit import AuditLog
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.model import Decision
from tracesettle.guard.monitor import SecurityMonitor
from tracesettle.guard.service import GuardService
from tracesettle.httpclient import HttpClient
from tracesettle.near.networks import network_config
from tracesettle.near.outlayer import OutLayerConfig, OutLayerCustodyProvider
from tracesettle.near.outlayer_execution import (
    CUSTODY_ASSET,
    CUSTODY_OPERATION,
    CustodyError,
    OutLayerCustodyBoundary,
)
from tracesettle.guard.model import TransactionRequest
from tracesettle.near.policy import PolicyAdapter
from tracesettle.near.provider_policy_gate import (
    ProviderPolicyGate,
    ProviderPolicyOutcome,
    combine_provider_policy,
)

WALLET = "9575a853fa0f62ed12334306cd5d1a18f6821ef9036601c99822f17d9bb13c38"
WALLET_PUB = "ed25519:B4RodGLvA3a8wyPQydgJwAUtm6ULkfdia17WP9hPYBGs"
DEST = "tsfund52f8405ad4.testnet"
TX_HASH = "76mYB4gsgj3ogYCgsqzd5P4ESsLRw2rTecasQZ6kcnmh"
API_KEY = "wk_test_key_not_a_real_secret_000000000000000000000000000000"
AGENT = "treasury-agent"


def _provider(opener: FakeOpener) -> OutLayerCustodyProvider:
    client = HttpClient(
        opener=opener, max_attempts=1, timeout=1.0, backoff_base=0.0, sleeper=lambda _: None
    )
    config = OutLayerConfig(api_key=API_KEY, network="testnet", timeout=1.0)
    return OutLayerCustodyProvider(config, client=client)


def _guard(*, approved=DEST, max_amount="10") -> GuardService:
    return GuardService(
        policy=near_policy(approved=frozenset({approved}), max_amount=max_amount),
        authority=AuthorizationAuthority(
            key=TEST_SEED, key_id="t", ephemeral=False, replay_store=InMemoryReplayStore(), ttl_seconds=90
        ),
        monitor=SecurityMonitor(),
        audit=AuditLog(),
    )


def _policy_adapter(body: dict, *, expected_agent_id: str = AGENT) -> PolicyAdapter:
    class _Client:
        def get_json(self, url, params=None, headers=None):  # noqa: ANN001
            class _R:
                ok = True
                http_status = 200
                status = "SourceStatus.OK"

            _R.data = body
            return _R()

    return PolicyAdapter(
        base_url="https://provider.invalid",
        api_key="k",
        http_client=_Client(),
        expected_host="provider.invalid",
        expected_agent_id=expected_agent_id,
    )


def _policy_body(**overrides):
    body = {
        "agent_id": AGENT,
        "revision": 5,
        "status": "APPLIED",
        "provider_policy_synced": True,
        "frozen": False,
        "native": {"near": {"transfer": True, "call": False, "sign_message": False}},
    }
    body.update(overrides)
    return body


def _boundary(
    opener: FakeOpener | None = None,
    *,
    guard: GuardService | None = None,
    policy_adapter: PolicyAdapter | None = None,
    require: bool = True,
):
    opener = opener or FakeOpener()
    opener.json(
        "GET",
        "/wallet/v1/address",
        {"wallet_id": "w", "address": WALLET, "public_key": WALLET_PUB},
    )
    opener.json(
        "POST",
        "/wallet/v1/transfer",
        {"status": "success", "request_id": "r1", "tx_hash": TX_HASH},
    )
    provider = _provider(opener)
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {
            "hash": TX_HASH,
            "signer_id": WALLET,
            "receiver_id": DEST,
            "public_key": WALLET_PUB,
            "actions": [{"Transfer": {"deposit": "500000000000000000000000"}}],
        },
    }
    return (
        OutLayerCustodyBoundary(
            guard or _guard(),
            provider,
            network=nc.network,
            rpc=rpc,
            sleep=lambda _: None,
            policy_adapter=policy_adapter,
            provider_policy_agent_id=AGENT if policy_adapter is not None else "",
            require_provider_policy=require,
        ),
        provider,
        opener,
    )


# --- the gate in isolation -------------------------------------------------


def test_in_force_policy_that_enables_transfer_permits():
    gate = ProviderPolicyGate(_policy_adapter(_policy_body()), agent_id=AGENT)
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.IN_FORCE
    assert result.decision is Decision.ALLOW
    assert result.permitted is True
    assert result.revision == 5


def test_not_applied_policy_holds():
    gate = ProviderPolicyGate(_policy_adapter(_policy_body(status="REQUESTED")), agent_id=AGENT)
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.NOT_IN_FORCE
    assert result.decision is Decision.HOLD
    assert result.permitted is False


def test_frozen_wallet_blocks():
    gate = ProviderPolicyGate(_policy_adapter(_policy_body(frozen=True)), agent_id=AGENT)
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.FROZEN
    assert result.decision is Decision.BLOCK


def test_native_transfer_disabled_blocks():
    body = _policy_body(native={"near": {"transfer": False, "call": True}})
    gate = ProviderPolicyGate(_policy_adapter(body), agent_id=AGENT)
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.NATIVE_TRANSFER_DISABLED
    assert result.decision is Decision.BLOCK


def test_unconfigured_provider_holds_when_required():
    gate = ProviderPolicyGate(
        PolicyAdapter(base_url=None, api_key=None), agent_id=AGENT, require=True
    )
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.UNCONFIGURED
    assert result.decision is Decision.HOLD


def test_unconfigured_provider_does_not_block_when_not_required():
    """The layer is honest about being off; it must not silently pass as in force."""
    gate = ProviderPolicyGate(
        PolicyAdapter(base_url=None, api_key=None), agent_id=AGENT, require=False
    )
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.UNCONFIGURED
    assert result.decision is Decision.ALLOW
    assert "not required" in result.detail


def test_agent_mismatch_blocks():
    """The gate re-checks the agent against the parsed body, not just the request."""
    from tracesettle.near.policy import PolicyAvailability, parse_policy

    policy = parse_policy(_policy_body(agent_id="someone-else"))
    gate = ProviderPolicyGate(_policy_adapter(_policy_body()), agent_id=AGENT)

    read = type(
        "_Read",
        (),
        {
            "ok": True,
            "availability": PolicyAvailability.AVAILABLE,
            "policy": policy,
            "detail": "x",
            "endpoint": "e",
            "local_fixture": False,
        },
    )()
    gate.adapter = type("A", (), {"read_policy": staticmethod(lambda _a: read)})()
    result = gate.evaluate()
    assert result.outcome is ProviderPolicyOutcome.AGENT_MISMATCH
    assert result.decision is Decision.BLOCK


# --- combine: never loosens -------------------------------------------------


def _allowed_decision():
    guard = _guard()
    decision = guard.evaluate(
        TransactionRequest(
            request_id="r",
            service_id=AGENT,
            operation=CUSTODY_OPERATION,
            chain="near-testnet",
            asset=CUSTODY_ASSET,
            amount=Decimal("0.5"),
            amount_raw="0.5",
            destination=DEST,
        )
    )
    assert decision.decision is Decision.ALLOW
    assert decision.authorization is not None
    return decision


def test_combine_never_loosens_and_drops_authorization():
    decision = _allowed_decision()
    gate = ProviderPolicyGate(_policy_adapter(_policy_body(status="REQUESTED")), agent_id=AGENT)
    combined = combine_provider_policy(decision, gate.evaluate())
    assert combined.decision is Decision.HOLD
    assert combined.authorization is None
    assert any(f.code.startswith("PROVIDER_POLICY_") for f in combined.findings)


def test_combine_in_force_leaves_an_allow_untouched():
    decision = _allowed_decision()
    gate = ProviderPolicyGate(_policy_adapter(_policy_body()), agent_id=AGENT)
    combined = combine_provider_policy(decision, gate.evaluate())
    assert combined.decision is Decision.ALLOW
    assert combined.authorization is not None


# --- end-to-end through the custody boundary -------------------------------


def _transferred(opener: FakeOpener) -> bool:
    return any("/wallet/v1/transfer" in call for call in opener.calls)


def test_custody_not_applied_policy_blocks_before_the_provider():
    boundary, _, opener = _boundary(
        policy_adapter=_policy_adapter(_policy_body(status="REQUESTED"))
    )
    prepared = boundary.prepare(
        service_id=AGENT, destination=DEST, amount_human=Decimal("0.5")
    )
    assert prepared.authorized is False
    assert prepared.provider_policy is not None
    assert prepared.provider_policy.decision is Decision.HOLD
    with pytest.raises(CustodyError):
        boundary.execute(prepared)
    assert not _transferred(opener)  # the provider was never reached


def test_custody_in_force_policy_still_executes_and_verifies():
    boundary, _, opener = _boundary(policy_adapter=_policy_adapter(_policy_body()))
    prepared = boundary.prepare(
        service_id=AGENT, destination=DEST, amount_human=Decimal("0.5")
    )
    assert prepared.authorized is True
    assert prepared.provider_policy.outcome is ProviderPolicyOutcome.IN_FORCE
    execution = boundary.execute(prepared)
    assert execution.settlement_verified is True
    assert _transferred(opener)


def test_custody_without_a_policy_adapter_is_unaffected():
    """With the layer explicitly not required, the operator policy alone decides."""
    boundary, _, opener = _boundary(require=False)
    prepared = boundary.prepare(
        service_id=AGENT, destination=DEST, amount_human=Decimal("0.5")
    )
    assert prepared.authorized is True
    assert prepared.provider_policy is None
    info = boundary.info()
    assert info["provider_policy_layer"]["applied"] is False
    assert info["provider_policy_layer"]["required"] is False
    boundary.execute(prepared)
    assert _transferred(opener)


def test_a_required_provider_policy_with_no_adapter_refuses():
    """A required layer that was never constructed must refuse, not fail open."""
    boundary, _, opener = _boundary(require=True)
    assert boundary.info()["provider_policy_layer"]["required"] is True
    with pytest.raises(CustodyError):
        boundary.prepare(service_id=AGENT, destination=DEST, amount_human=Decimal("0.5"))
    assert not _transferred(opener)


def test_custody_info_reports_the_policy_layer_as_applied():
    boundary, _, _ = _boundary(policy_adapter=_policy_adapter(_policy_body()))
    info = boundary.info()
    assert info["provider_policy_layer"]["applied"] is True
    assert info["provider_policy_layer"]["required"] is True


def test_custody_prepared_payload_carries_provider_policy_provenance():
    boundary, _, _ = _boundary(policy_adapter=_policy_adapter(_policy_body()))
    prepared = boundary.prepare(
        service_id=AGENT, destination=DEST, amount_human=Decimal("0.5")
    )
    payload = prepared.to_dict()
    assert payload["provider_policy"]["outcome"] == "IN_FORCE"
    assert payload["provider_policy"]["source"] == "live"
    assert payload["provider_policy"]["revision"] == 5
