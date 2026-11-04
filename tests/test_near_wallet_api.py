"""The NEAR wallet-mediated HTTP routes.

Driven through the real ``GuardAPI`` and the real execution boundary. The RPC
transport is the only substitution. These routes are off by default; when enabled
the *wallet* signs and sends, so the server only authorizes an intent and then
independently verifies the on-chain record. No key is ever held or transmitted.
"""

from __future__ import annotations

import pytest

from near_helpers import (
    RECIPIENT,
    SIGNER,
    FakeNearRpc,
    make_guard,
    near_policy,
)
from tracesettle.guard.api import GuardAPI
from tracesettle.model import SourceStatus
from tracesettle.near.execution import NearExecutionBoundary
from tracesettle.near.networks import NETWORKS, NearNetwork
from tracesettle.near.verify import SettlementState

TX_HASH = "H8hQ1Z8bqk9a3V6m2bN4v5x7y8zA1bC2dE3fG4hJ5kL6"
YOCTO_PER_NEAR = 10**24


def _api(*, policy=None):
    guard = make_guard(policy or near_policy())
    rpc = FakeNearRpc(NETWORKS[NearNetwork.TESTNET])
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    return GuardAPI(guard, near_execution=boundary), rpc, guard


def _prepare_body(**overrides):
    body = {
        "service_id": "treasury-agent",
        "account_id": SIGNER,
        "receiver_id": RECIPIENT,
        "asset": "near:native",
        "amount": "1",
    }
    body.update(overrides)
    return body


def _post(api, path, body):
    return api.dispatch("POST", path, {}, body)


def _record(*, deposit: str, receiver: str = RECIPIENT, signer: str = SIGNER, finality: str = "FINAL", status_kind: str = "success"):
    status = {"SuccessValue": ""} if status_kind == "success" else {"Failure": {"error_message": "x"}}
    return {
        "final_execution_status": finality,
        "status": status,
        "transaction": {
            "hash": TX_HASH,
            "signer_id": signer,
            "receiver_id": receiver,
            "nonce": 7,
            "actions": [{"Transfer": {"deposit": deposit}}],
        },
        "transaction_outcome": {"block_hash": "x", "outcome": {"logs": []}},
        "receipts_outcome": [],
    }


def test_wallet_flow_is_disabled_by_default():
    guard = make_guard()
    api = GuardAPI(guard)
    info = api.dispatch("GET", "/api/guard/near/wallet", {}, None)
    assert info.status == 200 and info.payload["enabled"] is False
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    assert prepared.status == 404


def test_wallet_info_reports_no_key_and_the_network():
    api, _, _ = _api()
    info = api.dispatch("GET", "/api/guard/near/wallet", {}, None)
    assert info.payload["enabled"] is True
    assert info.payload["mode"] == "wallet"
    assert info.payload["signs"] is False
    assert info.payload["broadcasts"] is False
    assert info.payload["network"] == "testnet"


def test_prepare_returns_a_wallet_request_and_no_key_material():
    api, _, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    assert prepared.status == 200
    assert prepared.payload["authorized"] is True
    assert prepared.payload["prepare_id"].startswith("wprep_")
    request = prepared.payload["wallet_request"]
    assert request["signerId"] == SIGNER
    assert request["receiverId"] == RECIPIENT
    assert request["actions"][0]["type"] == "Transfer"
    assert request["actions"][0]["params"]["deposit"] == str(YOCTO_PER_NEAR)
    assert "private" not in str(prepared.payload).lower()
    assert "seed" not in str(prepared.payload).lower()


def test_prepare_requires_all_fields():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/wallet/prepare", {"service_id": "treasury-agent"})
    assert resp.status == 400


def test_prepare_does_not_authorize_a_blocked_destination():
    api, _, _ = _api(policy=near_policy(approved=frozenset({"other.testnet"})))
    resp = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    assert resp.status == 200
    assert resp.payload["authorized"] is False
    assert "prepare_id" not in resp.payload


def test_prepare_refuses_a_wrong_network():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/wallet/prepare", _prepare_body(network="mainnet"))
    assert resp.status == 422


def test_verify_reaches_verified_on_a_matching_record():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR))
    verified = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert verified.status == 200
    assert verified.payload["verification"]["state"] == SettlementState.VERIFIED.value
    assert verified.payload["verification"]["all_checks_passed"] is True


def test_verify_consumes_the_authorization_so_a_replay_is_refused():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR))
    first = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert first.status == 200
    second = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert second.status == 404


def test_a_wrong_amount_is_disputed_not_verified():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit="999")
    verified = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert verified.payload["verification"]["state"] == SettlementState.DISPUTED.value


def test_a_wrong_receiver_is_disputed():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR), receiver="attacker.testnet")
    verified = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert verified.payload["verification"]["state"] == SettlementState.DISPUTED.value


def test_a_non_final_record_is_pending_not_verified():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR), finality="EXECUTED_OPTIMISTIC")
    verified = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert verified.payload["verification"]["state"] == SettlementState.PENDING.value


def test_an_unavailable_source_is_insufficient_evidence_not_success():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_status = SourceStatus.TIMEOUT
    verified = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    assert verified.payload["verification"]["state"] == SettlementState.INSUFFICIENT_EVIDENCE.value


def test_verify_rejects_an_unknown_prepare_id():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/wallet/verify", {"prepare_id": "wprep_nope", "tx_hash": TX_HASH})
    assert resp.status == 404


def test_verify_requires_both_fields():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/wallet/verify", {"prepare_id": "wprep_x"})
    assert resp.status == 400


def test_a_prepared_operation_is_owner_scoped():
    """One service's prepared operation is invisible to another."""
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR))
    store = api.near_wallet_store()
    # Another owner cannot take it.
    assert store.take(prepared.payload["prepare_id"], "other-service") is None


def test_wallet_info_advertises_the_supported_assets():
    """The console needs the real, network-scoped asset list, not a hardcoded one."""
    api, _, _ = _api()
    info = api.dispatch("GET", "/api/guard/near/wallet", {}, None)
    assets = {a["identifier"] for a in info.payload["supported_assets"]}
    assert "near:native" in assets
    # A testnet asset identifier must never be offered on mainnet, and vice versa.
    assert all(a["decimals"] >= 0 for a in info.payload["supported_assets"])
    ops = {o["operation"] for o in info.payload["supported_operations"]}
    assert {"NATIVE_TRANSFER", "NEP141_TRANSFER"} <= ops


def test_wallet_info_assets_are_scoped_to_the_configured_network():
    api, _, _ = _api()
    info = api.dispatch("GET", "/api/guard/near/wallet", {}, None)
    assert info.payload["network"] == "testnet"
    ids = {a["identifier"] for a in info.payload["supported_assets"]}
    assert "near:wrap.testnet" in ids
    assert "near:wrap.near" not in ids


def test_an_unrecognised_operation_is_never_verified():
    """A fail-closed check: an operation the verifier does not recognise must
    resolve to DISPUTED, never VERIFIED. Otherwise a record for an operation
    whose amount could not be checked (e.g. a Delegate/AddKey/full-access
    action) would be reported as an independent success."""
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    prepare_id = prepared.payload["prepare_id"]
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR), status_kind="success")
    # Sabotage the operation label so no semantic branch matches.
    stored = api.near_wallet_store().peek(prepare_id, "local")
    stored.operation = "ADD_KEY"
    result = _post(api, "/api/guard/near/wallet/verify",
                   {"prepare_id": prepare_id, "tx_hash": TX_HASH})
    assert result.payload["verification"]["state"] == SettlementState.DISPUTED.value
    names = {c["name"]: c["ok"] for c in result.payload["verification"]["checks"]}
    assert names["operation_recognised"] is False


def test_a_final_successful_record_for_an_unknown_operation_is_disputed():
    """The same guard at the pure-verifier level, so it cannot be weakened by an
    HTTP-layer change."""
    from tracesettle.near.verify import IntendedOperation, verify_intent

    intended = IntendedOperation(
        network=NETWORKS[NearNetwork.TESTNET],
        signer_id=SIGNER,
        operation="ADD_KEY",
        receiver_id=RECIPIENT,
        amount_base=YOCTO_PER_NEAR,
        destination=RECIPIENT,
        contract=None,
    )
    record = _record(deposit=str(YOCTO_PER_NEAR), status_kind="success")
    verification = verify_intent(
        intended=intended, result=record, source_status=SourceStatus.OK
    )
    assert verification.state is SettlementState.DISPUTED


def test_wallet_verification_is_recorded_on_the_audit_chain():
    """The independent settlement outcome must persist as audit evidence, not
    only be returned in the response, and it must carry the on-chain facts."""
    api, rpc, guard = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR))
    _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    records = [r for r in guard.audit_records(limit=50)
               if r.event_type == "SETTLEMENT_VERIFICATION"]
    assert records, "the settlement verification was not recorded"
    rec = records[-1]
    assert rec.outcome == SettlementState.VERIFIED.value
    assert rec.extra["tx_hash"] == TX_HASH
    assert rec.extra["destination"] == RECIPIENT
    # The record is on the hash-chained log and the chain still verifies.
    assert guard.audit_verification().ok is True


def test_a_disputed_wallet_verification_is_recorded_with_its_failing_check():
    api, rpc, guard = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_result = _record(deposit=str(YOCTO_PER_NEAR + 1))  # wrong amount
    _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    rec = [r for r in guard.audit_records(limit=50)
           if r.event_type == "SETTLEMENT_VERIFICATION"][-1]
    assert rec.outcome == SettlementState.DISPUTED.value
    assert any(c["name"] == "transfer_amount_matches" and not c["ok"] for c in rec.extra["checks"])


@pytest.mark.parametrize("degraded", [
    SourceStatus.TIMEOUT,
    SourceStatus.RATE_LIMITED,
    SourceStatus.SERVER_ERROR,
    SourceStatus.NETWORK_ERROR,
    SourceStatus.UNAUTHORIZED,
    SourceStatus.MALFORMED,
])
def test_every_degraded_rpc_status_is_insufficient_evidence(degraded):
    """No upstream degradation may ever resolve to VERIFIED: a source that could
    not answer leaves the settlement unverified, never successful."""
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/wallet/prepare", _prepare_body())
    rpc.tx_status_status = degraded
    rpc.tx_status_result = None
    result = _post(api, "/api/guard/near/wallet/verify", {
        "prepare_id": prepared.payload["prepare_id"], "tx_hash": TX_HASH,
    })
    state = result.payload["verification"]["state"]
    assert state == SettlementState.INSUFFICIENT_EVIDENCE.value
    assert state != SettlementState.VERIFIED.value
