"""The NEAR wallet-mediated HTTP routes.

Driven through the real ``GuardAPI`` and the real execution boundary. The RPC
transport is the only substitution. These routes are off by default; when enabled
the *wallet* signs and sends, so the server only authorizes an intent and then
independently verifies the on-chain record. No key is ever held or transmitted.
"""

from __future__ import annotations

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
