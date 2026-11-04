"""The NEAR execution HTTP routes.

Driven through the real ``GuardAPI`` and the real execution boundary. The RPC
transport is the only substitution. The routes are off by default and, when
enabled, never sign: ``/prepare`` builds and authorizes, ``/submit`` accepts a
wallet signature and broadcasts.
"""

from __future__ import annotations

import base64

from near_helpers import (
    RECIPIENT,
    SIGNER,
    TEST_SEED,
    FakeNearRpc,
    make_guard,
    near_policy,
    public_key_for_test,
)
from tracesettle.guard.api import GuardAPI
from tracesettle.near import ed25519
from tracesettle.near.execution import NearExecutionBoundary
from tracesettle.near.networks import NETWORKS, NearNetwork
from tracesettle.near.verify import SettlementState

PUBLIC_KEY = public_key_for_test()


def _api(*, policy=None):
    guard = make_guard(policy or near_policy())
    rpc = FakeNearRpc(NETWORKS[NearNetwork.TESTNET])
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    return GuardAPI(guard, near_execution=boundary), rpc, guard


def _prepare_body(**overrides):
    body = {
        "service_id": "treasury-agent",
        "account_id": SIGNER,
        "public_key": PUBLIC_KEY,
        "receiver_id": RECIPIENT,
        "asset": "near:native",
        "amount": "1",
    }
    body.update(overrides)
    return body


def _post(api, path, body):
    return api.dispatch("POST", path, {}, body)


def test_execution_is_disabled_by_default():
    guard = make_guard()
    api = GuardAPI(guard)  # no near_execution
    info = api.dispatch("GET", "/api/guard/near/execution", {}, None)
    assert info.status == 200 and info.payload["enabled"] is False
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    assert prepared.status == 404


def test_info_reports_the_boundary_holds_no_key():
    api, _, _ = _api()
    info = api.dispatch("GET", "/api/guard/near/execution", {}, None)
    assert info.payload["enabled"] is True
    assert info.payload["signs"] is False
    assert info.payload["network"]["network"] == "testnet"


def test_prepare_then_submit_reaches_verified():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    assert prepared.status == 200
    assert prepared.payload["authorized"] is True
    assert prepared.payload["prepare_id"].startswith("prep_")
    # The response carries the exact bytes-bound transaction, never a key.
    assert "public_key" in prepared.payload["transaction"]
    assert "private" not in str(prepared.payload).lower()

    tx_hash = prepared.payload["transaction"]["tx_hash"]
    # Sign exactly the transaction hash (what a wallet signs).
    from tracesettle.base58 import b58decode

    signature = base64.b64encode(ed25519.sign(b58decode(tx_hash), TEST_SEED)).decode()
    rpc.send_result = {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {
            "hash": tx_hash,
            "signer_id": SIGNER,
            "receiver_id": RECIPIENT,
            "nonce": prepared.payload["transaction"]["nonce"],
            "actions": [{"Transfer": {"deposit": str(10**24)}}],
        },
        "transaction_outcome": {"block_hash": prepared.payload["transaction"]["block_hash"], "outcome": {"logs": []}},
        "receipts_outcome": [],
    }
    submitted = _post(api, "/api/guard/near/execution/submit", {"prepare_id": prepared.payload["prepare_id"], "signature": signature})
    assert submitted.status == 200
    assert submitted.payload["state"] == SettlementState.VERIFIED.value


def test_prepare_requires_all_fields():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/execution/prepare", {"service_id": "treasury-agent"})
    assert resp.status == 400


def test_prepare_refuses_an_unsupported_asset():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/execution/prepare", _prepare_body(asset="USDC"))
    assert resp.status == 422


def test_prepare_refuses_a_wrong_network():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/execution/prepare", _prepare_body(network="mainnet"))
    assert resp.status == 422


def test_prepare_does_not_authorize_a_blocked_destination():
    api, rpc, _ = _api(policy=near_policy(approved=frozenset({"other.testnet"})))
    resp = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    assert resp.status == 200
    assert resp.payload["authorized"] is False
    assert "prepare_id" not in resp.payload
    assert rpc.broadcasts == []


def test_submit_rejects_an_unknown_prepare_id():
    api, _, _ = _api()
    resp = _post(api, "/api/guard/near/execution/submit", {"prepare_id": "prep_nope", "signature": "AAAA"})
    assert resp.status == 404


def test_submit_is_single_use():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    from tracesettle.base58 import b58decode

    tx_hash = prepared.payload["transaction"]["tx_hash"]
    signature = base64.b64encode(ed25519.sign(b58decode(tx_hash), TEST_SEED)).decode()
    rpc.send_result = {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {"hash": tx_hash, "signer_id": SIGNER, "receiver_id": RECIPIENT,
                        "nonce": prepared.payload["transaction"]["nonce"],
                        "actions": [{"Transfer": {"deposit": str(10**24)}}]},
        "transaction_outcome": {"block_hash": prepared.payload["transaction"]["block_hash"], "outcome": {"logs": []}},
        "receipts_outcome": [],
    }
    first = _post(api, "/api/guard/near/execution/submit", {"prepare_id": prepared.payload["prepare_id"], "signature": signature})
    assert first.status == 200
    second = _post(api, "/api/guard/near/execution/submit", {"prepare_id": prepared.payload["prepare_id"], "signature": signature})
    assert second.status == 404


def test_a_bad_signature_is_refused_and_nothing_is_broadcast():
    api, rpc, _ = _api()
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    resp = _post(
        api,
        "/api/guard/near/execution/submit",
        {"prepare_id": prepared.payload["prepare_id"], "signature": base64.b64encode(b"x" * 64).decode()},
    )
    assert resp.status == 422
    assert rpc.broadcasts == []
