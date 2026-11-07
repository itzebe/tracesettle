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


def test_info_reports_the_provider_policy_gate_honestly():
    """With no adapter configured, the layer is reported not applied, never implied."""
    api, _, _ = _api()
    info = api.dispatch("GET", "/api/guard/near/execution", {}, None)
    gate = info.payload["provider_policy_gate"]
    assert gate["applied"] is False
    assert "note" in gate


def test_info_reports_the_provider_policy_gate_when_configured():
    from tracesettle.near.policy import PolicyAdapter
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    api, _, _ = _api()

    class _Fixed:
        base_url = "https://provider.invalid"

        def read_policy(self, agent_id):  # noqa: ARG002
            return PolicyAdapter.from_fixture(
                {
                    "agent_id": "treasury-agent",
                    "revision": 1,
                    "status": "APPLIED",
                    "provider_policy_synced": True,
                    "native": {"near": {"transfer": True}},
                }
            )

    api.near_execution._policy_adapter = _Fixed()
    api.near_execution._provider_policy_agent_id = "treasury-agent"
    api.near_execution._policy_gate = ProviderPolicyGate(
        api.near_execution._policy_adapter, agent_id="treasury-agent", native_chain="near"
    )
    info = api.dispatch("GET", "/api/guard/near/execution", {}, None)
    gate = info.payload["provider_policy_gate"]
    assert gate["applied"] is True
    assert gate["agent_id"] == "treasury-agent"


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


# --- the TEE gate over HTTP -----------------------------------------------


def _tee_api(*, provider=None, expected_measurement=""):
    from near_helpers import FakeTeeProvider
    from tracesettle.near.tee_execution import ExecutionRecordStore, TeeExecutionAuthorizer

    guard = make_guard(near_policy())
    config = NETWORKS[NearNetwork.TESTNET]
    rpc = FakeNearRpc(config)
    authorizer = TeeExecutionAuthorizer(
        store=ExecutionRecordStore(),
        require_attestation=True,
        expected_measurement=expected_measurement,
        ttl_seconds=90,
    )
    provider = provider or FakeTeeProvider()
    boundary = NearExecutionBoundary(
        guard, config, rpc=rpc, tee_authorizer=authorizer, tee_provider=provider
    )
    return GuardAPI(guard, near_execution=boundary), rpc, authorizer, provider


def test_the_execution_info_reports_the_tee_gate():
    api, _, _, _ = _tee_api()
    info = api.dispatch("GET", "/api/guard/near/execution", {}, None)
    assert info.status == 200
    assert info.payload["tee_gate"]["enabled"] is True
    assert info.payload["tee_gate"]["required"] is True


def test_attest_binds_a_verified_attestation_over_http():
    api, rpc, authorizer, provider = _tee_api()
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    execution_id = prepared.payload["execution_id"]
    assert execution_id
    attested = _post(api, "/api/guard/near/execution/attest", {"prepare_id": prepared.payload["prepare_id"]})
    assert attested.status == 200, attested.payload
    assert attested.payload["tee_verified"] is True
    record = authorizer.get(execution_id)
    assert record.tee_verified
    # The record is inspectable through its own route.
    fetched = api.dispatch("GET", f"/api/guard/near/execution/record/{execution_id}", {}, None)
    assert fetched.status == 200
    assert fetched.payload["record"]["tee_verified"] is True


def test_submit_without_attestation_is_refused_over_http_and_nothing_broadcasts():
    api, rpc, _, _ = _tee_api()
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    from tracesettle.base58 import b58decode

    tx_hash = prepared.payload["transaction"]["tx_hash"]
    signature = base64.b64encode(ed25519.sign(b58decode(tx_hash), TEST_SEED)).decode()
    resp = _post(
        api,
        "/api/guard/near/execution/submit",
        {"prepare_id": prepared.payload["prepare_id"], "signature": signature},
    )
    assert resp.status == 422
    assert rpc.broadcasts == []


def test_a_failed_attestation_is_refused_over_http():
    from near_helpers import FakeTeeProvider

    api, rpc, authorizer, provider = _tee_api(provider=FakeTeeProvider(verified=False))
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    resp = _post(api, "/api/guard/near/execution/attest", {"prepare_id": prepared.payload["prepare_id"]})
    assert resp.status == 422
    assert rpc.broadcasts == []


def test_attest_without_a_gate_is_a_conflict():
    api, rpc, _ = _api()  # no tee_authorizer
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    resp = _post(api, "/api/guard/near/execution/attest", {"prepare_id": prepared.payload["prepare_id"]})
    assert resp.status == 409


def test_attest_requires_a_prepare_id():
    api, _, _, _ = _tee_api()
    resp = _post(api, "/api/guard/near/execution/attest", {})
    assert resp.status == 400


def test_attest_unknown_prepare_id_is_not_found():
    api, _, _, _ = _tee_api()
    resp = _post(api, "/api/guard/near/execution/attest", {"prepare_id": "nope"})
    assert resp.status == 404


# -- enclave signing route ----------------------------------------------------


class _StandInEnclave:
    """A deterministic enclave: real keypair, no network."""

    sign_url = "http://enclave.test/sign"

    def __init__(self, public: bytes):
        self.public = public

    def attestation_report(self, nonce_hex):
        return {
            "gateway_attestation": {
                "intel_quote": "00" * 64,
                "signing_algo": "ed25519",
                "signing_address": self.public.hex(),
            }
        }

    def sign(self, payload):
        import hashlib

        message = base64.b64decode(payload["message"])
        return {
            "signing_algo": "ed25519",
            "signing_address": self.public.hex(),
            "message_digest": hashlib.sha256(message).hexdigest(),
            "signature": base64.b64encode(ed25519.sign(message, TEST_SEED)).decode("ascii"),
        }


def _enclave_boundary(public: bytes):
    from tracesettle.near.enclave import (
        ApprovedMeasurement,
        EnclaveSigningBoundary,
        MeasurementPolicy,
    )
    from tracesettle.near.tdx import TdxVerification

    def verifier(quote, *, nonce=None, signing_address=None, **kwargs):  # noqa: A002
        result = TdxVerification(verified=True)
        result.nonce = (nonce or b"").hex()
        result.measurement = {"mr_config_id": "aa" * 48}
        result.checks = {"collateral_verified": True}
        result.signing_address = public.hex()
        return result

    return EnclaveSigningBoundary(
        transport=_StandInEnclave(public),
        measurements=MeasurementPolicy(
            [ApprovedMeasurement("test", {"mr_config_id": "aa" * 48})], require_pin=True
        ),
        verifier=verifier,
    )


def test_enclave_sign_route_signs_and_submits():
    from near_helpers import result_for
    from tracesettle.near.ed25519 import public_key

    public = public_key(TEST_SEED)
    guard = make_guard(near_policy())
    rpc = FakeNearRpc(NETWORKS[NearNetwork.TESTNET])
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    api = GuardAPI(guard, near_execution=boundary, enclave=_enclave_boundary(public))

    info = api.dispatch("GET", "/api/guard/near/enclave", {}, None)
    assert info.status == 200 and info.payload["enabled"] is True

    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    assert prepared.status == 200
    prepare_id = prepared.payload["prepare_id"]

    signed = _post(api, "/api/guard/near/execution/enclave-sign", {"prepare_id": prepare_id})
    assert signed.status == 200, signed.payload
    signature = signed.payload["signature"]

    rpc.send_result = result_for(api.near_execution_store().peek(prepare_id, "local").transaction)
    rpc.tx_status_result = rpc.send_result
    submitted = _post(
        api,
        "/api/guard/near/execution/submit",
        {"prepare_id": prepare_id, "signature": signature},
    )
    assert submitted.status == 200, submitted.payload
    assert len(rpc.broadcasts) == 1
    assert submitted.payload["tx_hash"] == signed.payload["tx_hash"]


def test_enclave_sign_route_is_absent_without_an_enclave():
    api, _rpc, _guard = _api()
    info = api.dispatch("GET", "/api/guard/near/enclave", {}, None)
    assert info.status == 200 and info.payload["enabled"] is False
    prepared = _post(api, "/api/guard/near/execution/prepare", _prepare_body())
    refused = _post(
        api, "/api/guard/near/execution/enclave-sign", {"prepare_id": prepared.payload["prepare_id"]}
    )
    assert refused.status == 409


def test_enclave_sign_route_requires_a_known_prepare_id():
    from tracesettle.near.ed25519 import public_key

    guard = make_guard(near_policy())
    rpc = FakeNearRpc(NETWORKS[NearNetwork.TESTNET])
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    api = GuardAPI(guard, near_execution=boundary, enclave=_enclave_boundary(public_key(TEST_SEED)))
    refused = _post(
        api, "/api/guard/near/execution/enclave-sign", {"prepare_id": "does-not-exist"}
    )
    assert refused.status == 404


# ---------------------------------------------------------------------------
# The TEE signing boundary route (OutLayer Signing Keys)
# ---------------------------------------------------------------------------


def test_tee_signing_is_disabled_by_default():
    api = GuardAPI(make_guard())
    info = api.dispatch("GET", "/api/guard/near/tee-signing", {}, None)
    assert info.status == 200
    assert info.payload["enabled"] is False
    assert "TRACESETTLE_TEE_SIGNING" in info.payload["note"]


def test_tee_signing_reports_unavailable_when_configured_without_a_payment_key():
    from tracesettle.near.tee_signing import OutLayerSigningProvider, TeeSigningBoundary

    provider = OutLayerSigningProvider(
        client=None, network="testnet", owner="owner", project="proj", payment_key=None
    )
    boundary = TeeSigningBoundary(provider=provider, approved_build="sha256:" + "0" * 64)
    api = GuardAPI(make_guard(), tee_signing=boundary)
    info = api.dispatch("GET", "/api/guard/near/tee-signing", {}, None)
    assert info.status == 200
    assert info.payload["enabled"] is True
    assert info.payload["available"] is False
    assert info.payload["provider"]["requires_payment"] is True


def test_tee_signing_never_reports_a_tee_claim_it_did_not_verify():
    from tracesettle.near.tee_signing import LocalStandInSigningProvider, TeeSigningBoundary

    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=bytes(range(32))),
        approved_build="sha256:" + "0" * 64,
    )
    api = GuardAPI(make_guard(), tee_signing=boundary)
    info = api.dispatch("GET", "/api/guard/near/tee-signing", {}, None)
    # The stand-in is not a TEE; the route still reports the honest checks.
    assert "the Intel TDX quote against the pinned Intel root and fresh collateral" in info.payload[
        "verifies"
    ]
    assert info.payload["measurement_pinned"] is False
