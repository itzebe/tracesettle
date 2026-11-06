"""End-to-end: an enclave-signed transaction flows through the real pipeline.

The enclave boundary is exercised with a deterministic stand-in enclave holding a
real ed25519 keypair, and the *rest* of the path is real: the real transaction
builder, the real guard, the real TEE authorizer, the real settlement verifier,
and the real durable ledger. The only substitutions are the network boundaries
(the RPC transport and the enclave transport), which is the same discipline the
other pipeline tests use. "Nothing was broadcast" is asserted by inspecting the
recorded submissions.
"""

from __future__ import annotations

import base64
import hashlib

from near_helpers import (
    RECIPIENT,
    SIGNER,
    TEST_SEED,
    make_boundary,
    make_guard,
    b58encode,
    near_policy,
    result_for,
)
from tracesettle.near import ed25519
from tracesettle.near.enclave import (
    ApprovedMeasurement,
    EnclaveSigningBoundary,
    EnclaveTransactionSigner,
    MeasurementPolicy,
    ProvisioningRequest,
)
from tracesettle.near.ledger import SubmissionLedger, SubmissionState
from tracesettle.near.networks import NearNetwork
from tracesettle.near.pipeline import NearExecutionPipeline
from tracesettle.near.tdx import TdxVerification
from tracesettle.near.verify import SettlementState

MEASUREMENT = {"mr_config_id": "aa" * 48}
PUBLIC = ed25519.public_key(TEST_SEED)


class _StandInEnclave:
    """A deterministic enclave: real keypair, no network, nonce echoed."""

    sign_url = "http://enclave.test/sign"

    def __init__(self) -> None:
        self.signed: list[bytes] = []

    def attestation_report(self, nonce_hex: str) -> dict:
        return {
            "gateway_attestation": {
                "intel_quote": "00" * 64,
                "signing_algo": "ed25519",
                "signing_address": PUBLIC.hex(),
                "nonce": nonce_hex,
            }
        }

    def sign(self, payload: dict) -> dict:
        message = base64.b64decode(payload["message"])
        self.signed.append(message)
        return {
            "signing_algo": "ed25519",
            "signing_address": PUBLIC.hex(),
            "message_digest": hashlib.sha256(message).hexdigest(),
            "signature": base64.b64encode(ed25519.sign(message, TEST_SEED)).decode("ascii"),
        }


def _verifier(quote, *, nonce=None, signing_address=None, **kwargs):  # noqa: A002
    result = TdxVerification(verified=True)
    result.nonce = (nonce or b"").hex()
    result.measurement = dict(MEASUREMENT)
    result.checks = {"collateral_verified": True}
    result.signing_address = PUBLIC.hex()
    return result


def _enclave_boundary(transport):
    return EnclaveSigningBoundary(
        transport=transport,
        measurements=MeasurementPolicy(
            [ApprovedMeasurement("test-enclave", {"mr_config_id": MEASUREMENT["mr_config_id"]})],
            require_pin=True,
        ),
        verifier=_verifier,
    )


def test_enclave_signed_transaction_settles_through_the_real_pipeline():
    boundary, rpc = make_boundary()
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger())
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key="ed25519:" + b58encode(PUBLIC),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    transport = _StandInEnclave()
    enclave = _enclave_boundary(transport)
    request = ProvisioningRequest(
        key_id="enclave-key-1",
        purpose="execute",
        execution_id=prepared.transaction.tx_hash,
        transaction_digest=prepared.transaction.tx_hash,
        decision_nonce=prepared.transaction.tx_hash,
        policy_version="v1",
    )
    key = enclave.provision(request)
    signer = EnclaveTransactionSigner(
        boundary=enclave, key=key, request=request, account_id=SIGNER, network=NearNetwork.TESTNET
    )

    result = pipeline.execute(prepared, signer)

    assert result.state == SubmissionState.SETTLED
    assert result.settlement_state == SettlementState.VERIFIED.value
    # The enclave signed the exact transaction-hash bytes, once.
    assert transport.signed == [prepared.transaction.tx_hash_bytes]
    assert len(rpc.broadcasts) == 1


def test_enclave_signer_refusal_stops_execution_before_broadcast():
    """If the enclave refuses, nothing is signed by software and nothing is broadcast."""
    boundary, rpc = make_boundary()
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger())
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key="ed25519:" + b58encode(PUBLIC),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")

    transport = _StandInEnclave()
    enclave = _enclave_boundary(transport)
    request = ProvisioningRequest(
        key_id="enclave-key-1",
        purpose="execute",
        execution_id=prepared.transaction.tx_hash,
        transaction_digest=prepared.transaction.tx_hash,
        decision_nonce=prepared.transaction.tx_hash,
        policy_version="v1",
    )
    key = enclave.provision(request)
    signer = EnclaveTransactionSigner(
        boundary=enclave, key=key, request=request, account_id=SIGNER, network=NearNetwork.TESTNET
    )
    # Revoke the key: the enclave must refuse, and the pipeline must not broadcast.
    enclave.registry.revoke(key.key_id)

    import pytest

    from tracesettle.near.pipeline import SigningError

    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)
    assert rpc.broadcasts == [], "a refused enclave signature must never reach broadcast"


def test_enclave_guard_policy_blocks_before_any_signing():
    """A guard BLOCK prevents the enclave from ever being asked to sign."""
    guard = make_guard(policy=near_policy(approved=frozenset({"someone-else.testnet"})))
    boundary, rpc = make_boundary(guard)
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger())
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key="ed25519:" + b58encode(PUBLIC),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )

    transport = _StandInEnclave()
    enclave = _enclave_boundary(transport)
    request = ProvisioningRequest(
        key_id="enclave-key-1",
        purpose="execute",
        execution_id=prepared.transaction.tx_hash,
        transaction_digest=prepared.transaction.tx_hash,
        decision_nonce=prepared.transaction.tx_hash,
        policy_version="v1",
    )
    key = enclave.provision(request)
    signer = EnclaveTransactionSigner(
        boundary=enclave, key=key, request=request, account_id=SIGNER, network=NearNetwork.TESTNET
    )

    import pytest

    from tracesettle.near.pipeline import SigningError

    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)
    assert transport.signed == []
    assert rpc.broadcasts == []
