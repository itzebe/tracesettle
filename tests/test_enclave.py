"""Tests for the enclave signing boundary.

These exercise the boundary logic with an injected verifier (so the quote's
genuineness is covered separately by the live hardware harness and the
``tee_attestation_verification_is_genuine`` invariant) and a real ed25519 keypair,
so a signature that does not verify over the exact bytes is genuinely rejected.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from tracesettle.near import ed25519
from tracesettle.near.enclave import (
    ApprovedMeasurement,
    EnclaveError,
    EnclaveSigningBoundary,
    EnclaveTransactionSigner,
    KeyNotUsable,
    MeasurementMismatch,
    MeasurementPolicy,
    ProvisioningRequest,
    derive_provisioning_nonce,
)
from tracesettle.near.networks import NearNetwork
from tracesettle.near.tdx import TdxVerification

SEED = bytes(range(32))
PUBLIC = ed25519.public_key(SEED)
MEASUREMENT = {"mr_config_id": "aa" * 48, "rt_mr3": "bb" * 48}


def _request(**over):
    base = dict(
        key_id="key-1",
        purpose="execute",
        execution_id="exec-1",
        transaction_digest="d" * 64,
        decision_nonce="n" * 64,
        policy_version="v1",
    )
    base.update(over)
    return ProvisioningRequest(**base)


class FakeTransport:
    """A deterministic enclave: a real keypair, no network."""

    def __init__(self, *, seed: bytes = SEED, tamper: bool = False) -> None:
        self._seed = seed
        self.sign_url = "http://enclave.test/sign"
        self._tamper = tamper
        self.reports: list[str] = []

    def attestation_report(self, nonce_hex: str) -> dict:
        self.reports.append(nonce_hex)
        # The injected verifier ignores the quote bytes; a real quote is required
        # only when the real verifier runs (the live hardware harness).
        return {
            "gateway_attestation": {
                "nonce": nonce_hex,
                "intel_quote": "00" * 64,
                "signing_algo": "ed25519",
                "signing_address": ed25519.public_key(self._seed).hex(),
            }
        }

    def sign(self, payload: dict) -> dict:
        message = base64.b64decode(payload["message"])
        signature = ed25519.sign(message, self._seed)
        if self._tamper:
            signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        return {
            "signing_algo": "ed25519",
            "signing_address": ed25519.public_key(self._seed).hex(),
            "message_digest": hashlib.sha256(message).hexdigest(),
            "signature": base64.b64encode(signature).decode("ascii"),
        }


def _verifier(*, measurement=None, nonce_override=None, verified=True, signing_address=None):
    """A stand-in quote verifier bound to the requested nonce."""

    def _verify(quote, *, nonce=None, signing_address=None, **_kwargs):  # noqa: A002
        result = TdxVerification(verified=verified)
        result.nonce = (nonce_override if nonce_override is not None else (nonce or b"").hex())
        result.measurement = dict(measurement if measurement is not None else MEASUREMENT)
        result.checks = {"collateral_verified": True}
        result.signing_address = (signing_address or PUBLIC).hex()
        if not verified:
            result.failures.append("synthetic failure")
        return result

    return _verify


def _boundary(transport=None, *, measurement=None, verifier=None, require_pin=True, approved=None):
    transport = transport or FakeTransport()
    if approved is None:
        approved = [ApprovedMeasurement("good", {"mr_config_id": MEASUREMENT["mr_config_id"]})]
    return EnclaveSigningBoundary(
        transport=transport,
        measurements=MeasurementPolicy(approved, require_pin=require_pin),
        verifier=verifier or _verifier(measurement=measurement),
    )


def test_provision_succeeds_with_a_matching_measurement_pin():
    key = _boundary().provision(_request())
    assert key.signing_address == PUBLIC.hex()
    assert key.measurement_name == "good"


def test_provision_rejects_a_wrong_measurement_pin():
    with pytest.raises(MeasurementMismatch):
        _boundary(measurement={"mr_config_id": "cc" * 48}).provision(_request())


def test_provision_rejects_when_no_pin_is_configured():
    boundary = _boundary(approved=[])
    with pytest.raises(MeasurementMismatch):
        boundary.provision(_request())


def test_provision_rejects_an_unverified_quote():
    with pytest.raises(EnclaveError):
        _boundary(verifier=_verifier(verified=False)).provision(_request())


def test_provision_rejects_a_nonce_bound_to_a_different_request():
    # The verifier returns a nonce that is not the one derived for this request.
    with pytest.raises(EnclaveError):
        _boundary(verifier=_verifier(nonce_override="de" * 32)).provision(_request())


def test_sign_returns_a_signature_verified_over_the_exact_bytes():
    boundary = _boundary()
    request = _request()
    key = boundary.provision(request)
    message = b"the exact transaction hash bytes"
    result = boundary.sign(key, request, message)
    assert result.verified
    assert ed25519.verify(result.signature, message, PUBLIC)


def test_sign_refuses_a_tampered_signature():
    transport = FakeTransport(tamper=True)
    boundary = _boundary(transport=transport)
    request = _request()
    key = boundary.provision(request)
    with pytest.raises(EnclaveError):
        boundary.sign(key, request, b"message")


def test_sign_refuses_when_the_message_does_not_match():
    # A malicious or buggy enclave that signs a *different* message than the one
    # requested must be refused: the boundary verifies the signature over the
    # exact bytes it asked for.
    class WrongMessageTransport(FakeTransport):
        def sign(self, payload):
            response = super().sign(payload)
            response["signature"] = base64.b64encode(
                ed25519.sign(b"a different message", self._seed)
            ).decode("ascii")
            response["message_digest"] = hashlib.sha256(b"a different message").hexdigest()
            return response

    boundary = _boundary(transport=WrongMessageTransport())
    request = _request()
    key = boundary.provision(request)
    with pytest.raises(EnclaveError):
        boundary.sign(key, request, b"the requested message")


def test_sign_refuses_a_revoked_key():
    boundary = _boundary()
    request = _request()
    key = boundary.provision(request)
    boundary.registry.revoke(key.key_id)
    with pytest.raises(KeyNotUsable):
        boundary.sign(key, request, b"message")


def test_rotated_key_is_no_longer_usable():
    boundary = _boundary()
    request = _request()
    old = boundary.provision(request)
    new_key = boundary.provision(_request(key_id="key-2"))
    boundary.registry.rotate(old.key_id, new_key)
    assert boundary.registry.state(old.key_id) == "ROTATED"
    assert boundary.registry.is_usable(new_key.key_id)
    with pytest.raises(KeyNotUsable):
        boundary.sign(old, request, b"message")


def test_sign_refuses_a_request_that_does_not_match_the_key():
    boundary = _boundary()
    request = _request()
    key = boundary.provision(request)
    with pytest.raises(EnclaveError):
        boundary.sign(key, _request(key_id="different"), b"message")


def test_available_is_false_without_a_configured_sign_url():
    from tracesettle.near.enclave import HttpEnclaveTransport

    transport = HttpEnclaveTransport(base_url="https://cloud-api.near.ai", sign_url=None, client=object())
    boundary = EnclaveSigningBoundary(
        transport=transport, measurements=MeasurementPolicy([], require_pin=True)
    )
    assert boundary.available() is False


def test_enclave_transaction_signer_produces_a_verifiable_signature():
    boundary = _boundary()
    request = _request()
    key = boundary.provision(request)
    signer = EnclaveTransactionSigner(
        boundary=boundary, key=key, request=request, account_id="acct.testnet",
        network=NearNetwork.TESTNET,
    )
    assert signer.public_key == "ed25519:" + signer.public_key.split(":", 1)[1]
    message = b"tx hash bytes"
    signature = signer.sign(message)
    assert ed25519.verify(signature, message, PUBLIC)


def test_enclave_transaction_signer_refuses_mainnet():
    boundary = _boundary()
    request = _request()
    key = boundary.provision(request)
    with pytest.raises(EnclaveError):
        EnclaveTransactionSigner(
            boundary=boundary, key=key, request=request, account_id="acct.near",
            network=NearNetwork.MAINNET,
        )


def test_derive_provisioning_nonce_is_request_specific_and_unpredictable():
    a = derive_provisioning_nonce(_request())
    b = derive_provisioning_nonce(_request())
    assert a != b  # fresh randomness
    assert derive_provisioning_nonce(_request(), salt=b"x") == derive_provisioning_nonce(
        _request(), salt=b"x"
    )
    assert derive_provisioning_nonce(_request(), salt=b"x") != derive_provisioning_nonce(
        _request(execution_id="other"), salt=b"x"
    )


def test_measurement_policy_requires_every_pinned_field():
    policy = MeasurementPolicy(
        [ApprovedMeasurement("m", {"mr_config_id": "aa" * 48, "rt_mr3": "bb" * 48})]
    )
    assert policy.evaluate(MEASUREMENT).name == "m"
    with pytest.raises(MeasurementMismatch):
        policy.evaluate({"mr_config_id": "aa" * 48})  # missing rt_mr3


def test_approved_measurement_with_no_fields_is_refused():
    with pytest.raises(MeasurementMismatch):
        ApprovedMeasurement("empty", {})
