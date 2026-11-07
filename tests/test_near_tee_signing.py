"""Tests for the TEE signing boundary (``tracesettle/near/tee_signing/``).

The boundary is the only place TraceSettle asks a remote, attested enclave to
sign the exact NEAR transaction digest. These tests exercise the real code paths:
the canonical signing request, the digest binding, the provider adapter, the
attestation ladder and the pipeline signer adapter. The only substitution is the
network transport — every signing test signs with a **real** ed25519 key over the
**real** digest, so "the signature verifies" means it genuinely verifies.

The OutLayer HTTP provider is tested against a stand-in HTTP client, not a mocked
boundary, so the request it builds and the output it parses are the real ones.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal

import pytest

from tracesettle.near import ed25519
from tracesettle.near.assets import NearAsset
from tracesettle.near.networks import NearNetwork
from tracesettle.near.tee_signing import (
    LocalStandInSigningProvider,
    OutLayerSigningProvider,
    TeeSigningBoundary,
    TeeSigningRefusal,
    build_signing_request,
    digest_for,
)
from tracesettle.near.tee_signing.boundary import _b58, TeeSigningTransactionSigner
from tracesettle.near.tee_signing.guest_reference import (
    GuestRefusal,
    guest_accepts,
    guest_signing_digest,
)
from tracesettle.near.tee_signing.provider import ProviderCapability, TeeProviderError
from tracesettle.near.txbuild import build_ft_transfer, build_transfer

SEED = bytes(range(32))
PUBLIC_KEY = "ed25519:" + _b58(ed25519.public_key(SEED))
BUILD = "sha256:" + "0" * 64
BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"


def _transfer(amount: str = "0.01", receiver: str = "merchant.testnet"):
    return build_transfer(
        network=NearNetwork.TESTNET,
        signer_id="agent.testnet",
        public_key=PUBLIC_KEY,
        nonce=7,
        receiver_id=receiver,
        block_hash=BLOCK_HASH,
        amount_human=Decimal(amount),
        service_id="svc",
    )


def _ft_transfer(amount: str = "1.5"):
    asset = NearAsset(
        network=NearNetwork.TESTNET,
        contract="usdc.testnet",
        symbol="USDC",
        decimals=6,
        name="USD Coin",
    )
    return build_ft_transfer(
        network=NearNetwork.TESTNET,
        signer_id="agent.testnet",
        public_key=PUBLIC_KEY,
        nonce=8,
        block_hash=BLOCK_HASH,
        asset=asset,
        receiver_id="merchant.testnet",
        amount_human=Decimal(amount),
        service_id="svc",
    )


def _record(tx, *, expired: bool = False):
    return {
        "authorization_id": "auth_1",
        "execution_digest": "sha256:" + "ab" * 32,
        "expires_at": "2999-01-01T00:00:00+00:00",
        "policy_version": "v1",
        "transaction_digest": tx.payload_fingerprint(),
        "expired": expired,
    }


class _Decision:
    def __init__(self, outcome: str = "ALLOW") -> None:
        self.outcome = outcome


# ---------------------------------------------------------------------------
# The canonical signing request
# ---------------------------------------------------------------------------


def test_signing_request_digest_is_stable_and_domain_separated():
    tx = _transfer()
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    first = build_signing_request(
        transaction=tx, authorization=auth, provider="outlayer:signing-keys", approved_build=BUILD
    )
    second = build_signing_request(
        transaction=tx, authorization=auth, provider="outlayer:signing-keys", approved_build=BUILD
    )
    assert first.digest() == second.digest()
    assert first.digest().startswith("sha256:")
    assert digest_for(first) == first.digest()


def test_signing_request_digest_changes_when_the_amount_changes():
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    a = build_signing_request(
        transaction=_transfer("0.01"), authorization=auth, provider="p", approved_build=BUILD
    )
    b = build_signing_request(
        transaction=_transfer("0.02"), authorization=auth, provider="p", approved_build=BUILD
    )
    assert a.digest() != b.digest()


def test_signing_request_never_carries_raw_bytes():
    tx = _transfer()
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    request = build_signing_request(
        transaction=tx, authorization=auth, provider="p", approved_build=BUILD
    )
    canonical = request.canonical()
    for forbidden in ("raw_message", "raw_digest", "message", "bytes"):
        assert forbidden not in canonical


# ---------------------------------------------------------------------------
# The guest reference: it must reproduce the product's own digest
# ---------------------------------------------------------------------------


def test_guest_digest_matches_the_product_digest_for_a_transfer():
    tx = _transfer()
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    request = build_signing_request(
        transaction=tx, authorization=auth, provider="p", approved_build=BUILD
    )
    guest_accepts(request)
    assert "sha256:" + guest_signing_digest(request).hex() == tx.payload_fingerprint()


def test_guest_digest_matches_the_product_digest_for_an_ft_transfer():
    tx = _ft_transfer()
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    request = build_signing_request(
        transaction=tx, authorization=auth, provider="p", approved_build=BUILD
    )
    guest_accepts(request)
    assert "sha256:" + guest_signing_digest(request).hex() == tx.payload_fingerprint()


def test_guest_refuses_an_unknown_domain():
    tx = _transfer()
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    request = build_signing_request(
        transaction=tx, authorization=auth, provider="p", approved_build=BUILD
    )

    class _WrongDomain:
        def canonical(self):
            d = request.canonical()
            d["domain"] = "evil"
            return d

    with pytest.raises(GuestRefusal):
        guest_accepts(_WrongDomain())  # type: ignore[arg-type]


def test_guest_refuses_a_request_carrying_raw_bytes():
    tx = _transfer()
    auth = {"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"}
    request = build_signing_request(
        transaction=tx, authorization=auth, provider="p", approved_build=BUILD
    )

    class _Smuggling:
        def canonical(self):
            d = request.canonical()
            d["raw_message"] = "deadbeef"
            return d

    with pytest.raises(GuestRefusal):
        guest_accepts(_Smuggling())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The boundary: authorization, binding, and the signature check
# ---------------------------------------------------------------------------


def test_authorized_transaction_is_signed_and_the_signature_verifies():
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    evidence = boundary.sign(tx, decision=_Decision(), authorization_record=_record(tx))
    assert evidence.signature_verified
    signature = base64.b64decode(evidence.signature_b64)
    assert ed25519.verify(signature, tx.tx_hash_bytes, ed25519.public_key(SEED))
    # No attestation was supplied, so no TEE claim is made.
    assert evidence.state == "SIGNATURE_VERIFIED"
    assert not evidence.attestation_verified
    assert not evidence.tee_signing_verified


def test_block_decision_never_reaches_the_provider():
    tx = _transfer()
    provider = LocalStandInSigningProvider(seed=SEED)
    calls = {"n": 0}
    real = provider.sign

    def _counting(request):
        calls["n"] += 1
        return real(request)

    provider.sign = _counting  # type: ignore[assignment]
    boundary = TeeSigningBoundary(provider=provider, approved_build=BUILD)
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(tx, decision=_Decision("BLOCK"), authorization_record=_record(tx))
    assert calls["n"] == 0


@pytest.mark.parametrize("outcome", ["BLOCK", "HOLD", "REQUIRE_APPROVAL", "UNKNOWN", ""])
def test_every_non_allow_outcome_is_refused(outcome):
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(tx, decision=_Decision(outcome), authorization_record=_record(tx))


def test_missing_authorization_record_is_refused():
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(tx, decision=_Decision(), authorization_record=None)


def test_record_bound_to_a_different_digest_is_refused():
    tx = _transfer()
    other = _transfer(amount="9999")
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(other, decision=_Decision(), authorization_record=_record(tx))


def test_expired_authorization_is_refused():
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(
            tx, decision=_Decision(), authorization_record=_record(tx, expired=True)
        )


def test_a_provider_signing_with_the_wrong_key_is_refused():
    tx = _transfer()
    wrong = LocalStandInSigningProvider(seed=bytes(reversed(range(32))))
    boundary = TeeSigningBoundary(provider=wrong, approved_build=BUILD)
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(tx, decision=_Decision(), authorization_record=_record(tx))


def test_unavailable_provider_refuses_and_does_not_fall_back_to_software():
    tx = _transfer()
    provider = OutLayerSigningProvider(
        client=None, network="testnet", owner="", project="", payment_key=None
    )
    assert provider.capability().available is False
    boundary = TeeSigningBoundary(provider=provider, approved_build=BUILD)
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(tx, decision=_Decision(), authorization_record=_record(tx))


# ---------------------------------------------------------------------------
# The attestation ladder
# ---------------------------------------------------------------------------


def test_verified_attestation_reaches_tee_signing_verified():
    from tracesettle.near.enclave import ApprovedMeasurement, MeasurementPolicy

    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED),
        approved_build=BUILD,
        approved_measurement=MeasurementPolicy(
            [ApprovedMeasurement("op", {"mr_td": "aa" * 48})], require_pin=True
        ),
        expected_caller="owner",
        expected_project="proj",
        quote_verifier=_ApprovingQuoteVerifier(),
    )
    request = build_signing_request(
        transaction=tx,
        authorization={
            "id": "auth_1",
            "digest": "sha256:" + "ab" * 32,
            "expiry": "2999-01-01T00:00:00+00:00",
            "policy_version": "v1",
        },
        provider="local-stand-in",
        approved_build=BUILD,
    )
    # Sign once to obtain the signature the attestation must commit to.
    result = LocalStandInSigningProvider(seed=SEED).sign(request)
    attestation = {
        "intel_quote": "00" * 16,
        "nonce": "11" * 32,
        "wasm_hash": BUILD,
        "caller": "owner",
        "project": "proj",
        "input_hash": request.digest(),
        "output_hash": "sha256:" + __import__("hashlib").sha256(result.signature_raw64).hexdigest(),
    }
    evidence = boundary.sign(
        tx, decision=_Decision(), authorization_record=_record(tx), attestation=attestation
    )
    assert evidence.state == "TEE_SIGNING_VERIFIED", evidence.refusal_reason
    assert evidence.attestation_verified


def test_non_verifying_attestation_is_attestation_rejected():
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED),
        approved_build=BUILD,
        quote_verifier=_RejectingQuoteVerifier(),
    )
    evidence = boundary.sign(
        tx,
        decision=_Decision(),
        authorization_record=_record(tx),
        attestation={"intel_quote": "00" * 8, "nonce": "11" * 32, "wasm_hash": BUILD},
    )
    assert evidence.state == "ATTESTATION_REJECTED"
    assert not evidence.attestation_verified
    assert not evidence.tee_signing_verified


def test_attestation_for_a_different_build_is_rejected():
    from tracesettle.near.enclave import ApprovedMeasurement, MeasurementPolicy

    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED),
        approved_build=BUILD,
        approved_measurement=MeasurementPolicy(
            [ApprovedMeasurement("op", {"mr_td": "aa" * 48})], require_pin=True
        ),
        expected_caller="owner",
        expected_project="proj",
        quote_verifier=_ApprovingQuoteVerifier(),
    )
    evidence = boundary.sign(
        tx,
        decision=_Decision(),
        authorization_record=_record(tx),
        attestation={
            "intel_quote": "00" * 16,
            "nonce": "11" * 32,
            "wasm_hash": "sha256:" + "ff" * 32,
            "caller": "owner",
            "project": "proj",
        },
    )
    assert evidence.state == "ATTESTATION_REJECTED"
    assert "approved_build" in evidence.attestation["failures"]


class _Verification:
    """A stand-in for the TDX verifier's result object."""

    def __init__(self, *, verified, failures, measurement, nonce):
        self.verified = verified
        self.failures = failures
        self.measurement = measurement
        self.nonce = nonce


class _ApprovingQuoteVerifier:
    def __call__(self, *a, **k):  # noqa: ANN002, ANN003
        nonce = k.get("nonce") or (a[1] if len(a) > 1 else b"")
        if isinstance(nonce, bytes):
            nonce = nonce.hex()
        return _Verification(
            verified=True,
            failures=[],
            measurement={"mr_td": "aa" * 48},
            nonce=str(nonce),
        )


class _RejectingQuoteVerifier:
    def __call__(self, *a, **k):  # noqa: ANN002, ANN003
        return _Verification(verified=False, failures=["quote signature did not verify"], measurement={}, nonce="")


# ---------------------------------------------------------------------------
# The OutLayer provider adapter
# ---------------------------------------------------------------------------


class _FakeHttpClient:
    """A stand-in HTTP client: it records the request and returns a fixed reply."""

    def __init__(self, status: int, payload: dict) -> None:
        self.status = status
        self.payload = payload
        self.calls: list[dict] = []

    def post_json(self, url, data, headers=None):  # noqa: ANN001
        self.calls.append({"url": url, "body": json.loads(data), "headers": dict(headers or {})})
        return self.status, self.payload


def _outlayer_output(tx) -> dict:
    request = build_signing_request(
        transaction=tx,
        authorization={"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"},
        provider="outlayer:signing-keys",
        approved_build=BUILD,
    )
    digest = bytes.fromhex(tx.payload_fingerprint().split(":")[-1])
    signature = ed25519.sign(digest, SEED)
    signed = tx.signed_bytes(signature)
    return {
        "signature": base64.b64encode(signature).decode(),
        "public_key": PUBLIC_KEY,
        "signed_transaction": base64.b64encode(signed).decode(),
        "transaction_digest": tx.payload_fingerprint(),
        "request_digest": request.digest(),
        "wasm_hash": BUILD,
    }


def test_outlayer_provider_sends_the_canonical_request_and_parses_the_signature():
    tx = _transfer()
    client = _FakeHttpClient(200, {"call_id": "call_1", "output": _outlayer_output(tx)})
    provider = OutLayerSigningProvider(
        client=client,
        network="testnet",
        owner="owner",
        project="proj",
        payment_key="pk_secret",
        approved_build=BUILD,
    )
    assert provider.capability().available is True
    request = build_signing_request(
        transaction=tx,
        authorization={"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"},
        provider=provider.name,
        approved_build=BUILD,
    )
    result = provider.sign(request)
    assert result.public_key == PUBLIC_KEY
    assert len(result.signature_raw64) == 64
    assert result.execution_id == "call_1"
    # The request body carries the canonical request, not raw bytes.
    body = client.calls[0]["body"]
    assert body["input"]["domain"] == "tracesettle.tee.signing-request"
    assert "raw_message" not in body["input"]
    # The key travels only in the header.
    assert client.calls[0]["headers"]["X-Payment-Key"] == "pk_secret"
    assert "pk_secret" not in json.dumps(body)


def test_outlayer_provider_refuses_a_non_200_response():
    tx = _transfer()
    client = _FakeHttpClient(402, {"error": "insufficient balance"})
    provider = OutLayerSigningProvider(
        client=client,
        network="testnet",
        owner="owner",
        project="proj",
        payment_key="pk_secret",
        approved_build=BUILD,
    )
    request = build_signing_request(
        transaction=tx,
        authorization={"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"},
        provider=provider.name,
        approved_build=BUILD,
    )
    with pytest.raises(TeeProviderError):
        provider.sign(request)


def test_outlayer_provider_reports_unavailable_without_a_payment_key():
    provider = OutLayerSigningProvider(
        client=_FakeHttpClient(200, {}),
        network="testnet",
        owner="owner",
        project="proj",
        payment_key=None,
    )
    capability = provider.capability()
    assert capability.available is False
    assert capability.requires_payment is True


def test_outlayer_provider_never_leaks_the_payment_key_in_a_refusal_message():
    tx = _transfer()
    client = _FakeHttpClient(500, {"error": "boom"})
    provider = OutLayerSigningProvider(
        client=client,
        network="testnet",
        owner="owner",
        project="proj",
        payment_key="pk_super_secret_value",
        approved_build=BUILD,
    )
    request = build_signing_request(
        transaction=tx,
        authorization={"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"},
        provider=provider.name,
        approved_build=BUILD,
    )
    with pytest.raises(TeeProviderError) as exc:
        provider.sign(request)
    assert "pk_super_secret_value" not in str(exc.value)


# ---------------------------------------------------------------------------
# The pipeline signer adapter
# ---------------------------------------------------------------------------


def test_pipeline_signer_signs_the_authorized_transaction():
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    signer = TeeSigningTransactionSigner(
        boundary=boundary,
        transaction=tx,
        decision=_Decision(),
        authorization_record=_record(tx),
        network=NearNetwork.TESTNET,
    )
    signature = signer.sign(tx.tx_hash_bytes)
    assert ed25519.verify(signature, tx.tx_hash_bytes, ed25519.public_key(SEED))
    assert signer.last_evidence is not None
    assert signer.last_evidence.signature_verified


def test_pipeline_signer_refuses_bytes_other_than_the_authorized_transaction():
    tx = _transfer()
    other = _transfer(amount="9999")
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    signer = TeeSigningTransactionSigner(
        boundary=boundary,
        transaction=tx,
        decision=_Decision(),
        authorization_record=_record(tx),
        network=NearNetwork.TESTNET,
    )
    with pytest.raises(TeeSigningRefusal):
        signer.sign(other.tx_hash_bytes)


def test_pipeline_signer_refuses_mainnet():
    tx = _transfer()
    boundary = TeeSigningBoundary(
        provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
    )
    with pytest.raises(TeeSigningRefusal):
        TeeSigningTransactionSigner(
            boundary=boundary,
            transaction=tx,
            decision=_Decision(),
            authorization_record=_record(tx),
            network=NearNetwork.MAINNET,
        )


def test_provider_capability_serialises_honestly():
    capability = ProviderCapability(
        provider="p", available=False, detail="d", requires_payment=True
    )
    d = capability.to_dict()
    assert d["available"] is False
    assert d["requires_payment"] is True
