#!/usr/bin/env python3
"""Deterministic TEE signing-boundary demonstration.

Shows the boundary's guarantees end to end with a *stand-in* signing provider: a
real ed25519 key, a real NEAR transaction, and no network. The boundary logic
(authorization precondition, digest binding, signature verification, the
attestation ladder, mainnet refusal) is the real code path. The only substitution
is the network transport to OutLayer, exactly as the test suite substitutes it;
the genuineness of real Intel TDX quote verification is covered separately by
``tee_attestation_verification_is_genuine`` and the live hardware harness.

Usage:
    python demo/near_tee_signing_demo.py            # all checks
    python demo/near_tee_signing_demo.py --json     # machine-readable

Nothing here reaches OutLayer, signs a real transaction, or touches a chain. The
signing provider is a deterministic stand-in with a real keypair; the digest and
the signature are real, and they are verified over the exact NEAR transaction
digest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.near import ed25519  # noqa: E402
from tracesettle.near.enclave import ApprovedMeasurement, MeasurementPolicy  # noqa: E402
from tracesettle.near.networks import NearNetwork  # noqa: E402
from tracesettle.near.tee_signing import (  # noqa: E402
    LocalStandInSigningProvider,
    OutLayerSigningProvider,
    TeeSigningBoundary,
    TeeSigningRefusal,
    build_signing_request,
)
from tracesettle.near.tee_signing.boundary import (  # noqa: E402
    TeeSigningTransactionSigner,
    _b58,
)
from tracesettle.near.tee_signing.guest_reference import (  # noqa: E402
    guest_accepts,
    guest_signing_digest,
)
from tracesettle.near.txbuild import build_transfer  # noqa: E402

SEED = bytes(range(32))
PUBLIC_KEY = "ed25519:" + _b58(ed25519.public_key(SEED))
BUILD = "sha256:" + "0" * 64
MEASUREMENT = {"mr_td": "aa" * 48}
BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"

SIMULATION_NOTE = (
    "Controlled demonstration: the signing provider is a deterministic stand-in "
    "with a real ed25519 key; the boundary, the digest binding and the signature "
    "verification are the real code paths. No OutLayer call is made, nothing is "
    "broadcast, and no key material is requested."
)


def _tx(amount: str = "0.01", receiver: str = "merchant.testnet"):
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


class _Decision:
    def __init__(self, outcome: str = "ALLOW") -> None:
        self.outcome = outcome


def _record(tx, *, expired: bool = False):
    return {
        "authorization_id": "auth_1",
        "execution_digest": "sha256:" + "ab" * 32,
        "expires_at": "2999-01-01T00:00:00+00:00",
        "policy_version": "v1",
        "transaction_digest": tx.payload_fingerprint(),
        "expired": expired,
    }


class _Verification:
    def __init__(self, *, verified, failures, measurement, nonce):
        self.verified = verified
        self.failures = failures
        self.measurement = measurement
        self.nonce = nonce


class _ApprovingVerifier:
    def __call__(self, *a, **k):  # noqa: ANN002, ANN003
        nonce = k.get("nonce") or (a[1] if len(a) > 1 else b"")
        if isinstance(nonce, bytes):
            nonce = nonce.hex()
        return _Verification(
            verified=True, failures=[], measurement=dict(MEASUREMENT), nonce=str(nonce)
        )


class _RejectingVerifier:
    def __call__(self, *a, **k):  # noqa: ANN002, ANN003
        return _Verification(
            verified=False,
            failures=["quote signature did not verify"],
            measurement={},
            nonce="",
        )


def _check(name, fn):
    try:
        fn()
    except AssertionError as exc:  # pragma: no cover - demo reporting
        return {"name": name, "passed": False, "detail": str(exc) or "assertion failed"}
    except Exception as exc:  # noqa: BLE001 - demo reporting
        return {"name": name, "passed": False, "detail": f"{type(exc).__name__}: {exc}"}
    return {"name": name, "passed": True, "detail": ""}


def run_all() -> list[dict]:
    checks: list[dict] = []

    def _authorized_signature_verifies():
        tx = _tx()
        boundary = TeeSigningBoundary(
            provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
        )
        evidence = boundary.sign(tx, decision=_Decision(), authorization_record=_record(tx))
        assert evidence.signature_verified, "the signature was not verified"
        signature = base64.b64decode(evidence.signature_b64)
        assert ed25519.verify(signature, tx.tx_hash_bytes, ed25519.public_key(SEED))
        assert evidence.state == "SIGNATURE_VERIFIED"
        assert not evidence.tee_signing_verified, "a TEE claim was made with no attestation"

    checks.append(
        _check("A an authorized transaction is signed and the signature verifies", _authorized_signature_verifies)
    )

    def _guest_matches_product_digest():
        tx = _tx()
        request = build_signing_request(
            transaction=tx,
            authorization={"id": "a", "digest": "sha256:ab", "expiry": "e", "policy_version": "v1"},
            provider="local-stand-in",
            approved_build=BUILD,
        )
        guest_accepts(request)
        assert "sha256:" + guest_signing_digest(request).hex() == tx.payload_fingerprint()

    checks.append(
        _check("B the enclave guest recomputes the product's exact NEAR digest", _guest_matches_product_digest)
    )

    def _block_never_reaches_the_provider():
        tx = _tx()
        provider = LocalStandInSigningProvider(seed=SEED)
        calls = {"n": 0}
        real = provider.sign

        def _counting(request):  # noqa: ANN001
            calls["n"] += 1
            return real(request)

        provider.sign = _counting  # type: ignore[assignment]
        boundary = TeeSigningBoundary(provider=provider, approved_build=BUILD)
        try:
            boundary.sign(tx, decision=_Decision("BLOCK"), authorization_record=_record(tx))
        except TeeSigningRefusal:
            assert calls["n"] == 0, "the provider was called for a BLOCK"
            return
        raise AssertionError("a BLOCK decision was signed")

    checks.append(
        _check("C a BLOCK decision never reaches the signing provider", _block_never_reaches_the_provider)
    )

    def _digest_mismatch_refused():
        tx = _tx()
        other = _tx(amount="9999")
        boundary = TeeSigningBoundary(
            provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
        )
        try:
            boundary.sign(other, decision=_Decision(), authorization_record=_record(tx))
        except TeeSigningRefusal:
            return
        raise AssertionError("a record for a different transaction was accepted")

    checks.append(
        _check("D a record bound to another transaction is refused", _digest_mismatch_refused)
    )

    def _wrong_key_refused():
        tx = _tx()
        boundary = TeeSigningBoundary(
            provider=LocalStandInSigningProvider(seed=bytes(reversed(range(32)))),
            approved_build=BUILD,
        )
        try:
            boundary.sign(tx, decision=_Decision(), authorization_record=_record(tx))
        except TeeSigningRefusal:
            return
        raise AssertionError("a signature under the wrong key was accepted")

    checks.append(_check("E a signature under a different key is refused", _wrong_key_refused))

    def _non_verifying_attestation_rejected():
        tx = _tx()
        boundary = TeeSigningBoundary(
            provider=LocalStandInSigningProvider(seed=SEED),
            approved_build=BUILD,
            quote_verifier=_RejectingVerifier(),
        )
        evidence = boundary.sign(
            tx,
            decision=_Decision(),
            authorization_record=_record(tx),
            attestation={"intel_quote": "00" * 8, "nonce": "11" * 32, "wasm_hash": BUILD},
        )
        assert evidence.state == "ATTESTATION_REJECTED"
        assert not evidence.tee_signing_verified

    checks.append(
        _check("F a non-verifying attestation never reaches TEE_SIGNING_VERIFIED", _non_verifying_attestation_rejected)
    )

    def _verified_attestation_reaches_the_top_state():
        tx = _tx()
        boundary = TeeSigningBoundary(
            provider=LocalStandInSigningProvider(seed=SEED),
            approved_build=BUILD,
            approved_measurement=MeasurementPolicy(
                [ApprovedMeasurement("op", dict(MEASUREMENT))], require_pin=True
            ),
            expected_caller="owner",
            expected_project="proj",
            quote_verifier=_ApprovingVerifier(),
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
        result = LocalStandInSigningProvider(seed=SEED).sign(request)
        evidence = boundary.sign(
            tx,
            decision=_Decision(),
            authorization_record=_record(tx),
            attestation={
                "intel_quote": "00" * 16,
                "nonce": "11" * 32,
                "wasm_hash": BUILD,
                "caller": "owner",
                "project": "proj",
                "input_hash": request.digest(),
                "output_hash": "sha256:" + hashlib.sha256(result.signature_raw64).hexdigest(),
            },
        )
        assert evidence.state == "TEE_SIGNING_VERIFIED", evidence.refusal_reason
        assert evidence.attestation_verified

    checks.append(
        _check(
            "G a fully verified attestation reaches TEE_SIGNING_VERIFIED",
            _verified_attestation_reaches_the_top_state,
        )
    )

    def _mainnet_refused():
        tx = _tx()
        boundary = TeeSigningBoundary(
            provider=LocalStandInSigningProvider(seed=SEED), approved_build=BUILD
        )
        try:
            TeeSigningTransactionSigner(
                boundary=boundary,
                transaction=tx,
                decision=_Decision(),
                authorization_record=_record(tx),
                network=NearNetwork.MAINNET,
            )
        except TeeSigningRefusal:
            return
        raise AssertionError("mainnet signing was not refused")

    checks.append(_check("H the signing boundary refuses mainnet (testnet-only)", _mainnet_refused))

    def _unconfigured_provider_refuses():
        tx = _tx()
        provider = OutLayerSigningProvider(
            client=None, network="testnet", owner="owner", project="proj", payment_key=None
        )
        assert provider.capability().available is False
        boundary = TeeSigningBoundary(provider=provider, approved_build=BUILD)
        try:
            boundary.sign(tx, decision=_Decision(), authorization_record=_record(tx))
        except TeeSigningRefusal:
            return
        raise AssertionError("an unavailable provider signed anyway")

    checks.append(
        _check(
            "I with no payment key the real provider refuses (no software fallback)",
            _unconfigured_provider_refuses,
        )
    )

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="TRACESETTLE TEE signing boundary demonstration")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    checks = run_all()
    passed = all(c["passed"] for c in checks)

    if args.json:
        print(json.dumps({"note": SIMULATION_NOTE, "checks": checks, "all_passed": passed}, indent=2))
        return 0 if passed else 1

    print("=" * 78)
    print("TRACESETTLE — TEE signing boundary demonstration")
    print("=" * 78)
    print(SIMULATION_NOTE)
    print()
    for c in checks:
        mark = "PASS" if c["passed"] else "FAIL"
        print(f"  [{mark}] {c['name']}")
        if not c["passed"]:
            print(f"         {c['detail']}")
    print()
    print(f"{sum(c['passed'] for c in checks)}/{len(checks)} checks produced the expected outcome.")
    print("=" * 78)
    print("No OutLayer call was made. Nothing was broadcast. No key was requested.")
    print("=" * 78)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
