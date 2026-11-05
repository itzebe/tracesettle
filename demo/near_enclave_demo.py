#!/usr/bin/env python3
"""Deterministic enclave signing-boundary demonstration.

Shows the boundary's guarantees end to end with a *stand-in* enclave transport: a
real ed25519 keypair, a deterministic attestation, and no network. The boundary
logic (measurement pinning, transaction binding, signature verification, mainnet
refusal) is the real code path. The only substitution is the enclave transport,
exactly as the test suite substitutes it; the genuineness of real quote
verification is covered separately by the live hardware harness
(``tracesettle/near/enclave_harness.py``) and the
``tee_attestation_verification_is_genuine`` invariant.

Usage:
    python demo/near_enclave_demo.py            # all checks
    python demo/near_enclave_demo.py --json     # machine-readable

Nothing here signs a real transaction or reaches a chain. The executor is never
invoked; a signature is produced and verified locally over synthetic bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.near import ed25519  # noqa: E402
from tracesettle.near.enclave import (  # noqa: E402
    ApprovedMeasurement,
    EnclaveError,
    EnclaveSigningBoundary,
    EnclaveTransactionSigner,
    MeasurementMismatch,
    MeasurementPolicy,
    ProvisioningRequest,
    _b58,
)
from tracesettle.near.networks import NearNetwork  # noqa: E402
from tracesettle.near.tdx import TdxVerification  # noqa: E402

SEED = bytes(range(32))
PUBLIC = ed25519.public_key(SEED)
MEASUREMENT = {"mr_config_id": "aa" * 48}

SIMULATION_NOTE = (
    "Controlled demonstration: the enclave transport is a deterministic stand-in "
    "with a real keypair; the boundary logic is real. No transaction is signed for "
    "a chain, nothing is broadcast, and no key is requested."
)


class _StandInEnclave:
    """A deterministic enclave: a real keypair, no network."""

    sign_url = "http://enclave.test/sign"

    def __init__(self, *, seed: bytes = SEED, tamper: bool = False) -> None:
        self._seed = seed
        self._tamper = tamper

    def attestation_report(self, nonce_hex: str) -> dict:
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


def _verifier(quote, *, nonce=None, signing_address=None, **kwargs):  # noqa: A002
    result = TdxVerification(verified=True)
    result.nonce = (nonce or b"").hex()
    result.measurement = dict(MEASUREMENT)
    result.checks = {"collateral_verified": True}
    result.signing_address = PUBLIC.hex()
    return result


def _boundary(transport, *, fields=None):
    return EnclaveSigningBoundary(
        transport=transport,
        measurements=MeasurementPolicy(
            [ApprovedMeasurement("near-ai-cloud", fields or dict(MEASUREMENT))], require_pin=True
        ),
        verifier=_verifier,
    )


def _request(**over):
    base = dict(
        key_id="demo-key",
        purpose="execute",
        execution_id="demo-exec",
        transaction_digest="ab" * 32,
        decision_nonce="cd" * 32,
        policy_version="v1",
    )
    base.update(over)
    return ProvisioningRequest(**base)


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

    def _provision_and_verify():
        transport = _StandInEnclave()
        boundary = _boundary(transport)
        assert boundary.available() is True
        request = _request()
        key = boundary.provision(request)
        signer = EnclaveTransactionSigner(
            boundary=boundary,
            key=key,
            request=request,
            account_id="agent.testnet",
            network=NearNetwork.TESTNET,
        )
        message = bytes.fromhex(request.transaction_digest)
        signature = signer.sign(message)
        assert ed25519.verify(signature, message, bytes.fromhex(key.signing_address))
        assert signer.public_key.endswith(_b58(bytes.fromhex(key.signing_address)))
        assert signer.public_key.startswith("ed25519:")

    checks.append(_check("A a signed, verified enclave key over the exact bytes", _provision_and_verify))

    def _wrong_measurement_refused():
        transport = _StandInEnclave()
        boundary = _boundary(transport, fields={"mr_config_id": "bb" * 48})
        try:
            boundary.provision(_request())
        except MeasurementMismatch:
            return
        raise AssertionError("a non-approved measurement was accepted")

    checks.append(_check("B a non-approved measurement is refused", _wrong_measurement_refused))

    def _mainnet_refused():
        transport = _StandInEnclave()
        boundary = _boundary(transport)
        request = _request()
        key = boundary.provision(request)
        try:
            EnclaveTransactionSigner(
                boundary=boundary,
                key=key,
                request=request,
                account_id="agent.near",
                network=NearNetwork.MAINNET,
            )
        except EnclaveError:
            return
        raise AssertionError("mainnet signing was not refused")

    checks.append(_check("C mainnet signing is refused (testnet-only boundary)", _mainnet_refused))

    def _tampered_signature_refused():
        transport = _StandInEnclave(tamper=True)
        boundary = _boundary(transport)
        request = _request()
        key = boundary.provision(request)
        signer = EnclaveTransactionSigner(
            boundary=boundary,
            key=key,
            request=request,
            account_id="agent.testnet",
            network=NearNetwork.TESTNET,
        )
        try:
            signer.sign(bytes.fromhex(request.transaction_digest))
        except EnclaveError:
            return
        raise AssertionError("a signature that does not verify was accepted")

    checks.append(_check("D a signature that does not verify is refused", _tampered_signature_refused))

    def _mismatched_request_refused():
        transport = _StandInEnclave()
        boundary = _boundary(transport)
        request = _request()
        key = boundary.provision(request)
        other = _request(key_id="other-key")
        try:
            boundary.sign(key, other, b"x")
        except EnclaveError:
            return
        raise AssertionError("a key was used with a different provisioning request")

    checks.append(_check("E a key cannot be used with a different request", _mismatched_request_refused))

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="TRACESETTLE enclave boundary demonstration")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    checks = run_all()
    passed = all(c["passed"] for c in checks)

    if args.json:
        print(json.dumps({"note": SIMULATION_NOTE, "checks": checks, "all_passed": passed}, indent=2))
        return 0 if passed else 1

    print("=" * 78)
    print("TRACESETTLE — Enclave signing boundary demonstration")
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
    print("No transaction was signed for a chain. No key was requested.")
    print("=" * 78)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
