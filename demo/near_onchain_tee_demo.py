#!/usr/bin/env python3
"""The free on-chain TEE signing route, demonstrated offline and deterministically.

This replays a **real** OutLayer run captured on 2026-11-07
(``tracesettle/near/fixtures/onchain_tee_run.json``): a genuine Intel TDX enclave
executed the TraceSettle guest and signed a real NEAR testnet transaction. The
capture holds public data only — no key, no seed, no signed-bytes blob.

The strongest check needs no trust in the capture at all: the product's own
transaction builder is fed the parameters the enclave recorded, and it must
reproduce the **exact** digest and transaction hash the live run produced. If the
product's serialization drifted by one byte, this fails.

Usage:
    python demo/near_onchain_tee_demo.py            # all checks
    python demo/near_onchain_tee_demo.py --json     # machine-readable

Nothing here reaches OutLayer, signs a transaction, or touches a chain. The live
reproduction is ``tests/test_near_live_onchain_tee.py`` (opt-in, testnet only).
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.model import SourceStatus  # noqa: E402
from tracesettle.near import ed25519  # noqa: E402
from tracesettle.near.networks import NearNetwork  # noqa: E402
from tracesettle.near.rpc import RpcResult  # noqa: E402
from tracesettle.near.tee_signing import (  # noqa: E402
    OnChainCaller,
    OnChainTeeConfig,
    OnChainTeeError,
    OutLayerOnChainSigningProvider,
    build_signing_request,
)
from tracesettle.near.tee_signing.boundary import _b58  # noqa: E402
from tracesettle.near.txbuild import build_transfer  # noqa: E402

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "tracesettle"
    / "near"
    / "fixtures"
    / "onchain_tee_run.json"
)

REPLAY_NOTE = (
    "REPLAY — the enclave's answer and lifecycle events are the real 2026-11-07 OutLayer "
    "capture (tracesettle/near/fixtures/onchain_tee_run.json). The request builder, the digest "
    "rule and the refusal rules are the real code. No network call is made."
)

#: The caller's seed is a demo value. The *enclave's* key is the captured one; the
#: caller's key only signs the (here, replayed) request_execution call.
CALLER_SEED = bytes(range(32))
CALLER_PUBLIC = "ed25519:" + _b58(ed25519.public_key(CALLER_SEED))


def _capture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _recorded_request() -> dict:
    """The exact signing request the enclave was given, recovered from its event."""
    capture = _capture()
    event = capture["sign_transaction"]["events"]["execution_requested"]
    return json.loads(json.loads(event["request_data"])["input_data"])


def _rebuild_transaction():
    """Rebuild the live transaction from the recorded parameters with the product's builder."""
    recorded = _recorded_request()
    return build_transfer(
        network=NearNetwork.TESTNET,
        signer_id=recorded["signer_account"],
        public_key=recorded["public_key"],
        nonce=int(recorded["nonce"]),
        receiver_id=recorded["receiver_account"],
        block_hash=recorded["block_hash"],
        amount_human=Decimal(recorded["transfer_amount_yocto"]) / Decimal(10**24),
        service_id="m25-demo",
    )


def _recorded_sign_request(tx, capture):
    return build_signing_request(
        transaction=tx,
        authorization={
            "id": _capture()["sign_transaction"]["output"]["authorization_id"],
            "digest": "sha256:" + "00" * 32,
            "expiry": "2999-01-01T00:00:00+00:00",
            "policy_version": "m25-demo",
        },
        provider="outlayer:signing-keys-onchain",
        approved_build="sha256:" + capture["wasm_sha256"],
    )


class _ReplayRpc:
    """Answers from the capture; never opens a socket. Runs no enclave."""

    def __init__(self, capture: dict, *, tamper_digest: str | None = None):
        self._capture = capture
        self._tamper = tamper_digest

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        return RpcResult(SourceStatus.OK, data={"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1})

    def view_access_key(self, account_id: str, public_key: str) -> RpcResult:
        return RpcResult(SourceStatus.OK, data={"nonce": 100, "permission": "FullAccess"})

    def send_tx(self, signed_b64: str, *, wait_until: str = "INCLUDED_FINAL") -> RpcResult:
        output = dict(self._capture["sign_transaction"]["output"])
        if self._tamper:
            output["transaction_digest"] = self._tamper
        return RpcResult(
            SourceStatus.OK,
            data={
                "receipts_outcome": [
                    {
                        "outcome": {
                            "status": {
                                "SuccessValue": base64.b64encode(
                                    json.dumps(output).encode("utf-8")
                                ).decode("ascii")
                            },
                            "logs": [],
                        }
                    }
                ]
            },
        )


def _provider(rpc) -> OutLayerOnChainSigningProvider:
    capture = _capture()
    return OutLayerOnChainSigningProvider(
        caller=OnChainCaller(
            account_id="m25-demo.testnet",
            public_key=CALLER_PUBLIC,
            sign=lambda d: ed25519.sign(d, CALLER_SEED),
        ),
        config=OnChainTeeConfig(
            network="testnet",
            wasm_url="https://example.test/tracesettle-signing-module-wasm.wasm",
            wasm_sha256=capture["wasm_sha256"],
        ),
        rpc=rpc,
    )


def _check(name: str, fn):
    try:
        detail = fn() or ""
        return {"name": name, "passed": True, "detail": detail}
    except AssertionError as exc:
        return {"name": name, "passed": False, "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001 - a demo reports any failure
        return {"name": name, "passed": False, "detail": f"{type(exc).__name__}: {exc}"}


def run_all() -> list[dict]:
    capture = _capture()
    recorded = capture["sign_transaction"]["output"]
    checks: list[dict] = []

    # A. The product's serializer reproduces the live run's digest and hash.
    def _reproduces():
        tx = _rebuild_transaction()
        assert tx.payload_fingerprint() == recorded["transaction_digest"], (
            f"digest drift: {tx.payload_fingerprint()} != {recorded['transaction_digest']}"
        )
        assert tx.tx_hash == recorded["tx_hash"], f"hash drift: {tx.tx_hash} != {recorded['tx_hash']}"
        return f"{tx.tx_hash} reproduced from the recorded parameters"

    checks.append(_check("A the product rebuilds the live run's exact digest and hash", _reproduces))

    # B. A signature over that digest verifies, the way the provider checks one.
    def _signature_verifies():
        tx = _rebuild_transaction()
        digest = bytes.fromhex(tx.payload_fingerprint().split(":")[1])
        signature = ed25519.sign(digest, CALLER_SEED)
        assert ed25519.verify(signature, digest, ed25519.public_key(CALLER_SEED)), (
            "the signature does not verify over the rebuilt digest"
        )
        return "a signature over the rebuilt digest verifies under its key"

    checks.append(_check("B a signature over the rebuilt digest verifies", _signature_verifies))

    # C. The provider parses the captured answer and returns a verified result.
    def _provider_parses():
        tx = _rebuild_transaction()
        provider = _provider(_ReplayRpc(capture))
        result = provider.sign(_recorded_sign_request(tx, capture))
        assert result.transaction_digest == recorded["transaction_digest"], result.transaction_digest
        assert result.public_key == recorded["public_key"], result.public_key
        assert result.simulated is False
        assert result.build_hash == "sha256:" + capture["wasm_sha256"]
        return f"{result.public_key} → {result.build_hash}"

    checks.append(_check("C the provider parses the captured answer", _provider_parses))

    # D. A swapped digest is refused.
    def _swap_refused():
        tx = _rebuild_transaction()
        provider = _provider(_ReplayRpc(capture, tamper_digest="sha256:" + "11" * 32))
        try:
            provider.sign(_recorded_sign_request(tx, capture))
        except OnChainTeeError as exc:
            assert "different transaction digest" in str(exc), str(exc)
            return "a swapped digest is refused"
        raise AssertionError("a signature over a different digest was accepted")

    checks.append(_check("D a signature over a different digest is refused", _swap_refused))

    # E. The run's own cost and refund are reported honestly.
    def _cost():
        completed = capture["sign_transaction"]["events"]["execution_completed"]
        charged = int(completed["payment_charged"])
        refunded = int(completed["payment_refunded"])
        assert completed["success"] is True
        # The cost is a fraction of a NEAR; the rest of the deposit came back.
        assert 0 < charged < 10**22, charged
        assert refunded > charged, (charged, refunded)
        assert charged + refunded <= 10**24, (charged, refunded)
        return (
            f"charged {charged} yocto (~{charged / 10**24:.6f} NEAR), "
            f"refunded {refunded} yocto (free testnet NEAR)"
        )

    checks.append(_check("E the run's cost and refund are reported", _cost))

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="TRACESETTLE on-chain TEE signing demonstration")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    checks = run_all()
    passed = all(c["passed"] for c in checks)

    if args.json:
        print(json.dumps({"note": REPLAY_NOTE, "checks": checks, "all_passed": passed}, indent=2))
        return 0 if passed else 1

    print("=" * 78)
    print("TRACESETTLE — free on-chain TEE signing demonstration")
    print("=" * 78)
    print(REPLAY_NOTE)
    print()
    for c in checks:
        mark = "PASS" if c["passed"] else "FAIL"
        print(f"  [{mark}] {c['name']}")
        if c["detail"]:
            print(f"         {c['detail']}")
    print()
    print(f"{sum(c['passed'] for c in checks)}/{len(checks)} checks produced the expected outcome.")
    print("=" * 78)
    print("No OutLayer call was made. Nothing was broadcast. No key was requested.")
    print("=" * 78)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
