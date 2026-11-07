#!/usr/bin/env python3
"""Deterministic demonstration: recovery verifies a transaction from its bytes.

This shows one security property of the real execution pipeline with no network:
a submission whose outcome is unknown is recorded durably, and when the chain
later knows it, the *exact* transaction is re-derived from the signed bytes that
were broadcast - so recovery verifies the amount and the recipient, not merely
the hash and finality.

The pipeline, the transaction builder, the guard, the durable ledger, the
``SignedTransaction`` decoder and the settlement verifier are the real code
paths. The only substitution is the RPC transport, exactly as the test suite
substitutes it. Nothing is signed for a chain and nothing is broadcast.

Usage:
    python demo/near_recovery_demo.py            # human-readable
    python demo/near_recovery_demo.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.guard.authorization import (  # noqa: E402
    AuthorizationAuthority,
    InMemoryReplayStore,
)
from tracesettle.guard.policy import PolicyConfig, ServicePolicy  # noqa: E402
from tracesettle.guard.service import GuardService  # noqa: E402
from tracesettle.model import SourceStatus  # noqa: E402
from tracesettle.near import ed25519  # noqa: E402
from tracesettle.near.execution import NearExecutionBoundary  # noqa: E402
from tracesettle.near.ledger import SubmissionLedger, SubmissionState  # noqa: E402
from tracesettle.near.networks import NETWORKS, NearNetwork  # noqa: E402
from tracesettle.near.pipeline import NearExecutionPipeline  # noqa: E402
from tracesettle.near.rpc import RpcResult  # noqa: E402
from tracesettle.near.txbuild import _b58encode  # noqa: E402
from tracesettle.near.verify import SettlementState  # noqa: E402

SEED = bytes(range(32))
PUBLIC = ed25519.public_key(SEED)
PUBLIC_KEY = "ed25519:" + _b58encode(PUBLIC)
SIGNER = "agent.testnet"
RECIPIENT = "alice.testnet"

SIMULATION_NOTE = (
    "Controlled demonstration: the RPC transport is a deterministic stand-in; the "
    "pipeline, the guard, the durable ledger, the signed-bytes decoder and the "
    "settlement verifier are the real code paths. No transaction is broadcast."
)


class _OfflineRpc:
    """A deterministic RPC transport: send times out, tx_status is controllable."""

    def __init__(self, config) -> None:
        self.config = config
        self.broadcasts: list[str] = []
        self.status_result: dict | None = None

    def status(self):
        return RpcResult(
            SourceStatus.OK,
            {"chain_id": self.config.chain_id, "genesis_hash": self.config.genesis_hash},
        )

    def block_hash(self, *, finality="final"):
        return RpcResult(
            SourceStatus.OK,
            {"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1},
        )

    def view_access_key(self, account_id, public_key):
        return RpcResult(SourceStatus.OK, {"nonce": 1, "permission": "FullAccess"})

    def call_function(self, account_id, method_name, args=None, *, finality="final"):
        return RpcResult(SourceStatus.OK, {"decimals": 24})

    def send_tx(self, signed_transaction_b64, *, wait_until="INCLUDED_FINAL"):
        # The outcome is genuinely unknown: the node timed out.
        self.broadcasts.append(signed_transaction_b64)
        return RpcResult(SourceStatus.TIMEOUT, None, error="connection timed out")

    def tx_status(self, tx_hash, sender_account_id):
        if self.status_result is None:
            return RpcResult(SourceStatus.NOT_FOUND, None, error="unknown transaction")
        return RpcResult(SourceStatus.OK, self.status_result)


def _policy() -> PolicyConfig:
    return PolicyConfig(
        policy_id="recovery-demo",
        name="recovery demo",
        version="1",
        approved_destinations=frozenset({RECIPIENT}),
        services={
            "svc": ServicePolicy(
                service_id="svc",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"near-testnet"}),
                allowed_assets=frozenset({"NEAR:NATIVE"}),
                max_amount_per_transaction=Decimal("100"),
                approval_threshold=Decimal("1000"),
            )
        },
        per_transaction_limit=Decimal("100"),
        approval_threshold=Decimal("1000"),
        allow_unlisted_destinations=False,
    )


def _drive(amount: str = "1"):
    """Prepare and submit one operation, leaving an UNKNOWN submission behind."""
    config = NETWORKS[NearNetwork.TESTNET]
    guard = GuardService(
        policy=_policy(),
        authority=AuthorizationAuthority(
            key=b"demo-key", key_id="demo", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )
    rpc = _OfflineRpc(config)
    boundary = NearExecutionBoundary(guard, config, rpc=rpc)
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger())
    prepared = boundary.prepare(
        service_id="svc",
        account_id=SIGNER,
        public_key=PUBLIC_KEY,
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human=amount,
    )

    class _Signer:
        public_key = PUBLIC_KEY

        def sign(self, message):
            return ed25519.sign(message, SEED)

    result = pipeline.execute(prepared, _Signer())
    return pipeline, prepared, rpc, result


def _tx_status_result(prepared, finality: str = "FINAL") -> dict:
    return {
        "final_execution_status": finality,
        "status": {"SuccessValue": ""},
        "transaction": {
            "hash": prepared.transaction.tx_hash,
            "signer_id": prepared.transaction.signer_id,
            "receiver_id": prepared.transaction.receiver_id,
            "nonce": prepared.transaction.nonce,
            "actions": [{"Transfer": {"deposit": str(prepared.transaction.amount_base)}}],
        },
        "transaction_outcome": {"outcome": {"logs": []}},
        "receipts_outcome": [],
    }


def run_all() -> list[dict]:
    checks: list[dict] = []

    pipeline, prepared, rpc, result = _drive()
    tx_hash = prepared.transaction.tx_hash

    checks.append(
        {
            "name": "A the timed-out submission is recorded UNKNOWN, never FAILED",
            "passed": result.state == SubmissionState.UNKNOWN,
            "detail": f"state={result.state}",
        }
    )
    checks.append(
        {
            "name": "B exactly one submission was attempted (no blind retry)",
            "passed": len(rpc.broadcasts) == 1,
            "detail": f"broadcasts={len(rpc.broadcasts)}",
        }
    )

    record = pipeline.ledger.get(tx_hash)
    checks.append(
        {
            "name": "C the exact signed bytes are durable in the ledger",
            "passed": bool(record and record.signed_b64),
            "detail": f"bytes={len(record.signed_b64) if record else 0} base64 chars",
        }
    )

    # The chain now knows the transaction and it is final. Resolve it *without*
    # the original prepared operation - the situation after a restart.
    rpc.status_result = _tx_status_result(prepared)
    resolved = pipeline.resolve_unknown(tx_hash)
    checks.append(
        {
            "name": "D recovery reconstructs the transaction from its bytes and VERIFIES",
            "passed": resolved is not None
            and resolved.settlement_state == SettlementState.VERIFIED.value,
            "detail": f"settlement={resolved.settlement_state if resolved else 'none'}",
        }
    )
    checks.append(
        {
            "name": "E recovery re-checked the amount and recipient, not just the hash",
            "passed": resolved is not None and bool(resolved.verification)
            and resolved.verification.all_ok,
            "detail": "all semantic checks passed"
            if resolved is not None and resolved.verification and resolved.verification.all_ok
            else "a check did not pass",
        }
    )
    checks.append(
        {
            "name": "F recovery never broadcast anything again",
            "passed": len(rpc.broadcasts) == 1,
            "detail": f"broadcasts={len(rpc.broadcasts)}",
        }
    )

    # Contrast: bytes that do not decode faithfully must never inflate the verdict.
    pipeline2, prepared2, rpc2, _ = _drive()
    record2 = pipeline2.ledger.get(prepared2.transaction.tx_hash)
    raw = bytearray(base64.b64decode(record2.signed_b64))
    raw[40] ^= 0x01
    record2.signed_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    pipeline2.ledger.put(record2)
    rpc2.status_result = _tx_status_result(prepared2)
    fallback = pipeline2.resolve_unknown(prepared2.transaction.tx_hash)
    checks.append(
        {
            "name": "G unreadable bytes fall back to CONFIRMED and are never inflated to VERIFIED",
            "passed": fallback is not None
            and fallback.settlement_state == SettlementState.CONFIRMED.value,
            "detail": f"settlement={fallback.settlement_state if fallback else 'none'}",
        }
    )

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="TRACESETTLE recovery-verification demonstration")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    checks = run_all()
    passed = all(c["passed"] for c in checks)

    if args.json:
        print(json.dumps({"note": SIMULATION_NOTE, "checks": checks, "all_passed": passed}, indent=2))
        return 0 if passed else 1

    print("=" * 78)
    print("TRACESETTLE — recovery verification from durable signed bytes")
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
    print("No transaction was broadcast. No key material is stored or printed.")
    print("=" * 78)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
