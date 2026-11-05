#!/usr/bin/env python3
"""Live NEAR testnet pipeline: TEE-gated signing, real submission, real receipts.

This drives the *real* execution pipeline
(:class:`tracesettle.near.pipeline.NearExecutionPipeline`) end to end against
NEAR testnet:

  1. verify the network identity against the RPC;
  2. build the real transaction and evaluate it with the operator policy;
  3. fetch and locally verify a genuine Intel TDX attestation, bound to the
     exact bytes to be signed (the TEE gate);
  4. sign with a **testnet** key supplied through an environment variable;
  5. submit to NEAR testnet;
  6. independently verify settlement from the on-chain record;
  7. persist the submission in a durable ledger.

The pipeline refuses to sign if any precondition fails, and it never resubmits a
transaction whose submission outcome is unknown. It is testnet-only and refuses
to point at mainnet. The key is read only to sign; it is never logged or stored.

Usage:
    export TRACESETTLE_DEMO_TESTNET_KEY=<64-hex-ed25519-secret>   # testnet only
    export TRACESETTLE_DEMO_ACCOUNT=your-account.testnet
    export TRACESETTLE_DEMO_RECEIVER=recipient.testnet
    python demo/near_pipeline_demo.py

Without the key the script prints exactly what it would do and exits 0, so it is
safe to run anywhere.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.guard.audit import AuditLog  # noqa: E402
from tracesettle.guard.authorization import (  # noqa: E402
    AuthorizationAuthority,
    InMemoryReplayStore,
)
from tracesettle.guard.policy import PolicyConfig, ServicePolicy  # noqa: E402
from tracesettle.guard.service import GuardService  # noqa: E402
from tracesettle.near.attestation import TeeAttestationProvider  # noqa: E402
from tracesettle.near.execution import ExecutionError, NearExecutionBoundary  # noqa: E402
from tracesettle.near.ledger import SubmissionLedger  # noqa: E402
from tracesettle.near.networks import NearNetwork, network_config  # noqa: E402
from tracesettle.near.pipeline import (  # noqa: E402
    LocalKeySigner,
    NearExecutionPipeline,
    SigningError,
)
from tracesettle.near.rpc import NearRpc  # noqa: E402
from tracesettle.near.tee_execution import (  # noqa: E402
    ExecutionRecordStore,
    TeeExecutionAuthorizer,
)


def _demo_policy(receiver: str) -> PolicyConfig:
    return PolicyConfig(
        policy_id="near-testnet-pipeline",
        name="NEAR testnet pipeline policy",
        version="1",
        approved_destinations=frozenset({receiver}),
        services={
            "demo-agent": ServicePolicy(
                service_id="demo-agent",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"near-testnet"}),
                allowed_assets=frozenset({"NEAR:NATIVE"}),
                max_amount_per_transaction=Decimal("0.1"),
                max_amount_per_window=Decimal("1"),
                approval_threshold=Decimal("0.05"),
            )
        },
        per_transaction_limit=Decimal("0.1"),
        window_seconds=3600,
        max_requests_per_window=10,
        max_blocked_per_window=3,
        approval_threshold=Decimal("0.05"),
        min_approvals=1,
        max_rejected_authorizations=3,
        authorization_ttl_seconds=90,
        allow_unlisted_destinations=False,
    )


def _load_key() -> bytes | None:
    raw = os.environ.get("TRACESETTLE_DEMO_TESTNET_KEY", "").strip()
    if not raw:
        return None
    if raw.startswith("ed25519:"):
        raw = raw[len("ed25519:") :]
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        print("TRACESETTLE_DEMO_TESTNET_KEY must be 64 hex characters (a 32-byte seed).")
        raise SystemExit(2)
    if len(seed) != 32:
        print("TRACESETTLE_DEMO_TESTNET_KEY must decode to exactly 32 bytes.")
        raise SystemExit(2)
    return seed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live NEAR testnet pipeline demonstration")
    parser.add_argument("--amount", default="0.01", help="NEAR to transfer (default 0.01)")
    parser.add_argument(
        "--no-tee",
        action="store_true",
        help="disable the TEE gate (software signing only); the default is TEE-gated",
    )
    parser.add_argument(
        "--ledger",
        default="",
        help="path to a SQLite ledger (default: in-memory)",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON evidence block")
    args = parser.parse_args(argv)

    network = network_config("testnet")
    if network.network is not NearNetwork.TESTNET:
        print("This demonstration only runs on testnet.")
        return 2

    seed = _load_key()
    account = os.environ.get("TRACESETTLE_DEMO_ACCOUNT", "").strip()
    receiver = os.environ.get("TRACESETTLE_DEMO_RECEIVER", "").strip()

    if seed is None or not account or not receiver:
        print("No testnet key/account/receiver supplied, so nothing is signed or broadcast.")
        print()
        print("To run the live demonstration, provide a *testnet* key:")
        print("  export TRACESETTLE_DEMO_TESTNET_KEY=<64-hex-ed25519-secret>")
        print("  export TRACESETTLE_DEMO_ACCOUNT=<your-account.testnet>")
        print("  export TRACESETTLE_DEMO_RECEIVER=<recipient.testnet>")
        print("  python demo/near_pipeline_demo.py")
        print()
        print("The key is used only to sign one testnet transaction and is never stored.")
        return 0

    if not account.endswith(".testnet") or not receiver.endswith(".testnet"):
        print("Both the account and the receiver must be *.testnet accounts.")
        return 2

    signer = LocalKeySigner(seed, network=NearNetwork.TESTNET, account_id=account)
    guard = GuardService(
        policy=_demo_policy(receiver),
        authority=AuthorizationAuthority(
            key=os.urandom(32), key_id="demo", ephemeral=True, replay_store=InMemoryReplayStore()
        ),
        audit=AuditLog(),
    )

    tee_authorizer = None
    tee_provider = None
    if not args.no_tee:
        tee_authorizer = TeeExecutionAuthorizer(
            store=ExecutionRecordStore(),
            require_attestation=True,
            expected_measurement="",
            ttl_seconds=90,
        )
        tee_provider = TeeAttestationProvider()

    boundary = NearExecutionBoundary(
        guard,
        network,
        rpc=NearRpc(network),
        tee_authorizer=tee_authorizer,
        tee_provider=tee_provider,
    )
    ledger = SubmissionLedger(args.ledger or None)
    pipeline = NearExecutionPipeline(boundary, ledger=ledger)

    print("=" * 78)
    print("TRACESETTLE x NEAR - live testnet pipeline (TEE-gated signing)")
    print("=" * 78)
    print(f"network   : {network.network.value} (genesis {network.genesis_hash[:12]}...)")
    print(f"account   : {account}")
    print(f"receiver  : {receiver}")
    print(f"amount    : {args.amount} NEAR")
    print(f"TEE gate  : {'on' if tee_authorizer else 'off (software signing only)'}")
    print(f"ledger    : {ledger.backend}")
    print()

    # 1. Build + authorize.
    try:
        prepared = boundary.prepare(
            service_id="demo-agent",
            account_id=account,
            public_key=signer.public_key,
            receiver_id=receiver,
            asset_identifier="near:native",
            amount_human=args.amount,
        )
    except ExecutionError as exc:
        print(f"1. prepare refused: {exc}")
        return 1
    print(f"1. decision: {prepared.decision.decision.value}  (authorized: {prepared.authorized})")
    print(f"   tx hash : {prepared.transaction.tx_hash}")
    print(f"   nonce   : {prepared.transaction.nonce}")
    if not prepared.authorized:
        print("   the policy did not authorize this transfer; nothing to sign.")
        return 0

    # 2. TEE attestation bound to the exact bytes to be signed.
    if tee_authorizer is not None:
        try:
            boundary.verify_tee_attestation(prepared)
        except ExecutionError as exc:
            print(f"2. TEE attestation refused: {exc}")
            return 1
        print("2. TEE attestation fetched, verified locally, and bound to the transaction")
        print(f"   execution id: {prepared.execution_id}")
    else:
        print("2. TEE gate disabled: signing proceeds without an attestation (not hardware-protected)")

    # 3-6. Sign, submit, verify - through the real pipeline.
    try:
        result = pipeline.execute(prepared, signer)
    except SigningError as exc:
        print(f"3. signing refused: {exc}")
        return 1
    print(f"3. signed and submitted; tx hash {result.tx_hash}")
    print(f"   explorer: {network.explorer_url(result.tx_hash)}")
    print(f"4. submission state: {result.state}")
    print(f"5. independent settlement state: {result.settlement_state}")
    if result.verification is not None:
        for check in result.verification.checks:
            mark = "ok " if check.ok else "FAIL"
            print(f"     [{mark}] {check.name}: {check.detail}")
    print(f"6. ledger record persisted: {ledger.backend}")

    if args.json:
        print()
        print(json.dumps({
            "tx_hash": result.tx_hash,
            "explorer_url": network.explorer_url(result.tx_hash),
            "state": result.state,
            "settlement_state": result.settlement_state,
            "tee_gated": tee_authorizer is not None,
            "execution_id": prepared.execution_id,
        }, indent=2))

    print()
    print("The pipeline signs and broadcasts a real *testnet* transaction only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
