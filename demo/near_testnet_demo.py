#!/usr/bin/env python3
"""Live NEAR testnet demonstration: a real transaction, end to end.

This is the demonstration that closes the gap between "the guard decides" and
"the chain agrees". It:

  1. reads the real network status and verifies the genesis hash;
  2. builds a real NEAR transaction (Borsh-serialized) from validated inputs;
  3. evaluates it with the operator policy (the real guard);
  4. signs it with a **testnet** key supplied through an environment variable;
  5. broadcasts it to NEAR testnet;
  6. independently verifies settlement against the authorized transaction.

It never uses a mainnet key. It refuses to run unless
``TRACESETTLE_DEMO_TESTNET_KEY`` is set, and it refuses to point at mainnet. The
key is read only to sign one demonstration transaction; it is never logged,
stored, or returned. Nothing here is a production path: the production boundary
never holds a key at all (a wallet signs).

Usage:
    export TRACESETTLE_DEMO_TESTNET_KEY=<64-hex-ed25519-secret>   # testnet only
    export TRACESETTLE_DEMO_ACCOUNT=your-account.testnet
    export TRACESETTLE_DEMO_RECEIVER=recipient.testnet
    python demo/near_testnet_demo.py

Without the key the script prints exactly what it would do and exits 0, so it is
safe to run anywhere.
"""

from __future__ import annotations

import argparse
import base64
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
from tracesettle.near import ed25519  # noqa: E402
from tracesettle.near.execution import ExecutionError, NearExecutionBoundary  # noqa: E402
from tracesettle.near.networks import NearNetwork, network_config  # noqa: E402
from tracesettle.near.rpc import NearRpc  # noqa: E402


def _demo_policy(receiver: str) -> PolicyConfig:
    """A restrictive demonstration policy for one testnet recipient."""
    return PolicyConfig(
        policy_id="near-testnet-demo",
        name="NEAR testnet demonstration policy",
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


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live NEAR testnet demonstration")
    parser.add_argument("--amount", default="0.01", help="NEAR to transfer (default 0.01)")
    args = parser.parse_args(argv)

    network = network_config("testnet")
    if network.network is not NearNetwork.TESTNET:
        print("This demonstration only runs on testnet.")
        return 2

    seed = _load_key()
    account = os.environ.get("TRACESETTLE_DEMO_ACCOUNT", "").strip()
    receiver = os.environ.get("TRACESETTLE_DEMO_RECEIVER", "").strip()

    print("=" * 78)
    print("TRACESETTLE x NEAR - live testnet execution demonstration")
    print("=" * 78)
    print(f"network   : {network.network.value} (genesis {network.genesis_hash[:12]}...)")
    print(f"amount    : {args.amount} NEAR")
    print()

    if seed is None or not account or not receiver:
        print("No testnet key/account/receiver supplied, so nothing is signed or broadcast.")
        print()
        print("To run the live demonstration, provide a *testnet* key:")
        print("  export TRACESETTLE_DEMO_TESTNET_KEY=<64-hex-ed25519-secret>")
        print("  export TRACESETTLE_DEMO_ACCOUNT=<your-account.testnet>")
        print("  export TRACESETTLE_DEMO_RECEIVER=<recipient.testnet>")
        print("  python demo/near_testnet_demo.py")
        print()
        print("The key is used only to sign one testnet transaction and is never stored.")
        return 0

    if not account.endswith(".testnet") or not receiver.endswith(".testnet"):
        print("Both the account and the receiver must be *.testnet accounts.")
        return 2

    public_key = "ed25519:" + _b58(ed25519.public_key(seed))
    guard = GuardService(
        policy=_demo_policy(receiver),
        authority=AuthorizationAuthority(
            key=os.urandom(32), key_id="demo", ephemeral=True, replay_store=InMemoryReplayStore()
        ),
        audit=AuditLog(),
    )
    boundary = NearExecutionBoundary(guard, network, rpc=NearRpc(network))

    # 1. Verify the network identity before building anything.
    try:
        boundary.verify_network()
    except ExecutionError as exc:
        print(f"network check failed: {exc}")
        return 1
    print("1. network identity verified against the RPC")

    # 2. Build + authorize.
    try:
        prepared = boundary.prepare(
            service_id="demo-agent",
            account_id=account,
            public_key=public_key,
            receiver_id=receiver,
            asset_identifier="near:native",
            amount_human=args.amount,
        )
    except ExecutionError as exc:
        print(f"2. prepare refused: {exc}")
        return 1
    print(f"2. decision: {prepared.decision.decision.value}  (authorized: {prepared.authorized})")
    print(f"   tx hash : {prepared.transaction.tx_hash}")
    print(f"   nonce   : {prepared.transaction.nonce}   block: {prepared.transaction.block_hash[:12]}...")
    if not prepared.authorized:
        print("   the policy did not authorize this transfer; nothing to sign.")
        return 0

    # 3. Sign (the wallet's job; here the testnet key stands in).
    signature = base64.b64encode(
        ed25519.sign(prepared.transaction.tx_hash_bytes, seed)
    ).decode()
    print("3. signed with the supplied testnet key")

    # 4. Broadcast + independently verify.
    try:
        executed = boundary.broadcast(prepared, signature)
    except ExecutionError as exc:
        print(f"4. broadcast refused: {exc}")
        return 1
    print(f"4. broadcast submitted; tx hash {executed.tx_hash}")
    print(f"   explorer: {network.explorer_url(executed.tx_hash)}")

    # 5. Wait (bounded) for finality, then report the verified state.
    verification = boundary.wait_for_final(prepared)
    print(f"5. independent settlement state: {verification.state.value}")
    for check in verification.checks:
        mark = "ok " if check.ok else "FAIL"
        print(f"     [{mark}] {check.name}: {check.detail}")
    print()
    print("The demonstration signs and broadcasts a real *testnet* transaction only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
