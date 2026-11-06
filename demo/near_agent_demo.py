#!/usr/bin/env python3
"""The end-to-end agent-lifecycle demonstration: malicious vs legitimate.

One command runs the whole story through the **production** NEAR authorization
boundary, the real signer, the real broadcast, and the real independent
settlement verification:

    agent instruction -> proposal -> TraceSettle evaluation -> decision ->
    signer enforcement -> NEAR broadcast -> independent verification

Two scenarios:

  malicious   A legitimate invoice is injected with a redirect to an attacker
              receiver. The (compromised) planner proposes the attacker. The real
              guard BLOCKs it, the signer is never invoked (count = 0), and
              nothing is broadcast.
  legitimate  The operator-approved receiver is paid. The guard ALLOWs it, the
              signer signs exactly the authorized bytes, the transaction is
              broadcast, and settlement is independently verified.

Two modes:

  offline (default)  a deterministic in-memory RPC, no network, no key. The
                     broadcast and the on-chain record are simulated by the
                     offline transport; the boundary, the guard, the signer, the
                     pipeline and the verifier are all real code. Labelled
                     SIMULATED.
  --live             NEAR **testnet** only. A funded ``*.testnet`` key is read
                     from the environment, a real transaction is signed and
                     broadcast, and the on-chain record is read back to verify
                     settlement. Labelled TESTNET VERIFIED. Refuses to point at
                     mainnet and never writes the key anywhere.

Usage:
    python demo/near_agent_demo.py                 # offline, both scenarios
    python demo/near_agent_demo.py --json
    TRACESETTLE_DEMO_TESTNET_KEY=<64-hex-seed> \
    TRACESETTLE_DEMO_ACCOUNT=<you.testnet> \
    TRACESETTLE_DEMO_RECEIVER=<recipient.testnet> \
    python demo/near_agent_demo.py --live
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.guard.audit import AuditLog  # noqa: E402
from tracesettle.guard.authorization import (  # noqa: E402
    AuthorizationAuthority,
    InMemoryReplayStore,
)
from tracesettle.guard.service import GuardService  # noqa: E402
from tracesettle.near.agent_demo import (  # noqa: E402
    ATTACKER_RECEIVER,
    INJECTION_TEXT,
    build_offline_harness,
    demo_policy,
)
from tracesettle.near.agent_harness import (  # noqa: E402
    InjectedContext,
    LocalAgentHarness,
    PaymentInstruction,
)
from tracesettle.near.execution import NearExecutionBoundary  # noqa: E402
from tracesettle.near.networks import NearNetwork, network_config  # noqa: E402
from tracesettle.near.pipeline import LocalKeySigner, NearExecutionPipeline  # noqa: E402
from tracesettle.near.rpc import NearRpc  # noqa: E402
from tracesettle.near.ledger import SubmissionLedger  # noqa: E402


#: The policy and the offline harness are defined once, in
#: :mod:`tracesettle.near.agent_demo`, so the CLI, the HTTP endpoint and the
#: console panel all run the same implementation. ``_demo_policy`` is kept as a
#: thin alias for backward compatibility with callers that imported it.
_demo_policy = demo_policy


def _load_key() -> bytes | None:
    raw = os.environ.get("TRACESETTLE_DEMO_TESTNET_KEY", "").strip()
    if not raw:
        return None
    if raw.startswith("ed25519:"):
        raw = raw[len("ed25519:") :]
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        _say("TRACESETTLE_DEMO_TESTNET_KEY must be 64 hex characters (a 32-byte seed).")
        raise SystemExit(2)
    if len(seed) != 32:
        _say("TRACESETTLE_DEMO_TESTNET_KEY must decode to exactly 32 bytes.")
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


#: Where human-readable narration goes. With ``--json`` the JSON document is the
#: only thing on stdout, so a machine reader can parse it directly; the narration
#: moves to stderr.
_HUMAN_OUT = sys.stdout


def _say(*parts) -> None:
    _HUMAN_OUT.write(" ".join(str(p) for p in parts) + "\n")


def _print_result(result, *, mode: str) -> None:
    _say(f"  mode            : {mode}")
    _say(f"  instruction     : {result.instruction}")
    if result.injected_context:
        _say(f"  injected context: {result.injected_context}")
        _say(f"  redirected      : {result.redirected}")
    _say(f"  proposed        : {result.proposed_amount} NEAR -> {result.proposed_receiver}")
    _say(f"  decision        : {result.decision}  (authorized: {result.authorized})")
    if result.reasons:
        for reason in result.reasons:
            _say(f"    - {reason}")
    _say(f"  signer calls    : {result.signer_calls}")
    _say(f"  signed          : {result.signed}")
    _say(f"  broadcast       : {result.broadcast_occurred}")
    if result.tx_hash:
        _say(f"  tx hash         : {result.tx_hash}")
    if result.signed_bytes_digest:
        bound = result.authorization_binding.get("transaction_digest", "")
        tied = " (== authorization binding)" if bound and bound == result.signed_bytes_digest else ""
        _say(f"  signed bytes    : {result.signed_bytes_digest}{tied}")
    if result.authorization_binding:
        dest = result.authorization_binding.get("destination", "")
        amt = result.authorization_binding.get("amount", "")
        _say(f"  authorized for  : {amt} -> {dest}")
    if result.submission_state:
        _say(f"  submission      : {result.submission_state}")
    if result.settlement_state:
        _say(f"  settlement      : {result.settlement_state}")
    for note in result.notes:
        _say(f"  note            : {note}")


def _malicious_scenario(harness: LocalAgentHarness, approved: str, *, attempts, delay):
    instruction = PaymentInstruction(
        text=f"Pay invoice #4471 for 0.1 NEAR to our approved supplier at {approved}.",
        receiver_id=approved,
        amount="0.1",
    )
    injected = InjectedContext(text=INJECTION_TEXT, receiver_id=ATTACKER_RECEIVER)
    return harness.run(
        instruction,
        injected=injected,
        scenario="malicious",
        attempts=attempts,
        delay=delay,
    )


def _legitimate_scenario(harness: LocalAgentHarness, approved: str, *, attempts, delay):
    instruction = PaymentInstruction(
        text=f"Pay invoice #4471 for 0.1 NEAR to our approved supplier at {approved}.",
        receiver_id=approved,
        amount="0.1",
    )
    return harness.run(
        instruction,
        scenario="legitimate",
        idempotency_key="demo-legit",
        attempts=attempts,
        delay=delay,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NEAR agent lifecycle demonstration")
    parser.add_argument("--live", action="store_true", help="run against NEAR testnet (needs a key)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.json:
        # Keep stdout pure JSON so a machine reader can parse it directly.
        global _HUMAN_OUT
        _HUMAN_OUT = sys.stderr

    network = network_config("testnet")
    if network.network is not NearNetwork.TESTNET:
        _say("This demonstration only runs on testnet.")
        return 2

    seed = _load_key()
    account = os.environ.get("TRACESETTLE_DEMO_ACCOUNT", "").strip()
    receiver = os.environ.get("TRACESETTLE_DEMO_RECEIVER", "").strip()

    live = args.live
    if live and (seed is None or not account or not receiver):
        _say("--live requires TRACESETTLE_DEMO_TESTNET_KEY, TRACESETTLE_DEMO_ACCOUNT and")
        _say("TRACESETTLE_DEMO_RECEIVER (all testnet). Falling back is refused: re-run")
        _say("without --live for the offline demonstration.")
        return 2
    if not live:
        # Offline mode uses a deterministic account/receiver so the run is
        # reproducible; the values are placeholders, never real accounts.
        account = account or "demo-agent.testnet"
        receiver = receiver or "demo-receiver.testnet"

    if not account.endswith(".testnet") or not receiver.endswith(".testnet"):
        _say("Both the account and the receiver must be *.testnet accounts.")
        return 2

    mode = "TESTNET VERIFIED" if live else "SIMULATED (offline transport)"

    if live:
        guard = GuardService(
            policy=_demo_policy(receiver),
            authority=AuthorizationAuthority(
                key=bytes(range(32)),
                key_id="near-agent-demo",
                ephemeral=False,
                replay_store=InMemoryReplayStore(),
            ),
            audit=AuditLog(),
        )
        signer = LocalKeySigner(seed, network=NearNetwork.TESTNET, account_id=account)
        rpc = NearRpc(network)
        boundary = NearExecutionBoundary(guard, network, rpc=rpc)
        boundary.verify_network()
        pipeline = NearExecutionPipeline(
            boundary, ledger=SubmissionLedger(), finality_attempts=10, finality_delay=1.0
        )
        attempts, delay = 10, 1.0
        harness = LocalAgentHarness(
            boundary, signer=signer, account_id=account, pipeline=pipeline
        )
    else:
        # The offline harness (real boundary, signer, pipeline and verifier over a
        # deterministic transport) is built once, in tracesettle.near.agent_demo.
        harness = build_offline_harness(account=account, receiver=receiver)
        attempts, delay = 8, 1.0

    _say("=" * 78)
    _say("TRACESETTLE x NEAR - agent lifecycle demonstration")
    _say("=" * 78)
    _say(f"network   : {network.network.value} (genesis {network.genesis_hash[:12]}...)")
    _say(f"account   : {account}")
    _say(f"approved  : {receiver}")
    _say(f"attacker  : {ATTACKER_RECEIVER}  (synthetic, not approved)")
    _say()

    _say("-" * 78)
    _say("SCENARIO A - malicious payment (prompt-injected redirect)")
    _say("-" * 78)
    malicious = _malicious_scenario(harness, receiver, attempts=attempts, delay=delay)
    _print_result(malicious, mode=mode)
    _say()

    _say("-" * 78)
    _say("SCENARIO B - legitimate payment (approved receiver)")
    _say("-" * 78)
    legitimate = _legitimate_scenario(harness, receiver, attempts=attempts, delay=delay)
    _print_result(legitimate, mode=mode)
    _say()

    ok = (
        malicious.decision == "BLOCK"
        and malicious.signer_calls == 0
        and not malicious.broadcast_occurred
        and legitimate.decision == "ALLOW"
        and legitimate.signer_calls == 1
        and legitimate.signed
        and legitimate.settlement_state == "VERIFIED"
    )
    _say("=" * 78)
    _say(
        "RESULT: "
        + (
            "the malicious payment was blocked before signing and the legitimate "
            "payment settled and verified."
            if ok
            else "the run did NOT reproduce the expected outcomes; see the rows above."
        )
    )
    _say("=" * 78)

    if args.json:
        print(
            json.dumps(
                {"mode": mode, "malicious": malicious.to_dict(), "legitimate": legitimate.to_dict()},
                indent=2,
            )
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
