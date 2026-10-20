#!/usr/bin/env python3
"""TRACESETTLE demonstration: verified, incomplete, and refund cases.

This is a read-only walkthrough. It runs three investigations through the real
adapter/engine/report code paths:

  1. A real, independently verified ETH->USDC swap, showing all four confirmed
     stages and their decisive evidence, ending in SETTLED_VERIFIED.
  2. An intent-hash-only lookup, which cannot reach the whole path. It shows the
     tool refusing to overstate what it can establish.
  3. A real, refunded Bitcoin->TRON swap. It shows the tool confirming the
     Bitcoin refund from the on-chain payout when the sources are reachable, and
     otherwise keeping REPORTED, MISSING and UNAVAILABLE distinct.

The live cases use public endpoints when they are reachable. If the network is
unavailable, the script says so plainly and does not fabricate a result. Nothing
here signs, submits, or moves funds, and no key is requested.

Usage:
    python3 demo/demonstrate.py            # query live public endpoints
    python3 demo/demonstrate.py --offline  # replay captured fixtures (no network)

The ``--offline`` mode substitutes only the network transport, replaying the real
Phase 1 captures from ``evidence/raw/`` through the same adapter and engine code.
It is labelled as a replay and never presented as a live query; a replay cannot
show that an endpoint is answering right now.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tracesettle.httpclient import HttpClient  # noqa: E402
from tracesettle.investigation import build_result, investigate  # noqa: E402
from tracesettle.model import Stage, StageState  # noqa: E402

#: The real swap audited in Phase 1/Phase 3: a completed ETH -> USDC settlement.
VERIFIED_DEPOSIT_ADDRESS = "0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"
#: The intent hash of that same swap. On its own it can only reach the service
#: statement, because no reverse lookup from intent hash to deposit address exists.
INCOMPLETE_INTENT_HASH = "7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG"
#: A real refunded swap (BTC origin -> TRON destination) found on the public
#: NEAR Intents explorer. The Bitcoin origin chain has a configured public source,
#: so the refund can be confirmed from the on-chain payout when it is reachable.
REFUNDED_DEPOSIT_ADDRESS = "bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm"

RULE = "=" * 78


def _show(result) -> None:
    last = result.last_confirmed_stage.value if result.last_confirmed_stage else "none"
    print(f"outcome          : {result.outcome.value}")
    print(f"last confirmed   : {last}")
    print("stages:")
    for stage in (
        Stage.SOURCE_CHAIN_DEPOSIT,
        Stage.BRIDGE_DEPOSIT_CREDIT,
        Stage.NEAR_SETTLEMENT,
        Stage.DESTINATION_CHAIN_DELIVERY,
        Stage.REFUND,
    ):
        print(f"  {stage.value:28s} {result.stage(stage).state.value}")


#: The one event type that can confirm each stage (mirrors the engine's rule).
DECISIVE = {
    Stage.SOURCE_CHAIN_DEPOSIT: "SOURCE_TX_EXECUTED",
    Stage.BRIDGE_DEPOSIT_CREDIT: "DEPOSIT_OBSERVED",
    Stage.NEAR_SETTLEMENT: "INTENT_EVENT_OBSERVED",
    Stage.DESTINATION_CHAIN_DELIVERY: "DESTINATION_TRANSFER_OBSERVED",
}


def _decisive_evidence(inv, stage: Stage) -> None:
    """Print the single piece of evidence that actually confirms a stage."""
    wanted = DECISIVE[stage]
    for item in inv.evidence:
        if (
            item.stage is stage
            and item.event_type.value == wanted
            and item.verification.value == "CONFIRMED"
        ):
            print(f"    {item.event_type.value} [{item.source}]")
            if item.tx_hash:
                print(f"      tx: {item.tx_hash}")
            if item.evidence_url:
                print(f"      url: {item.evidence_url}")
            if item.limitations:
                print(f"      limits: {item.limitations[0]}")
            return


def _explain_refund(result3, inv3) -> None:
    """Explain the refund outcome from the evidence actually observed.

    The explanation must not assert how the payout was found: whether the
    provider named the refund transaction or the tool had to locate it from the
    refund address's history is read back from the confirmed evidence item. A
    hardcoded claim here would go stale the moment the upstream record changes.
    """
    refund_state = result3.stage(Stage.REFUND).state
    confirmed = [
        e
        for e in inv3.evidence
        if e.stage is Stage.REFUND
        and e.verification.value == "CONFIRMED"
        and e.tx_hash
    ]
    if refund_state is StageState.CONFIRMED and confirmed:
        discovery = confirmed[0].details.get("discovery")
        if discovery == "explicit":
            found = "the provider named the refund transaction, and the tool validated it"
        else:
            found = (
                "the provider named no refund transaction, so the payout was located from\n"
                "  the refund address's own confirmed history"
            )
        print(
            f"\n  The refund is independently confirmed: a confirmed Bitcoin transaction pays\n"
            f"  the address recorded on-chain for this intent's withdrawal. Here, {found}.\n"
            "  The amount reported by the service and the amount observed on-chain are both\n"
            "  stated; any difference is disclosed, not reconciled."
        )
    elif result3.outcome.value == "REFUND_REPORTED_UNVERIFIED":
        print(
            "\n  A refund is reported by the upstream service, but it is not independently\n"
            "  confirmed, so it stays a reported claim. The tool keeps the states apart: a\n"
            "  reported refund is never shown as confirmed, and a source that could not be\n"
            "  reached is shown as UNAVAILABLE, never as a failed refund. If several confirmed\n"
            "  payouts pay the refund address and the provider named none of them, the payout\n"
            "  cannot be tied to this intent and the refund stays unconfirmed too."
        )
    else:
        print(
            f"\n  NOTE: this run returned {result3.outcome.value}. An upstream source may be\n"
            "  unreachable or the record may have changed. The states above are what was\n"
            "  actually observed."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TRACESETTLE read-only demonstration.")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="replay the real Phase 1 captures from evidence/raw/ instead of "
        "querying the live network (labelled as a replay)",
    )
    args = parser.parse_args(argv)

    if args.offline:
        from replay_opener import (
            CAPTURE_DATE,
            intent_hash_opener,
            refunded_swap_opener,
            verified_settlement_opener,
        )

        def make_client(fixture):
            return HttpClient(
                opener=fixture,
                max_attempts=1,
                timeout=1.0,
                backoff_base=0.0,
                sleeper=lambda _: None,
            )

        client1 = make_client(verified_settlement_opener())
        client2 = make_client(intent_hash_opener())
        client3 = make_client(refunded_swap_opener())
    else:
        client = HttpClient()
        client1 = client2 = client3 = client

    print(RULE)
    print("TRACESETTLE demonstration - read-only settlement investigation")
    if args.offline:
        print(f"MODE: OFFLINE REPLAY of captured fixtures (fetched {CAPTURE_DATE} UTC).")
        print("      This is not a live query. It shows the tool's analysis of real")
        print("      captured responses; it does not show an endpoint answering now.")
    else:
        print("MODE: LIVE - querying public endpoints now.")
    print(RULE)

    # --- Case 1: independently verified settlement --------------------------
    print("\nCASE 1 - a real swap, investigated by deposit address")
    print(f"identifier: {VERIFIED_DEPOSIT_ADDRESS}\n")
    inv = investigate(VERIFIED_DEPOSIT_ADDRESS, client1)
    result = build_result(inv)
    _show(result)

    print("\n  decisive, independently confirmed evidence per stage:")
    for stage in (
        Stage.SOURCE_CHAIN_DEPOSIT,
        Stage.BRIDGE_DEPOSIT_CREDIT,
        Stage.NEAR_SETTLEMENT,
        Stage.DESTINATION_CHAIN_DELIVERY,
    ):
        if result.stage(stage).state is StageState.CONFIRMED:
            print(f"  {stage.value}:")
            _decisive_evidence(inv, stage)

    violated = [n for n, ok in result.safety.items() if not ok]
    print(f"\n  safety invariants violated: {violated or 'none'}")
    if result.outcome.value != "SETTLED_VERIFIED":
        print(
            "\n  NOTE: this run did not reproduce SETTLED_VERIFIED. A source may be "
            "unreachable right now. That is reported honestly above, not hidden."
        )

    # --- Case 2: incomplete evidence ---------------------------------------
    print(f"\n{RULE}")
    print("CASE 2 - an intent hash on its own cannot reach the whole path")
    print(f"identifier: {INCOMPLETE_INTENT_HASH}\n")
    inv2 = investigate(INCOMPLETE_INTENT_HASH, client2)
    result2 = build_result(inv2)
    _show(result2)
    print(f"\n  summary: {result2.summary}")
    print(
        "\n  The intent-hash path has no reverse lookup to the origin or destination\n"
        "  legs, so it can never confirm more than the settlement stage. When the\n"
        "  solver relay answers it reports that statement as REPORTED; when the relay\n"
        "  is unreachable it reports the stages as UNAVAILABLE. In neither case does it\n"
        "  invent the missing stages."
    )

    # --- Case 3: a real refunded Bitcoin swap --------------------------------
    print(f"\n{RULE}")
    print("CASE 3 - a real refunded Bitcoin swap")
    print(f"identifier: {REFUNDED_DEPOSIT_ADDRESS}\n")
    inv3 = investigate(REFUNDED_DEPOSIT_ADDRESS, client3)
    result3 = build_result(inv3)
    _show(result3)
    print(f"\n  summary: {result3.summary}")
    _explain_refund(result3, inv3)

    print(f"\n{RULE}")
    print("No case signs, submits, or moves funds. No key was requested.")
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
