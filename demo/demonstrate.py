#!/usr/bin/env python3
"""TRACESETTLE demonstration: verified, incomplete, and refund cases.

This is a read-only walkthrough. It runs three investigations through the real
adapter/engine/report code paths:

  1. A real, independently verified ETH->USDC swap, showing all four confirmed
     stages and their decisive evidence, ending in SETTLED_VERIFIED.
  2. An intent-hash-only lookup, which cannot reach the whole path. It shows the
     tool refusing to overstate what it can establish.
  3. A real, refunded Bitcoin->TRON swap. It shows the tool reporting a refund
     that it cannot independently verify (the origin chain has no configured
     RPC), keeping REPORTED, MISSING and UNAVAILABLE distinct.

The live cases use public endpoints when they are reachable. If the network is
unavailable, the script says so plainly and does not fabricate a result. Nothing
here signs, submits, or moves funds, and no key is requested.

Usage:
    python3 demo/demonstrate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tracesettle.httpclient import HttpClient  # noqa: E402
from tracesettle.investigation import build_result, investigate  # noqa: E402
from tracesettle.model import Stage, StageState  # noqa: E402

#: The real swap audited in Phase 1/Phase 3: a completed ETH -> USDC settlement.
VERIFIED_DEPOSIT_ADDRESS = "0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"
#: The intent hash of that same swap. On its own it can only reach the service
#: statement, because no reverse lookup from intent hash to deposit address exists.
INCOMPLETE_INTENT_HASH = "7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG"
#: A real refunded swap (BTC origin -> TRON destination) found on the public
#: NEAR Intents explorer. Its origin chain has no configured RPC, so the refund
#: can be reported but not independently verified.
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


def main() -> int:
    client = HttpClient()

    print(RULE)
    print("TRACESETTLE demonstration - read-only settlement investigation")
    print(RULE)

    # --- Case 1: independently verified settlement --------------------------
    print("\nCASE 1 - a real swap, investigated by deposit address")
    print(f"identifier: {VERIFIED_DEPOSIT_ADDRESS}\n")
    inv = investigate(VERIFIED_DEPOSIT_ADDRESS, client)
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
    inv2 = investigate(INCOMPLETE_INTENT_HASH, client)
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

    # --- Case 3: a real refund that cannot be independently verified ---------
    print(f"\n{RULE}")
    print("CASE 3 - a real refunded swap, reported but not independently verifiable")
    print(f"identifier: {REFUNDED_DEPOSIT_ADDRESS}\n")
    inv3 = investigate(REFUNDED_DEPOSIT_ADDRESS, client)
    result3 = build_result(inv3)
    _show(result3)
    print(f"\n  summary: {result3.summary}")
    if result3.outcome.value == "REFUND_REPORTED_UNVERIFIED":
        print(
            "\n  A refund is reported by the upstream service, but the origin chain has no\n"
            "  configured public RPC, so the refund transaction cannot be checked on-chain.\n"
            "  The tool keeps the states apart: the deposit credit is REPORTED (not\n"
            "  independently confirmed), the refund is UNAVAILABLE (a source problem, not\n"
            "  a failed refund), and destination delivery is MISSING. It does not claim the\n"
            "  refund was verified, and it does not claim the refund failed."
        )
    else:
        print(
            f"\n  NOTE: this run returned {result3.outcome.value}, not the expected\n"
            "  REFUND_REPORTED_UNVERIFIED. An upstream source may be unreachable or the\n"
            "  record may have changed. The states above are what was actually observed."
        )

    print(f"\n{RULE}")
    print("No case signs, submits, or moves funds. No key was requested.")
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
