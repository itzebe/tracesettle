#!/usr/bin/env python3
"""Deterministic NEAR attack demonstration.

Runs the nine mission scenarios against the real guard controls, the real
authorization authority, the real reference signer, and the real NEAR policy and
access-key analysis. Nothing is mocked; the only substitution is the simulated
executor, which records what it was asked to do and never touches a chain.

Usage:
    python demo/near_demo.py            # all nine scenarios
    python demo/near_demo.py --scenario B
    python demo/near_demo.py --json     # machine-readable
    python demo/near_demo.py --access-keys

Every scenario is a controlled simulation: the parameters are synthetic, the
executor is simulated, and nothing is broadcast to any chain.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tracesettle.near.attacks import (  # noqa: E402
    SIMULATION_NOTE,
    run_all,
    run_scenario,
)
from tracesettle.near.access_keys import parse_access_key  # noqa: E402
from tracesettle.near.policy import PolicyAdapter, controls_applicable_to  # noqa: E402
from tracesettle.near.policy import PolicyScope  # noqa: E402

FIXTURE_DIR = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "near"


def _print_scenario(result) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(f"[{status}] {result.scenario_id}. {result.title}")
    print(f"       expected : {result.expected}")
    print(f"       observed : {result.observed}")
    print(f"       detail   : {result.detail}")
    if result.log:
        print("       log:")
        for line in result.log:
            print(f"         - {line}")
    print()


def _print_access_keys() -> None:
    keys = json.loads((FIXTURE_DIR / "access_keys.json").read_text())["keys"]
    print("Access-key permission analysis (synthetic fixtures, no private key material):")
    print()
    for name, raw in keys.items():
        analysis = parse_access_key(raw)
        print(f"  {name}")
        print(f"    permission        : {analysis.permission.value}")
        print(f"    risk              : {analysis.risk.value}")
        print(f"    can transfer NEAR : {analysis.can_transfer_near}")
        print(f"    can add keys      : {analysis.can_add_keys}")
        print(f"    receiver_id       : {analysis.receiver_id}")
        print(f"    method_names      : {list(analysis.method_names) or '(all methods)'}")
        if analysis.warnings:
            for warning in analysis.warnings:
                print(f"    warning           : {warning}")
        print()


def _print_policy_scope() -> None:
    policy_read = PolicyAdapter.from_fixture(
        json.loads((FIXTURE_DIR / "policy_in_force.json").read_text())
    )
    policy = policy_read.policy
    print("NEAR Intents policy scope (synthetic fixture, in-force shape):")
    print(f"  in_force                 : {policy.in_force}")
    print(f"  status                   : {policy.status.value}")
    print(f"  provider_policy_synced   : {policy.provider_policy_synced}")
    print(f"  actions                  : {sorted(policy.actions)}")
    print(f"  native.near.transfer     : {policy.native_method_enabled('near', 'transfer')}")
    print()
    print("  Controls that apply to an INTENTS request:")
    print(f"    {list(controls_applicable_to(PolicyScope.INTENTS))}")
    print("  Controls that apply to a NATIVE NEAR request:")
    print(f"    {list(controls_applicable_to(PolicyScope.NATIVE_NEAR))}")
    print()
    print("  This is the scope gap the mission asks to surface: destinations, budget,")
    print("  timelock, schedule and owner approval do NOT protect a native request.")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TRACESETTLE NEAR attack demonstration")
    parser.add_argument("--scenario", help="run one scenario by id (A-I)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--access-keys", action="store_true", help="print access-key analysis")
    parser.add_argument("--policy-scope", action="store_true", help="print the policy scope gap")
    args = parser.parse_args(argv)

    if args.access_keys:
        _print_access_keys()
        return 0
    if args.policy_scope:
        _print_policy_scope()
        return 0

    results = (run_scenario(args.scenario),) if args.scenario else run_all()

    if args.json:
        print(
            json.dumps(
                {
                    "note": SIMULATION_NOTE,
                    "results": [r.to_dict() for r in results],
                    "all_passed": all(r.passed for r in results),
                },
                indent=2,
            )
        )
        return 0 if all(r.passed for r in results) else 1

    print("=" * 78)
    print("TRACESETTLE x NEAR - agent transaction security demonstration")
    print("=" * 78)
    print()
    print(SIMULATION_NOTE)
    print()
    for result in results:
        _print_scenario(result)
    passed = sum(1 for r in results if r.passed)
    print(f"{passed}/{len(results)} scenarios produced the expected outcome.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
