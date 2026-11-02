"""Mutation checks for the NEAR integration invariants.

Each NEAR invariant must be able to fail. The mutation is applied to a copy of
the real code path (a patched attribute), never to the production module, and is
restored afterwards. A checker that cannot fail proves nothing.
"""

from __future__ import annotations

import pathlib

from tracesettle.guard import invariants as inv

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "near"


def test_near_invariants_are_registered():
    near = [name for name in inv.INVARIANTS if name.startswith("near_")]
    assert len(near) == 4
    assert all(name in inv.INVARIANT_DESCRIPTIONS for name in near)


def test_near_policy_invariant_notices_a_permissive_in_force_rule(monkeypatch):
    """If a not-applied policy were treated as in force, the invariant must fail."""
    from tracesettle.near import policy as policy_mod

    monkeypatch.setattr(policy_mod.IntentsPolicy, "in_force", property(lambda self: True))
    result = inv.INVARIANTS["near_policy_must_be_in_force"]()
    assert result.holds is False


def test_near_scope_gap_invariant_notices_a_hidden_gap(monkeypatch):
    """If a native request reported no non-applicable controls, the invariant must fail."""
    from tracesettle.near import agent_wrapper as wrapper_mod

    monkeypatch.setattr(wrapper_mod, "controls_not_applicable_to", lambda scope: ())
    result = inv.INVARIANTS["near_native_scope_gap_is_always_stated"]()
    assert result.holds is False


def test_near_key_invariant_notices_a_permissive_key(monkeypatch):
    """If a function-call key were treated as able to transfer NEAR, it must fail."""
    from tracesettle.near import access_keys as keys_mod

    monkeypatch.setattr(keys_mod, "key_supports_operation", lambda *a, **k: (True, "mutated"))
    result = inv.INVARIANTS["near_function_call_key_cannot_transfer_near"]()
    assert result.holds is False


def test_near_settlement_invariant_notices_a_false_verification(monkeypatch):
    """If a provider claim produced VERIFIED, the invariant must fail."""
    from tracesettle.near import settlement as settlement_mod
    from tracesettle.near.settlement import AssuranceLevel, NearSettlementAssurance

    real = settlement_mod.settlement_assurance_from_result

    def permissive(result, *, provider_reported_success=False):
        real_result = real(result, provider_reported_success=provider_reported_success)
        return NearSettlementAssurance(
            outcome=real_result.outcome,
            level=AssuranceLevel.VERIFIED,
            provider_claimed_success=True,
            independently_verified=True,
            stages=real_result.stages,
        )

    monkeypatch.setattr(settlement_mod, "settlement_assurance_from_result", permissive)
    result = inv.INVARIANTS["near_provider_success_is_never_verified_without_evidence"]()
    assert result.holds is False


def test_near_invariants_hold_unmutated():
    for name in [n for n in inv.INVARIANTS if n.startswith("near_")]:
        assert inv.INVARIANTS[name]().holds is True
