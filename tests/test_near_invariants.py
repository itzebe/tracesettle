"""Mutation checks for the NEAR integration invariants.

Each NEAR invariant must be able to fail. The mutation is applied to a copy of
the real code path (a patched attribute), never to the production module, and is
restored afterwards. A checker that cannot fail proves nothing.
"""

from __future__ import annotations

import pathlib

from tracesettle.guard import invariants as inv

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "tracesettle" / "near" / "fixtures"


def test_near_invariants_are_registered():
    near = [name for name in inv.INVARIANTS if name.startswith("near_")]
    assert len(near) == 12
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


def test_near_unrecognised_key_invariant_notices_an_allow(monkeypatch):
    """Mutation: if an unrecognised key were allowed, the invariant must fail.

    Reverting the wrapper's UNKNOWN branch (treating an unrecognised permission
    as safe) reproduces the original defect: a CRITICAL-risk key producing ALLOW.
    The invariant must notice.
    """
    from tracesettle.near import agent_wrapper as wrapper_mod

    original = wrapper_mod.AgentAuthorizationWrapper._evaluate_access_key

    def permissive(self, transaction, analysis):
        # The mutation: drop the UNKNOWN fail-closed branch.
        from tracesettle.near.agent_wrapper import WrapperOutcome

        if analysis is not None and analysis.permission.value == "UNKNOWN":
            return WrapperOutcome.ALLOW, []
        return original(self, transaction, analysis)

    monkeypatch.setattr(
        wrapper_mod.AgentAuthorizationWrapper, "_evaluate_access_key", permissive
    )
    result = inv.INVARIANTS["near_unrecognised_access_key_never_allows"]()
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
            level=AssuranceLevel.SETTLEMENT_VERIFIED,
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


def test_near_partial_settlement_invariant_notices_a_false_verification(monkeypatch):
    """Mutation: if the amount comparison were dropped, the invariant must fail.

    Neutralizing the shortfall computation reproduces the original defect (a
    confirmed delivery of less than expected reported as VERIFIED). The invariant
    must notice.
    """
    from tracesettle.near import settlement as settlement_mod

    monkeypatch.setattr(settlement_mod, "_amount_shortfall", lambda expected, observed: (None, None))
    result = inv.INVARIANTS["near_partial_settlement_is_never_verified"]()
    assert result.holds is False


def test_near_policy_selection_invariant_fails_if_a_client_fixture_is_honoured(monkeypatch):
    """Mutation check: the invariant must fail when client policy selection returns."""
    from tracesettle.guard import api as api_mod

    original = api_mod.GuardAPI._near_policy_read

    def _honour_client_fixture(self, body):
        from tracesettle.near.policy import load_fixture

        fixture = body.get("policy_fixture")
        if isinstance(fixture, str) and fixture.strip():
            return load_fixture(fixture.strip())
        return original(self, body)

    monkeypatch.setattr(api_mod.GuardAPI, "_near_policy_read", _honour_client_fixture)
    result = inv._near_policy_selection_is_not_client_controlled()
    assert result.holds is False
    assert "client supplied" in result.detail


def test_near_terminal_states_invariant_notices_a_reported_failure_as_failed(monkeypatch):
    """Mutation check: if a reported failure read as FAILED, the invariant must fail."""
    from tracesettle.near import settlement as settlement_mod
    from tracesettle.near.settlement import AssuranceLevel, NearSettlementAssurance

    real = settlement_mod.settlement_assurance_from_result

    def permissive(result, **kwargs):
        out = real(result, **kwargs)
        return NearSettlementAssurance(
            outcome=out.outcome,
            level=AssuranceLevel.FAILED,
            provider_claimed_success=out.provider_claimed_success,
            independently_verified=out.independently_verified,
            stages=out.stages,
        )

    monkeypatch.setattr(settlement_mod, "settlement_assurance_from_result", permissive)
    result = inv._near_terminal_states_are_evidence_distinguished()
    assert result.holds is False


def test_near_destination_invariant_notices_a_provider_trusting_verifier(monkeypatch):
    """Mutation: if the destination verifier trusted a success without checking the
    recipient, the invariant must fail. Neutralizing the recipient check reproduces
    the defect the invariant exists to catch."""
    from tracesettle.near import destination_verify as dv_mod
    from tracesettle.near.destination_verify import DestinationVerdict

    real = dv_mod.verify_destination_delivery

    def permissive(*args, **kwargs):
        result = real(*args, **kwargs)
        # A provider-trusting verifier would call any successful receipt a delivery.
        return dv_mod.DestinationVerification(
            level=DestinationVerdict.VERIFIED,
            chain=result.chain,
            tx_hash=result.tx_hash,
            summary="trusted the receipt",
        )

    monkeypatch.setattr(dv_mod, "verify_destination_delivery", permissive)
    result = inv.INVARIANTS["near_destination_delivery_requires_the_destination_chain"]()
    assert result.holds is False


def test_near_chain_invariant_notices_a_caller_supplied_chain(monkeypatch):
    """Mutation: if the evaluated chain came from the caller instead of the origin
    asset, the invariant must fail. Restoring the original defect (a caller-supplied
    chain is honoured) reproduces exactly the chain-allowlist bypass the invariant
    exists to catch."""
    from tracesettle.near import lifecycle as lifecycle_mod

    # Reproduce the original defect: a native omft asset derives "near", so a
    # request that omits `chain` is evaluated against the wrong chain.
    monkeypatch.setattr(
        lifecycle_mod, "_chain_of", lambda asset_id: "near"
    )
    result = inv.INVARIANTS["near_chain_is_derived_from_the_origin_asset"]()
    assert result.holds is False


def test_near_chain_invariant_notices_a_silently_accepted_conflict(monkeypatch):
    """Mutation: if a declared chain that contradicts the origin asset were accepted
    (no refusal), the invariant must fail."""
    from tracesettle.near import lifecycle as lifecycle_mod

    real = lifecycle_mod.NearIntentsLifecycle.create_and_authorize

    def lenient(self, **kwargs):
        # Drop the conflict refusal: accept any declared chain.
        try:
            return real(self, **kwargs)
        except lifecycle_mod.LifecycleError as exc:
            if "disagrees with the origin asset" in str(exc):
                payload = dict(kwargs.get("payload") or {})
                payload.pop("chain", None)
                return real(self, **{**kwargs, "payload": payload})
            raise

    monkeypatch.setattr(lifecycle_mod.NearIntentsLifecycle, "create_and_authorize", lenient)
    result = inv.INVARIANTS["near_chain_is_derived_from_the_origin_asset"]()
    assert result.holds is False
