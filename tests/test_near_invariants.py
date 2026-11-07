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
    assert len(near) == 19
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


def test_near_unknown_permission_invariant_notices_a_permissive_helper(monkeypatch):
    """Mutation: if the helper allowed UNKNOWN, the invariant must fail.

    Restoring the old helper behaviour (``UNKNOWN`` treated as unrestricted)
    reproduces the latent fail-open this mission closes. The invariant must
    notice that the helper itself no longer fails closed.
    """
    from tracesettle.near import access_keys as keys_mod

    original = keys_mod.key_supports_operation

    def permissive(analysis, **kwargs):
        if analysis.permission.value == "UNKNOWN":
            return True, "unrecognised permission treated as unrestricted"
        return original(analysis, **kwargs)

    monkeypatch.setattr(keys_mod, "key_supports_operation", permissive)
    result = inv.INVARIANTS["near_unknown_permission_denies_at_the_helper"]()
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


def test_near_consume_order_invariant_notices_a_reversed_order(monkeypatch):
    """Mutation: if the nonce were consumed before the signature is checked, fail.

    Reverting the ordering (consume the single-use authorization first, verify
    the signature second) reproduces the original defect: a malformed signature
    burns the authorization, so the correct signature is then refused as a
    replay. The invariant must notice.
    """
    from tracesettle.near import execution as exec_mod

    def reversed_order(self, prepared, signature_b64):
        import base64

        from tracesettle.near import ed25519
        from tracesettle.near.execution import ExecutionError, _public_key_raw

        # The mutation: spend the authorization before validating the signature.
        self._enforce_tee(prepared, consume_record=True)
        self.verify_binding(prepared, consume=True)
        try:
            raw = base64.b64decode(signature_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ExecutionError("the signature was not valid base64") from exc
        if len(raw) != 64:
            raise ExecutionError("an ed25519 signature must be 64 bytes")
        if not ed25519.verify(
            raw, prepared.transaction.tx_hash_bytes, _public_key_raw(prepared.transaction.public_key)
        ):
            raise ExecutionError("the signature does not verify")
        return prepared.transaction.signed_b64(raw), raw

    monkeypatch.setattr(exec_mod.NearExecutionBoundary, "accept_signature", reversed_order)
    result = inv.INVARIANTS["near_signature_is_verified_before_state_is_consumed"]()
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


# --- TEE attestation invariants (genuine TDX verification) ------------------


def test_tee_invariants_are_registered():
    tee = [name for name in inv.INVARIANTS if name.startswith("tee_")]
    assert len(tee) == 7
    assert all(name in inv.INVARIANT_DESCRIPTIONS for name in tee)


def test_tee_collateral_invariant_notices_a_verifier_that_ignores_the_signature(monkeypatch):
    """Mutation: if collateral signature verification were skipped, the invariant fails.

    Neutralizing ``verify_signed_document`` to accept any document reproduces the
    original gap (collateral fetched but not authenticated against the pinned Intel
    root). The invariant must notice the tampered TCB document then being accepted.
    """
    from tracesettle.near import collateral as collateral_mod

    def _accept_anything(raw, *, key, signature_hex, issuer_chain_header, expected_root_fingerprint):
        import json as _json

        document = _json.loads(raw) if raw.lstrip()[:1] == b"{" else {}
        return document.get(key, {}), ()

    monkeypatch.setattr(collateral_mod, "verify_signed_document", _accept_anything)
    result = inv.INVARIANTS["tee_collateral_verifies_against_the_pinned_root"]()
    assert result.holds is False


def test_tee_execution_invariant_notices_a_gate_that_does_not_refuse(monkeypatch):
    """Mutation: if the boundary signed without an attestation, the invariant fails.

    Both layers of the gate are neutralised - ``enforce`` accepts anything and the
    record is not required to pass through ``SIGNING_PENDING`` - so a signature is
    accepted with no bound attestation. That is the original defect (attestation
    verified but not enforced). The invariant must notice.
    """
    from tracesettle.near.tee_execution import TeeExecutionAuthorizer

    monkeypatch.setattr(
        TeeExecutionAuthorizer, "enforce", lambda self, execution_id, *, transaction_digest: self.get(execution_id)
    )
    monkeypatch.setattr(TeeExecutionAuthorizer, "begin_signing", lambda self, execution_id: self.get(execution_id))
    result = inv.INVARIANTS["tee_execution_requires_a_bound_attestation"]()
    assert result.holds is False


def test_tee_execution_state_machine_invariant_notices_an_illegal_edge(monkeypatch):
    """Mutation: adding a pre-TEE edge to signing must fail the structural check."""
    from tracesettle.near import tee_execution as te

    original = te.LEGAL_TRANSITIONS[te.ExecutionState.AUTHORIZED]
    monkeypatch.setitem(
        te.LEGAL_TRANSITIONS,
        te.ExecutionState.AUTHORIZED,
        original | {te.ExecutionState.SIGNING_PENDING},
    )
    result = inv.INVARIANTS["tee_execution_cannot_be_skipped_by_the_state_machine"]()
    assert result.holds is False


def test_tee_execution_record_binding_invariant_notices_an_unbound_enforce(monkeypatch):
    """Mutation: if enforce ignored the digest, a substituted transaction would pass."""
    from tracesettle.near.tee_execution import TeeExecutionAuthorizer

    def unbound(self, execution_id, *, transaction_digest):
        return self.get(execution_id)

    monkeypatch.setattr(TeeExecutionAuthorizer, "enforce", unbound)
    result = inv.INVARIANTS["tee_execution_record_is_transaction_bound"]()
    assert result.holds is False


def test_tee_genuine_invariant_notices_a_verifier_that_accepts_anything(monkeypatch):
    """If the TDX verifier accepted a tampered quote, the invariant must fail."""
    from tracesettle.near import tdx as tdx_mod

    class _AlwaysVerified:
        verified = True
        failures: list = []
        checks: dict = {}

        def to_dict(self):
            return {"verified": True, "failures": [], "checks": {}}

    monkeypatch.setattr(tdx_mod, "verify_tdx_quote", lambda *a, **k: _AlwaysVerified())
    result = inv.INVARIANTS["tee_attestation_verification_is_genuine"]()
    assert result.holds is False


def test_tee_nonce_invariant_notices_a_verifier_that_ignores_the_nonce(monkeypatch):
    """If a quote verified regardless of the nonce, the binding invariant must fail."""
    from tracesettle.near import tdx as tdx_mod

    class _AlwaysVerified:
        verified = True
        failures: list = []
        checks: dict = {}

        def to_dict(self):
            return {"verified": True, "failures": [], "checks": {}}

    monkeypatch.setattr(tdx_mod, "verify_tdx_quote", lambda *a, **k: _AlwaysVerified())
    result = inv.INVARIANTS["tee_attestation_is_bound_to_the_decision_nonce"]()
    assert result.holds is False


def test_enclave_signing_invariant_notices_a_permissive_measurement_policy(monkeypatch):
    """If any measurement were accepted, the enclave provisioning invariant must fail."""
    from tracesettle.near import enclave as enclave_mod

    monkeypatch.setattr(
        enclave_mod.MeasurementPolicy,
        "evaluate",
        lambda self, measurement: enclave_mod.ApprovedMeasurement("mutated", {"mr_config_id": "aa" * 48}),
    )
    result = inv.INVARIANTS["enclave_signing_requires_a_verified_attestation"]()
    assert result.holds is False


def test_enclave_signing_invariant_notices_a_verifier_that_ignores_the_nonce(monkeypatch):
    """If the nonce binding were ignored, the enclave provisioning invariant must fail."""
    from tracesettle.near import enclave as enclave_mod

    monkeypatch.setattr(
        enclave_mod.EnclaveSigningBoundary, "_nonce_matches", staticmethod(lambda v, n: True)
    )
    result = inv.INVARIANTS["enclave_signing_requires_a_verified_attestation"]()
    assert result.holds is False


def test_enclave_key_isolation_invariant_notices_an_unverified_signature(monkeypatch):
    """If a tampered signature were accepted, the key-isolation invariant must fail."""
    from tracesettle.near import enclave as enclave_mod

    monkeypatch.setattr(enclave_mod.ed25519, "verify", lambda *a, **k: True)
    result = inv.INVARIANTS["enclave_signing_key_is_isolated_from_the_host"]()
    assert result.holds is False


def test_enclave_key_isolation_invariant_notices_a_revoked_key_that_still_signs(monkeypatch):
    """If a revoked key still signed, the key-isolation invariant must fail."""
    from tracesettle.near import enclave as enclave_mod

    monkeypatch.setattr(enclave_mod.EnclaveKeyRegistry, "is_usable", lambda self, key_id: True)
    monkeypatch.setattr(enclave_mod.EnclaveKeyRegistry, "state", lambda self, key_id: "ACTIVE")
    result = inv.INVARIANTS["enclave_signing_key_is_isolated_from_the_host"]()
    assert result.holds is False


def test_freshness_invariant_notices_a_stale_policy_that_is_accepted(monkeypatch):
    """If a stale policy were accepted, the freshness invariant must fail."""
    from tracesettle.near import policy as policy_mod

    monkeypatch.setattr(policy_mod.PolicyAdapter, "_freshness", lambda self, policy: None)
    result = inv.INVARIANTS["tee_attestation_freshness_is_enforced"]()
    assert result.holds is False


def test_provider_policy_invariant_notices_an_unverified_read(monkeypatch):
    """If a read were reported available regardless, the provider-policy invariant must fail."""
    from tracesettle.near import policy as policy_mod

    monkeypatch.setattr(
        policy_mod.PolicyAdapter,
        "read_policy",
        lambda self, agent_id: policy_mod.PolicyRead(
            availability=policy_mod.PolicyAvailability.AVAILABLE,
            policy=policy_mod.parse_policy(
                {
                    "agent_id": "a",
                    "revision": 1,
                    "status": "APPLIED",
                    "provider_policy_synced": True,
                }
            ),
        ),
    )
    result = inv.INVARIANTS["provider_policy_reads_fail_closed_and_verify_identity"]()
    assert result.holds is False


def test_new_invariants_are_registered():
    for name in (
        "enclave_signing_requires_a_verified_attestation",
        "enclave_signing_key_is_isolated_from_the_host",
        "tee_attestation_freshness_is_enforced",
        "provider_policy_reads_fail_closed_and_verify_identity",
        "near_execution_enforces_the_provider_policy",
    ):
        assert name in inv.INVARIANTS
        assert name in inv.INVARIANT_DESCRIPTIONS


def test_near_execution_provider_policy_invariant_notices_an_ignored_layer(monkeypatch):
    """Mutation: if the boundary ignored the provider policy, the invariant must fail.

    Neutralising ``_apply_provider_policy`` reproduces a boundary that consults
    only the operator policy, so a not-in-force provider policy no longer blocks.
    The invariant must notice that the second layer was dropped.
    """
    from tracesettle.near import execution as exec_mod

    monkeypatch.setattr(
        exec_mod.NearExecutionBoundary,
        "_apply_provider_policy",
        lambda self, decision: (decision, None),
    )
    result = inv.INVARIANTS["near_execution_enforces_the_provider_policy"]()
    assert result.holds is False
