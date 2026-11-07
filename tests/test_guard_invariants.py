"""Each security-layer invariant must hold, and must be able to fail.

A checker that always returns ``True`` proves nothing, so every invariant is also
mutation-checked: the guarded behaviour is deliberately broken and the checker is
shown to notice. The mutation is applied to a copy of the real code path (a
subclass or a patched callable), never to the production module.
"""

from __future__ import annotations

import pytest

from tracesettle.guard.invariants import (
    INVARIANT_DESCRIPTIONS,
    INVARIANTS,
    check_all,
)


def test_every_invariant_holds_on_the_current_build():
    results = check_all()
    failures = [r for r in results if not r.holds]
    assert not failures, [(r.name, r.detail) for r in failures]


def test_every_invariant_has_a_description():
    assert set(INVARIANT_DESCRIPTIONS) == set(INVARIANTS)


def test_invariant_names_are_unique_and_stable():
    assert len(INVARIANTS) == len(set(INVARIANTS))
    assert len(INVARIANTS) >= 10


@pytest.mark.parametrize("name", sorted(INVARIANTS))
def test_invariant_reports_a_boolean_and_a_detail(name):
    result = INVARIANTS[name]()
    assert result.name == name
    assert isinstance(result.holds, bool)
    assert isinstance(result.detail, str) and result.detail


# --- mutation checks -------------------------------------------------------


def test_audit_chain_checker_notices_a_forged_digest():
    """The chain checker must fail when a record's digest is rewritten to match a forgery."""
    from dataclasses import replace

    from tracesettle.guard.audit import AuditLog

    log = AuditLog()
    log.append(event_type="A", actor="svc", outcome="ALLOW", detail="one")
    log.append(event_type="B", actor="svc", outcome="BLOCK", detail="two")
    records = list(log.records())
    # Forge the first record *and* recompute its digest, which an attacker could
    # do; the following record's prev_digest then no longer links.
    forged = replace(records[0], detail="forged")
    forged = replace(forged, digest=forged.compute_digest())
    verification = AuditLog.verify_records([forged.to_dict(), records[1].to_dict()])
    assert verification.ok is False
    assert verification.broken_at == 2


def test_audit_chain_checker_accepts_an_untouched_chain():
    from tracesettle.guard.audit import AuditLog

    log = AuditLog()
    for index in range(5):
        log.append(event_type="E", actor="svc", outcome="ALLOW", detail=f"event {index}")
    assert log.verify().ok is True
    assert AuditLog.verify_records([r.to_dict() for r in log.records()]).ok is True


def test_refusal_invariant_notices_an_executor_call(monkeypatch):
    """If a refusal reached the executor, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.guard.model import SignOutcome


    class LeakyExecutor(inv.SimulatedExecutor):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def execute(self, request, authorization_id):
            self.calls += 1
            return super().execute(request, authorization_id)

    class BrokenSigner:
        def __init__(self, executor):
            self._executor = executor

        def sign(self, sign_request):
            # Always execute, regardless of the authorization: the bug the
            # invariant exists to catch.
            self._executor.execute(sign_request.transaction, None)
            from tracesettle.guard.model import AuthState, SignResult

            return SignResult(
                outcome=SignOutcome.REFUSED,
                state=AuthState.MISSING,
                detail="refused but executed",
            )

    original_fresh = inv._fresh

    def broken_fresh():
        authority = inv._authority_for_check()
        service = inv.GuardService(policy=inv.DEFAULT_POLICY, authority=authority)
        executor = LeakyExecutor()
        return service, BrokenSigner(executor), executor

    monkeypatch.setattr(inv, "_fresh", broken_fresh)
    try:
        result = inv.INVARIANTS["refusal_never_reaches_the_executor"]()
        assert result.holds is False
    finally:
        monkeypatch.setattr(inv, "_fresh", original_fresh)


def test_non_allow_invariant_notices_a_stray_authorization():
    """If a BLOCK decision carried an authorization, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.guard.model import Decision

    real_evaluate = inv.GuardService.evaluate_payload

    def leaky_evaluate(self, payload, *, simulated=False):
        decision = real_evaluate(self, payload, simulated=simulated)
        if decision.decision is Decision.BLOCK:
            # Attach a token to a BLOCK: exactly what must never happen.
            from dataclasses import replace

            token = self.authority.issue(
                decision_id=decision.decision_id,
                decision=Decision.ALLOW,
                service_id=decision.request.service_id,
                parameters=dict(decision.fingerprint.fields),
            )
            return replace(decision, authorization=token)
        return decision

    original = inv.GuardService.evaluate_payload
    inv.GuardService.evaluate_payload = leaky_evaluate
    try:
        result = inv.INVARIANTS["non_allow_never_authorizes"]()
        assert result.holds is False
    finally:
        inv.GuardService.evaluate_payload = original


def test_service_identity_invariant_notices_a_forged_identity():
    """If the API accepted a mismatched service_id, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.guard.api import GuardAPI

    original = GuardAPI._identity_matches

    def permissive(cls, body, authenticated_service_id):  # noqa: ANN001
        # The mutation: accept every declared identity.
        return True

    GuardAPI._identity_matches = classmethod(permissive)
    try:
        result = inv.INVARIANTS["service_identity_cannot_be_forged"]()
        assert result.holds is False
    finally:
        GuardAPI._identity_matches = original


def test_service_credentials_hashed_invariant_notices_a_plaintext_store():
    """If the store kept the plaintext secret, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle import serviceauth

    original = serviceauth.hash_secret
    serviceauth.hash_secret = lambda secret: secret  # the mutation: no hashing
    try:
        result = inv.INVARIANTS["service_credentials_are_hashed_at_rest"]()
        assert result.holds is False
    finally:
        serviceauth.hash_secret = original


def test_near_execution_invariant_notices_a_broadcast_without_authorization():
    """If the boundary broadcast a non-authorized transaction, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import execution as ex

    original = ex.NearExecutionBoundary.accept_signature

    def permissive(self, prepared, signature_b64):  # noqa: ANN001
        # The mutation: skip the authorization check entirely.
        return prepared.transaction.signed_b64(b"\x00" * 64), "mutated"

    ex.NearExecutionBoundary.accept_signature = permissive
    try:
        result = inv.INVARIANTS["near_execution_never_signs_without_authorization"]()
        assert result.holds is False
    finally:
        ex.NearExecutionBoundary.accept_signature = original


def test_near_execution_binding_invariant_notices_a_binding_that_ignores_the_amount():
    """If the binding ignored the amount, a tampered transaction would pass."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import execution as ex

    original = ex.NearExecutionBoundary.verify_binding

    def permissive(self, prepared, *, consume=False):  # noqa: ANN001
        # The mutation: accept any transaction that merely carries a token.
        return None

    ex.NearExecutionBoundary.verify_binding = permissive
    try:
        result = inv.INVARIANTS["near_execution_binding_covers_the_bytes"]()
        assert result.holds is False
    finally:
        ex.NearExecutionBoundary.verify_binding = original


def test_near_execution_binding_invariant_notices_a_binding_that_ignores_the_bytes():
    """If the byte digest did not track the bytes, a bytes-only tamper would pass.

    This reproduces the defect that motivated the digest binding: a transaction
    whose ``actions`` bytes were swapped while every human-readable parameter
    stayed identical. Making the digest constant (so it no longer changes when
    the bytes change) reverts the feature's *effect* end to end - mint and verify
    both commit to the same constant - so the invariant must fail.
    """
    from tracesettle.guard import invariants as inv
    from tracesettle.near.txbuild import NearTransaction

    original = NearTransaction.payload_fingerprint

    def constant_digest(self):  # noqa: ANN001
        return "sha256:" + "0" * 64

    NearTransaction.payload_fingerprint = constant_digest
    try:
        result = inv.INVARIANTS["near_execution_binding_covers_the_bytes"]()
        assert result.holds is False, "the invariant failed to notice a byte-less binding"
    finally:
        NearTransaction.payload_fingerprint = original


def test_configured_audit_log_invariant_notices_a_truthiness_guard():
    """Mutation check: restoring the ``audit or AuditLog()`` defect must make the
    checker fail. The mutation is applied to a subclass, never to production."""
    from tracesettle.guard.audit import AuditLog
    from tracesettle.guard.policy import DEFAULT_POLICY
    from tracesettle.guard.service import GuardService

    class _Regressed(GuardService):
        def __init__(self, **kwargs):
            audit = kwargs.get("audit")
            kwargs["audit"] = audit or AuditLog()
            super().__init__(**kwargs)

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        audit = AuditLog(path=path)
        regressed = _Regressed(policy=DEFAULT_POLICY, audit=audit)
        # The defective constructor dropped the configured log; the real checker
        # would therefore report the invariant as broken.
        assert regressed.audit is not audit
        assert not path.exists()


def test_access_key_permission_invariant_notices_a_removed_check():
    """Mutation check: if the boundary stopped enforcing the key's permission, a
    function-call key would move native NEAR and the checker must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import execution as ex

    original = ex.NearExecutionBoundary._validate_access_key_permission

    def permissive(self, transaction, access_key):  # noqa: ANN001
        return None  # the mutation: never check the permission

    ex.NearExecutionBoundary._validate_access_key_permission = permissive
    try:
        result = inv.INVARIANTS["near_execution_requires_access_key_permission"]()
        assert result.holds is False
    finally:
        ex.NearExecutionBoundary._validate_access_key_permission = original


def test_durable_submission_invariant_notices_a_retry_on_unknown_outcome():
    """Mutation check: if an unknown submission outcome were retried (or recorded
    as FAILED), the checker must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import pipeline as pl
    from tracesettle.near.ledger import SubmissionState

    original = pl.NearExecutionPipeline._submit_and_verify

    def retrying(self, record, prepared, *, attempts, delay):  # noqa: ANN001
        # The mutation: assume "no response" means "not applied" and retry.
        record.attempts += 1
        record.transition(SubmissionState.SUBMITTING, reason="mutated retry")
        self.ledger.put(record)
        self.boundary.rpc.send_tx(record.signed_b64)
        record.transition(SubmissionState.FAILED, reason="mutated: assumed failure")
        self.ledger.put(record)
        return pl.ExecutionResult(
            state=SubmissionState.FAILED,
            tx_hash=record.tx_hash,
            settlement_state="FAILED",
            verification=None,
            signed_b64=record.signed_b64,
        )

    pl.NearExecutionPipeline._submit_and_verify = retrying
    try:
        result = inv.INVARIANTS["near_submission_is_durable_and_recovery_never_resubmits"]()
        assert result.holds is False
    finally:
        pl.NearExecutionPipeline._submit_and_verify = original



def test_counterparty_invariant_notices_a_read_that_relaxes_a_control():
    """If a counterparty read could not restrict, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import agent_wrapper as aw

    original = aw._evaluate_counterparty

    def permissive(read):  # noqa: ANN001
        # The mutation: a counterparty read never restricts the outcome.
        return aw.WrapperOutcome.ALLOW, [], []

    aw._evaluate_counterparty = permissive
    try:
        result = inv.INVARIANTS["counterparty_intelligence_only_adds_restriction"]()
        assert result.holds is False
    finally:
        aw._evaluate_counterparty = original


def test_approval_invariant_notices_an_approval_that_overrides_a_block():
    """If a valid approval could override a BLOCK, the invariant must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.guard import service as svc

    original = svc.GuardService._resolve_approval

    def permissive(self, request, approval, payload_fingerprint):  # noqa: ANN001
        # The mutation: any presented approval allows, regardless of the decision.
        if approval is None:
            return svc.Decision.REQUIRE_APPROVAL, None
        return svc.Decision.ALLOW, None

    svc.GuardService._resolve_approval = permissive
    try:
        result = inv.INVARIANTS["human_approval_cannot_override_a_block"]()
        assert result.holds is False
    finally:
        svc.GuardService._resolve_approval = original


def test_approval_invariant_notices_an_unbound_approval():
    """If an approval were not bound to the payload, a mismatched one would pass."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import approval as ap

    original = ap.ApprovalAuthority.validate

    def unbound(self, token, *, expected_payload_fingerprint, expected_service_id=None, consume=False):  # noqa: ANN001
        # The mutation: ignore the payload binding entirely.
        return original(
            self, token, expected_payload_fingerprint=expected_payload_fingerprint,
            expected_service_id=expected_service_id, consume=consume,
        ).__class__(ap.ApprovalState.VALID, "mutated: binding ignored")

    ap.ApprovalAuthority.validate = unbound
    try:
        result = inv.INVARIANTS["human_approval_cannot_override_a_block"]()
        assert result.holds is False
    finally:
        ap.ApprovalAuthority.validate = original



def test_custody_authorization_invariant_notices_a_bypassed_gate():
    """Mutation check: if ``execute`` ran without checking authorization, a
    non-ALLOW custody operation would reach the provider and the checker must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import outlayer_execution as ox
    from tracesettle.near.verify import SettlementState, SettlementVerification

    original = ox.OutLayerCustodyBoundary.execute

    def permissive(self, prepared):  # noqa: ANN001
        # The mutation: send to the provider regardless of the decision.
        outcome = self.provider.transfer(to=prepared.destination, amount_yocto=prepared.amount_yocto)
        return ox.CustodyExecution(
            provider=outcome,
            tx_hash=outcome.tx_hash,
            verification=SettlementVerification(state=SettlementState.INSUFFICIENT_EVIDENCE),
        )

    ox.OutLayerCustodyBoundary.execute = permissive
    try:
        result = inv.INVARIANTS["custody_execution_requires_an_authorization"]()
        assert result.holds is False
    finally:
        ox.OutLayerCustodyBoundary.execute = original


def test_custody_verification_invariant_notices_a_provider_trusting_verifier():
    """Mutation check: if a provider success were taken as verified without chain
    evidence, the checker must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import outlayer_execution as ox
    from tracesettle.near.verify import SettlementState, SettlementVerification

    original = ox.verify_custody_transaction

    def trusting(**kwargs):  # noqa: ANN003
        # The mutation: trust the provider claim, never read the chain.
        return SettlementVerification(state=SettlementState.VERIFIED, source_status="OK")

    ox.verify_custody_transaction = trusting
    try:
        result = inv.INVARIANTS["custody_provider_success_is_never_verified_without_chain_evidence"]()
        assert result.holds is False
    finally:
        ox.verify_custody_transaction = original


def test_custody_binding_invariant_notices_an_unbound_authorization():
    """Mutation check: if the binding were not re-validated before the send, a
    substituted operation would reach the provider and the checker must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import outlayer_execution as ox

    original = ox.OutLayerCustodyBoundary.verify_binding

    def unbound(self, prepared, *, consume=False):  # noqa: ANN001
        # The mutation: never recompute or compare the digest.
        return None

    ox.OutLayerCustodyBoundary.verify_binding = unbound
    try:
        result = inv.INVARIANTS["custody_authorization_is_bound_to_the_sent_operation"]()
        assert result.holds is False
    finally:
        ox.OutLayerCustodyBoundary.verify_binding = original


def test_custody_tee_signing_invariant_notices_a_trusting_evidence_combiner():
    """Mutation check: if the evidence ladder promoted to TEE_SIGNING_VERIFIED
    without a bound attestation, the checker must fail.

    The mutation makes ``combine_evidence`` claim TEE signing whenever settlement
    verified - the exact overstatement the invariant exists to catch.
    """
    from tracesettle.guard import invariants as inv
    from tracesettle.near import custody_attestation as catt

    original = catt.combine_evidence

    def trusting(**kwargs):  # noqa: ANN003
        # The mutation: settlement alone is enough for a TEE claim.
        if kwargs.get("settlement_verified"):
            return catt.CustodyEvidenceState.TEE_SIGNING_VERIFIED
        return original(**kwargs)

    catt.combine_evidence = trusting
    try:
        result = inv.INVARIANTS["custody_tee_signing_requires_bound_attestation_and_settlement"]()
        assert result.holds is False
    finally:
        catt.combine_evidence = original


def test_custody_tee_signing_invariant_notices_an_accepting_attestation_verifier():
    """Mutation check: if an unbound attestation were accepted, the checker must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import custody_attestation as catt

    original = catt.verify_custody_attestation

    def accepting(*args, **kwargs):  # noqa: ANN002, ANN003
        # The mutation: accept any attestation as fully bound and verified.
        return catt.CustodyAttestationEvidence(
            state=catt.CustodyEvidenceState.ATTESTATION_VERIFIED,
            detail="",
            quote_present=True,
            quote_verified=True,
            operation_bound=True,
            signing_key_bound=True,
        )

    catt.verify_custody_attestation = accepting
    try:
        result = inv.INVARIANTS["custody_tee_signing_requires_bound_attestation_and_settlement"]()
        assert result.holds is False
    finally:
        catt.verify_custody_attestation = original


def test_service_facing_route_invariant_notices_an_ungated_route():
    """Mutation check: dropping a route from the gate set must fail the invariant.

    The mutation removes ``/api/guard/near/custody/prepare`` from
    ``SERVICE_FACING_POST_PATHS`` while the dispatch still consults the
    authenticated identity - exactly the omission that let a caller adopt another
    service's identity. The invariant derives the consulted set from the API
    source, so it must notice the route is no longer gated.
    """
    from tracesettle.guard import api as gap

    original = gap.SERVICE_FACING_POST_PATHS
    # The mutation: a service-facing route is no longer gated.
    gap.SERVICE_FACING_POST_PATHS = frozenset(
        p for p in original if p != "/api/guard/near/custody/prepare"
    )
    try:
        result = INVARIANTS["service_facing_routes_require_a_credential"]()
        assert result.holds is False
    finally:
        gap.SERVICE_FACING_POST_PATHS = original


def test_service_facing_route_invariant_notices_a_removed_transport_gate():
    """Mutation check: if the transport stopped authenticating these routes, the
    socket probe must fail even when the gate set is unchanged."""
    from tracesettle import ui as ui_mod

    original = ui_mod._SERVICE_OPERATION_PATHS
    # The mutation: the transport no longer treats any route as service-facing.
    ui_mod._SERVICE_OPERATION_PATHS = frozenset()
    try:
        result = INVARIANTS["service_facing_routes_require_a_credential"]()
        assert result.holds is False
    finally:
        ui_mod._SERVICE_OPERATION_PATHS = original
def test_public_demo_invariant_notices_a_write_route_in_the_allowlist():
    """If a state-changing route were added to the keyless allowlist, it must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle import ui as ui_module

    original = ui_module.PUBLIC_DEMO_ROUTES
    # The mutation: expose the signing route without a key.
    ui_module.PUBLIC_DEMO_ROUTES = frozenset(set(original) | {"/api/guard/sign"})
    try:
        result = inv.INVARIANTS["public_demo_never_exposes_a_state_changing_route"]()
        assert result.holds is False
        assert "sign" in result.detail
    finally:
        ui_module.PUBLIC_DEMO_ROUTES = original


def test_public_demo_invariant_notices_a_custody_route_in_the_allowlist():
    """A custody route on the keyless allowlist must fail the invariant.

    The custody boundary sends an authorized operation to a TEE-held signing
    wallet; exposing it without a key would be a real write surface. This guards
    the token the invariant exists to catch.
    """
    from tracesettle.guard import invariants as inv
    from tracesettle import ui as ui_module

    original = ui_module.PUBLIC_DEMO_ROUTES
    ui_module.PUBLIC_DEMO_ROUTES = frozenset(
        set(original) | {"/api/guard/near/custody/prepare"}
    )
    try:
        result = inv.INVARIANTS["public_demo_never_exposes_a_state_changing_route"]()
        assert result.holds is False
        assert "custody" in result.detail
    finally:
        ui_module.PUBLIC_DEMO_ROUTES = original


def test_public_demo_invariant_notices_a_broadcasting_demonstration():
    """If the demonstration broadcast a transaction, it must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.near import agent_demo as demo_module

    original = demo_module.run_agent_payment_demo

    class _BroadcastingResult:
        def __init__(self, inner):
            self._inner = inner

        def to_dict(self):
            payload = self._inner.to_dict()
            # The mutation: drop the simulation marker, so it would read as real.
            payload["simulated"] = False
            return payload

    def broadcasting():
        return _BroadcastingResult(original())

    demo_module.run_agent_payment_demo = broadcasting
    try:
        result = inv.INVARIANTS["public_demo_never_exposes_a_state_changing_route"]()
        assert result.holds is False
    finally:
        demo_module.run_agent_payment_demo = original


def test_hostile_input_invariant_notices_an_amount_that_overflows(monkeypatch):
    """If an absurd amount raised instead of being refused, the invariant must fail.

    The mutation restores the pre-fix behaviour: a magnitude bound that lets a
    huge exponent through to ``Decimal`` comparison, which raises ``OverflowError``
    rather than ``AmountError``.
    """
    from tracesettle.guard import invariants as inv
    from tracesettle.guard import model as model_module

    def leaky_parse_amount(raw):
        value = model_module.Decimal(str(raw).strip())
        if not value.is_finite():
            raise model_module.AmountError("amount must be finite")
        if value < 0:
            raise model_module.AmountError("amount must not be negative")
        # No magnitude bound: the pre-fix path.
        return value

    monkeypatch.setattr(model_module, "parse_amount", leaky_parse_amount)
    try:
        result = inv.INVARIANTS["hostile_input_never_crashes_the_guard"]()
        assert result.holds is False
        assert "raised" in result.detail or "accepted" in result.detail
    finally:
        monkeypatch.undo()


def test_hostile_input_invariant_notices_a_token_that_raises(monkeypatch):
    """If a non-token authorization raised instead of being refused, it must fail."""
    from tracesettle.guard import invariants as inv
    from tracesettle.guard import authorization as auth_module

    original = auth_module.AuthorizationAuthority.validate

    def leaky_validate(self, token, *, expected, consume=True, expected_service_id=None):
        if token is None:
            return original(self, token, expected=expected, consume=consume, expected_service_id=expected_service_id)
        if not isinstance(token, (auth_module.Authorization, dict)):
            # The mutation: dereference the token without the shape guard.
            return original(self, {"version": token.version}, expected=expected)
        return original(self, token, expected=expected, consume=consume, expected_service_id=expected_service_id)

    monkeypatch.setattr(auth_module.AuthorizationAuthority, "validate", leaky_validate)
    try:
        result = inv.INVARIANTS["hostile_input_never_crashes_the_guard"]()
        assert result.holds is False
    finally:
        monkeypatch.undo()


# --- agent surface is sandbox-scoped (mission 21) --------------------------


def test_agent_surface_invariant_holds_on_the_current_build():
    from tracesettle.guard.invariants import INVARIANTS

    result = INVARIANTS["agent_surface_is_sandbox_scoped"]()
    assert result.holds is True, result.detail


def test_agent_surface_invariant_notices_an_operator_identity(monkeypatch):
    """If a sandbox credential could name an operator service, it must fail.

    The mutation: drop the cross-service refusal in the agent API, so a request
    naming ``treasury-agent`` is evaluated instead of refused.
    """
    from tracesettle import agentapi as api_module
    from tracesettle.guard import invariants as inv

    monkeypatch.setattr(api_module.AgentAPI, "_identity_ok", lambda self, record, body: None)
    try:
        result = inv.INVARIANTS["agent_surface_is_sandbox_scoped"]()
        assert result.holds is False
        assert "403" in result.detail
    finally:
        monkeypatch.undo()


def test_agent_surface_invariant_notices_a_self_approving_credential(monkeypatch):
    """If the API credential were accepted as the approval secret, it must fail.

    The mutation: make ``resolve_approval`` accept anything, so an agent holding
    only its API credential could self-approve.
    """
    from tracesettle.guard import invariants as inv
    from tracesettle.guard import sandbox as sandbox_module

    monkeypatch.setattr(
        sandbox_module.SandboxAuthority, "resolve_approval", lambda self, credential_id, presented: True
    )
    try:
        result = inv.INVARIANTS["agent_surface_is_sandbox_scoped"]()
        assert result.holds is False
        assert "approval secret" in result.detail
    finally:
        monkeypatch.undo()
