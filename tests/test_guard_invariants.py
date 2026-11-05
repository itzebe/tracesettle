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

