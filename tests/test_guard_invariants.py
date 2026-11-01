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
