"""The vertical slice, end to end, exactly as the product describes it:

    Transaction Request
      -> Risk Evaluation
      -> Policy Decision
      -> Transaction-bound Authorization
      -> Independent Signer Validation
      -> Execution or Refusal
      -> Audit Record

Every step here runs the real code. The only substitution is the executor, and
even that is the real :class:`SimulatedExecutor` (which never touches a chain).
The point of these tests is the *ordering guarantee*: a request that is not
authorized cannot reach execution, and the audit trail records which happened.
"""

from __future__ import annotations

from decimal import Decimal

from tracesettle.guard.model import AuthState, Decision, SignOutcome
from tracesettle.guard.signer import ReferenceSigner, SimulatedExecutor

from guard_helpers import (
    DENIED_DESTINATION,
    UNAPPROVED_DESTINATION,
    make_request,
    make_service,
)


class CountingExecutor(SimulatedExecutor):
    """The real simulated executor, with a call counter for the ordering assertion."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def execute(self, request, authorization_id):
        self.calls += 1
        return super().execute(request, authorization_id)


def _service_with(executor):
    """A real service whose signer reports outcomes back to the service.

    The signer is the service's own, so a signing attempt writes the SIGNING
    audit record and any incident exactly as it does in production. The only
    substitution is the executor.
    """
    service = make_service()
    service._signer = ReferenceSigner(service.authority, executor, on_outcome=service._on_sign_outcome)
    return service


def _slice(service, executor, request):
    """Run the full slice for one request and return (decision, sign_result)."""
    decision = service.evaluate(request)
    authorization = decision.authorization
    result = service.sign_transaction(request, authorization)
    return decision, result


# --- the happy path --------------------------------------------------------


def test_legitimate_transfer_is_authorized_then_executed():
    executor = CountingExecutor()
    service = _service_with(executor)
    decision, result = _slice(service, executor, make_request())
    assert decision.decision is Decision.ALLOW
    assert decision.authorization is not None
    assert result.outcome is SignOutcome.EXECUTED
    assert result.state is AuthState.VALID
    assert executor.calls == 1
    # The audit trail contains both the decision and the signing outcome.
    events = [r.event_type for r in service.audit.records()]
    assert events.count("DECISION") == 1
    assert events.count("SIGNING") == 1
    assert service.audit.verify().ok is True


def test_the_authorization_is_bound_to_the_executed_transaction():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request()
    decision = service.evaluate(request)
    # Sign a *different* transaction with the token: the executor must not run.
    other = make_request(destination=UNAPPROVED_DESTINATION)
    result = service.sign_transaction(other, decision.authorization)
    assert result.outcome is SignOutcome.REFUSED
    assert result.state is AuthState.WRONG_PARAMETERS
    assert executor.calls == 0


# --- the refusal paths ----------------------------------------------------


def test_suspicious_transfer_is_blocked_and_never_signed():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request(
        amount=Decimal("480000"), amount_raw="480000", destination=UNAPPROVED_DESTINATION
    )
    decision, result = _slice(service, executor, request)
    assert decision.decision is Decision.BLOCK
    assert decision.authorization is None
    assert result.outcome is SignOutcome.REFUSED
    assert result.state is AuthState.MISSING
    assert executor.calls == 0
    # A block is a security event, not just a response.
    assert any(i.code in {"UNAPPROVED_DESTINATION", "AMOUNT_LIMIT_BREACH"} for i in service.incidents())


def test_denied_destination_is_blocked_and_never_signed():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request(destination=DENIED_DESTINATION)
    decision, result = _slice(service, executor, request)
    assert decision.decision is Decision.BLOCK
    assert any(f.code == "DESTINATION_DENIED" for f in decision.findings)
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


def test_unregistered_identity_is_blocked_and_never_signed():
    executor = CountingExecutor()
    service = _service_with(executor)
    decision, result = _slice(service, executor, make_request(service_id="unknown-agent"))
    assert decision.decision is Decision.BLOCK
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


def test_client_bypass_flag_never_reaches_execution():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request(asserted_approval_fields=("approved",))
    decision, result = _slice(service, executor, request)
    assert decision.decision is Decision.REQUIRE_APPROVAL
    assert decision.authorization is None
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


def test_amount_over_the_limit_is_blocked_and_never_signed():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request(amount=Decimal("10001"), amount_raw="10001")
    decision, result = _slice(service, executor, request)
    assert decision.decision is Decision.BLOCK
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


def test_amount_over_the_threshold_requires_approval_and_never_signed():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request(amount=Decimal("6000"), amount_raw="6000")
    decision, result = _slice(service, executor, request)
    assert decision.decision is Decision.REQUIRE_APPROVAL
    assert decision.authorization is None
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


def test_repeated_rejections_hold_the_service_before_execution():
    """Once the signer has refused repeatedly, a legitimate request is held too."""
    executor = CountingExecutor()
    service = _service_with(executor)
    # Three rejected attempts at the signing boundary.
    for _ in range(3):
        service.sign_transaction(make_request(), None)
    request = make_request()
    decision, result = _slice(service, executor, request)
    assert decision.decision is Decision.HOLD
    assert any(f.code == "REPEATED_AUTHORIZATION_REJECTIONS" for f in decision.findings)
    assert result.outcome is SignOutcome.REFUSED
    assert executor.calls == 0


# --- audit completeness ---------------------------------------------------


def test_audit_records_every_step_of_the_slice():
    executor = CountingExecutor()
    service = _service_with(executor)
    _slice(service, executor, make_request())
    records = list(service.audit.records())
    kinds = [r.event_type for r in records]
    assert "DECISION" in kinds
    assert "SIGNING" in kinds
    decision_record = next(r for r in records if r.event_type == "DECISION")
    assert decision_record.outcome == "ALLOW"
    assert decision_record.service_id == "treasury-agent"
    assert decision_record.extra["finding_codes"] == []
    assert decision_record.authorization_id is not None
    signing_record = next(r for r in records if r.event_type == "SIGNING")
    assert signing_record.outcome == "EXECUTED"
    assert service.audit.verify().ok is True


def test_audit_records_a_refusal_with_its_reason():
    executor = CountingExecutor()
    service = _service_with(executor)
    request = make_request(service_id="unknown-agent")
    _slice(service, executor, request)
    signing = next(r for r in service.audit.records() if r.event_type == "SIGNING")
    assert signing.outcome == "REFUSED"
    assert signing.extra["state"] == "MISSING"
    assert signing.extra["incident_id"]


def test_every_step_is_reproducible_from_the_recorded_inputs():
    """Two independent runs of the same request produce the same decisions."""
    def run():
        executor = CountingExecutor()
        service = _service_with(executor)
        decision, result = _slice(service, executor, make_request())
        return (
            decision.decision.value,
            [c.code for c in decision.controls],
            [c.outcome.value for c in decision.controls],
            [f.code for f in decision.findings],
            result.outcome.value,
            result.state.value,
        )

    assert run() == run()
