"""Audit-log integrity and security-monitoring tests.

The audit tests prove the property the product actually claims: an edit, a
reorder, or a removal of a stored record is detected by recomputation. They also
prove the honest limit: a whole-log rewrite with recomputed digests is *not*
detected, so the tool must not claim tamper-proofness.
"""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from tracesettle.guard.audit import GENESIS_DIGEST, AuditLog
from tracesettle.guard.model import IncidentSeverity, IncidentStatus
from tracesettle.guard.monitor import SecurityMonitor

from guard_helpers import (
    APPROVED_DESTINATION,
    DENIED_DESTINATION,
    UNAPPROVED_DESTINATION,
    make_request,
    make_service,
)


def _populated_log() -> AuditLog:
    log = AuditLog()
    for index in range(4):
        log.append(
            event_type="DECISION",
            actor="treasury-agent",
            outcome="ALLOW",
            detail=f"event {index}",
            service_id="treasury-agent",
        )
    return log


# --- chain integrity ------------------------------------------------------


def test_first_record_links_to_genesis():
    log = AuditLog()
    record = log.append(event_type="A", actor="svc", outcome="ALLOW", detail="first")
    assert record.prev_digest == GENESIS_DIGEST
    assert record.sequence == 1
    assert record.digest == record.compute_digest()


def test_each_record_links_to_its_predecessor():
    log = _populated_log()
    records = list(log.records())
    for previous, current in zip(records, records[1:]):
        assert current.prev_digest == previous.digest


def test_clean_chain_verifies():
    log = _populated_log()
    verification = log.verify()
    assert verification.ok is True
    assert verification.length == 4
    assert verification.broken_at is None


def test_editing_a_field_is_detected():
    log = _populated_log()
    records = [r.to_dict() for r in log.records()]
    records[2]["detail"] = "edited"
    verification = AuditLog.verify_records(records)
    assert verification.ok is False
    assert verification.broken_at == 3


def test_forging_a_digest_is_detected_by_recomputation():
    log = _populated_log()
    records = [r.to_dict() for r in log.records()]
    records[1]["digest"] = "f" * 64
    verification = AuditLog.verify_records(records)
    assert verification.ok is False
    assert verification.broken_at == 2


def test_reordering_records_is_detected():
    log = _populated_log()
    records = [r.to_dict() for r in log.records()]
    records[1], records[2] = records[2], records[1]
    assert AuditLog.verify_records(records).ok is False


def test_removing_a_record_is_detected():
    log = _populated_log()
    records = [r.to_dict() for r in log.records()]
    del records[1]
    assert AuditLog.verify_records(records).ok is False


def test_whole_log_rewrite_with_recomputed_digests_is_not_detected():
    """The honest limit of a hash chain, asserted so the claim stays accurate.

    An attacker who can rewrite every record and recompute every digest produces
    a self-consistent chain. Detecting that needs an external anchor, which is why
    the head digest is exposed rather than claimed to be tamper-proof.
    """
    log = _populated_log()
    rewritten = []
    prev = GENESIS_DIGEST
    for index, record in enumerate(log.records()):
        forged = replace(record, detail=f"rewritten {index}", prev_digest=prev)
        forged = replace(forged, digest=forged.compute_digest())
        rewritten.append(forged.to_dict())
        prev = forged.digest
    assert AuditLog.verify_records(rewritten).ok is True


def test_head_digest_is_the_last_record():
    log = _populated_log()
    assert log.head_digest == list(log.records())[-1].digest


def test_empty_log_verifies():
    assert AuditLog().verify().ok is True


def test_persistent_log_round_trips(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path)
    for index in range(3):
        log.append(event_type="E", actor="svc", outcome="ALLOW", detail=f"event {index}")
    persisted = log.read_file()
    assert len(persisted) == 3
    assert AuditLog.verify_records(persisted).ok is True


def test_persistent_log_survives_a_reload(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path=path)
    first.append(event_type="E", actor="svc", outcome="ALLOW", detail="one")
    second = AuditLog(path=path)
    second.append(event_type="E", actor="svc", outcome="ALLOW", detail="two")
    persisted = second.read_file()
    assert len(persisted) == 2
    assert AuditLog.verify_records(persisted).ok is True


def test_log_is_bounded(tmp_path):
    log = AuditLog(max_records=3)
    for index in range(10):
        log.append(event_type="E", actor="svc", outcome="ALLOW", detail=f"event {index}")
    assert len(log) == 3
    assert log.verify().ok is True


def test_recent_returns_newest_first_and_can_filter():
    log = _populated_log()
    log.append(event_type="SIGNING", actor="svc", outcome="REFUSED", detail="refused")
    recent = log.recent(limit=2)
    assert recent[0].event_type == "SIGNING"
    only_signing = log.recent(limit=10, event_types=["SIGNING"])
    assert len(only_signing) == 1


# --- monitoring -----------------------------------------------------------


def test_decision_counters_track_each_outcome():
    service = make_service()
    service.evaluate(make_request())
    service.evaluate(make_request(service_id="unknown"))
    service.evaluate(make_request(destination=UNAPPROVED_DESTINATION, amount_raw="100"))
    counts = service.monitor.counts()
    assert counts["evaluated"] == 3
    assert counts["ALLOW"] == 1
    assert counts["BLOCK"] == 2


def test_denied_destination_opens_a_critical_incident():
    service = make_service()
    service.evaluate(make_request(destination=DENIED_DESTINATION))
    incidents = service.incidents()
    assert any(i.code == "DENIED_DESTINATION_ATTEMPT" for i in incidents)
    denied = next(i for i in incidents if i.code == "DENIED_DESTINATION_ATTEMPT")
    assert denied.severity is IncidentSeverity.CRITICAL


def test_unregistered_identity_opens_a_critical_incident():
    service = make_service()
    service.evaluate(make_request(service_id="rogue"))
    assert any(i.code == "UNAUTHORIZED_SERVICE_IDENTITY" for i in service.incidents())


def test_amount_limit_breach_opens_an_incident():
    service = make_service()
    service.evaluate(make_request(amount=Decimal("999999"), amount_raw="999999"))
    assert any(i.code == "AMOUNT_LIMIT_BREACH" for i in service.incidents())


def test_repeated_blocks_open_a_burst_incident():
    service = make_service()
    for index in range(5):
        service.evaluate(make_request(service_id="unknown", request_id=f"r{index}"))
    assert any(i.code == "REPEATED_BLOCKED_REQUESTS" for i in service.incidents())


def test_signer_refusal_is_recorded_as_a_security_event():
    service = make_service()
    request = make_request()
    service.sign_transaction(request, None)
    assert service.monitor.counts()["signer_refusals"] == 1
    assert any(i.code == "SIGNER_REFUSAL" for i in service.incidents())


def test_successful_execution_is_counted_but_opens_no_incident():
    service = make_service()
    request = make_request()
    token = service.evaluate(request).authorization
    service.sign_transaction(request, token)
    assert service.monitor.counts()["signings_executed"] == 1
    assert not any(i.code == "SIGNER_REFUSAL" for i in service.incidents())


def test_incident_status_can_be_advanced_and_is_audited():
    service = make_service()
    service.evaluate(make_request(service_id="unknown"))
    incident = service.incidents()[0]
    updated = service.set_incident_status(incident.incident_id, IncidentStatus.ACKNOWLEDGED)
    assert updated.status is IncidentStatus.ACKNOWLEDGED
    resolved = service.set_incident_status(incident.incident_id, IncidentStatus.RESOLVED)
    assert resolved.status is IncidentStatus.RESOLVED
    assert any(r.event_type == "INCIDENT" for r in service.audit.records())


def test_incident_filtering_by_status():
    service = make_service()
    service.evaluate(make_request(service_id="unknown"))
    assert service.incidents(status=IncidentStatus.OPEN)
    assert service.incidents(status=IncidentStatus.RESOLVED) == ()


def test_monitor_counters_are_bounded_by_event_capacity():
    monitor = SecurityMonitor(max_events=5)
    service = make_service(monitor=monitor)
    for index in range(20):
        service.evaluate(make_request(service_id="unknown", request_id=f"r{index}"))
    assert len(service.monitor.events(limit=100)) <= 5


def test_rejected_authorization_count_uses_the_window():
    service = make_service()
    for _ in range(2):
        service.sign_transaction(make_request(), None)
    assert service.monitor.rejected_authorization_count("treasury-agent", window_seconds=3600) == 2
    assert service.monitor.rejected_authorization_count("other-service", window_seconds=3600) == 0
    assert service.monitor.rejected_authorization_count("treasury-agent", window_seconds=0) == 0


def test_metrics_expose_policy_and_audit_state_without_secrets():
    service = make_service()
    service.evaluate(make_request())
    metrics = service.metrics()
    assert metrics["policy"]["policy_id"]
    assert metrics["audit"]["length"] >= 1
    assert metrics["authorization"]["key_id"] == "test-key"
    assert "key" not in {k.lower() for k in metrics["authorization"] if k != "key_id"}


def test_approved_destination_is_not_an_incident():
    service = make_service()
    service.evaluate(make_request(destination=APPROVED_DESTINATION))
    assert service.incidents() == ()


def test_guard_service_keeps_a_configured_empty_persistent_audit_log(tmp_path):
    """A configured audit-log path must survive construction.

    An empty ``AuditLog`` is falsy (it defines ``__len__``), so a truthiness
    guard in ``GuardService.__init__`` would replace the persistent log with an
    in-memory one on every fresh start — silently disabling durable auditing.
    """
    from tracesettle.guard.service import GuardService

    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path=path)
    assert not audit  # the precondition that made the bug reachable
    service = GuardService(audit=audit)
    assert service.audit is audit
    service.audit.append(event_type="E", actor="svc", outcome="ALLOW", detail="recorded")
    assert path.exists()
    assert len(AuditLog(path=path).read_file()) == 1
