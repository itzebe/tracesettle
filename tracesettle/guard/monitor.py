"""Security monitoring: metrics, alerts, and incident records.

The monitor turns the stream of decisions and signer refusals into an operator
view: counters per outcome, an alert feed, and durable incident records. It is
deliberately deterministic — an incident is opened by an explicit rule, never by
a heuristic score — so an operator can always say why an incident exists.

Everything here is bounded, so a flood of blocked requests cannot exhaust memory.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque

from .model import (
    Decision,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    GuardDecision,
)

#: Incident rules. Each maps an observed condition to a severity and a stable
#: code, so the incident's origin is reproducible.
RULE_DENIED_DESTINATION = "DENIED_DESTINATION_ATTEMPT"
RULE_UNAUTHORIZED_SERVICE = "UNAUTHORIZED_SERVICE_IDENTITY"
RULE_REPEATED_BLOCKS = "REPEATED_BLOCKED_REQUESTS"
RULE_AUTHORIZATION_REJECTION = "AUTHORIZATION_REJECTION"
RULE_SIGNER_REFUSAL = "SIGNER_REFUSAL"
RULE_AMOUNT_LIMIT = "AMOUNT_LIMIT_BREACH"
RULE_CLIENT_ASSERTION = "CLIENT_ASSERTED_APPROVAL"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SecurityMonitor:
    """Bounded counters, an alert feed, and incident records."""

    def __init__(
        self,
        *,
        max_events: int = 500,
        max_incidents: int = 500,
        block_burst_threshold: int = 5,
        block_burst_window_seconds: int = 300,
    ) -> None:
        # Reentrant: several helpers (open_incident, _touch, _find_open) are
        # called both on their own and from inside another locked section.
        self._lock = threading.RLock()
        self._counts: dict[str, int] = {
            "evaluated": 0,
            Decision.ALLOW.value: 0,
            Decision.REQUIRE_APPROVAL.value: 0,
            Decision.HOLD.value: 0,
            Decision.BLOCK.value: 0,
            "authorizations_issued": 0,
            "signings_executed": 0,
            "signer_refusals": 0,
        }
        self._events: Deque[dict[str, Any]] = deque(maxlen=max_events)
        self._incidents: Deque[Incident] = deque(maxlen=max_incidents)
        self._incident_index: dict[str, int] = {}
        self._block_times: Deque[float] = deque()
        self._block_burst_threshold = max(2, block_burst_threshold)
        self._block_burst_window = timedelta(seconds=block_burst_window_seconds)
        self._blocked_by_service: dict[str, int] = {}

    # -- counters -----------------------------------------------------------

    def _bump(self, key: str, amount: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + amount

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            counts = dict(self._counts)
            open_incidents = sum(
                1 for i in self._incidents if i.status is not IncidentStatus.RESOLVED
            )
            by_severity: dict[str, int] = {}
            for incident in self._incidents:
                if incident.status is IncidentStatus.RESOLVED:
                    continue
                by_severity[incident.severity.value] = by_severity.get(incident.severity.value, 0) + 1
        counts["open_incidents"] = open_incidents
        return {
            "counts": counts,
            "open_incidents_by_severity": by_severity,
            "recent_events": self.events(limit=25),
        }

    # -- recording ----------------------------------------------------------

    def record_decision(self, decision: GuardDecision) -> list[Incident]:
        """Record a decision and open any incidents its findings justify."""
        opened: list[Incident] = []
        with self._lock:
            self._bump("evaluated")
            self._bump(decision.decision.value)
            self._events.appendleft(
                {
                    "at": decision.created_at,
                    "kind": "DECISION",
                    "decision": decision.decision.value,
                    "risk_level": decision.risk_level.value,
                    "service_id": decision.request.service_id,
                    "request_id": decision.request.request_id,
                    "decision_id": decision.decision_id,
                    "summary": decision.summary,
                    "finding_codes": [f.code for f in decision.findings],
                }
            )
            if decision.decision is Decision.BLOCK:
                self._note_block(decision.request.service_id)

        for finding in decision.findings:
            severity = _incident_severity(finding.severity)
            if finding.code == "DESTINATION_DENIED":
                opened.append(
                    self.open_incident(
                        code=RULE_DENIED_DESTINATION,
                        severity=IncidentSeverity.CRITICAL,
                        title="Attempt to send funds to a denied destination",
                        detail=finding.detail,
                        service_id=decision.request.service_id,
                        request_id=decision.request.request_id,
                        decision_id=decision.decision_id,
                    )
                )
            elif finding.code == "UNAUTHORIZED_SERVICE_IDENTITY":
                opened.append(
                    self.open_incident(
                        code=RULE_UNAUTHORIZED_SERVICE,
                        severity=IncidentSeverity.CRITICAL,
                        title="Unregistered service identity attempted a transfer",
                        detail=finding.detail,
                        service_id=decision.request.service_id,
                        request_id=decision.request.request_id,
                        decision_id=decision.decision_id,
                    )
                )
            elif finding.code == "AMOUNT_EXCEEDS_LIMIT":
                opened.append(
                    self.open_incident(
                        code=RULE_AMOUNT_LIMIT,
                        severity=IncidentSeverity.HIGH,
                        title="Withdrawal request exceeded the configured limit",
                        detail=finding.detail,
                        service_id=decision.request.service_id,
                        request_id=decision.request.request_id,
                        decision_id=decision.decision_id,
                    )
                )
            elif finding.code == "CLIENT_ASSERTED_APPROVAL_IGNORED":
                opened.append(
                    self.open_incident(
                        code=RULE_CLIENT_ASSERTION,
                        severity=IncidentSeverity.HIGH,
                        title="Client attempted to assert its own approval",
                        detail=finding.detail,
                        service_id=decision.request.service_id,
                        request_id=decision.request.request_id,
                        decision_id=decision.decision_id,
                    )
                )
            elif severity.rank >= IncidentSeverity.HIGH.rank:
                opened.append(
                    self.open_incident(
                        code=finding.code,
                        severity=severity,
                        title=finding.title,
                        detail=finding.detail,
                        service_id=decision.request.service_id,
                        request_id=decision.request.request_id,
                        decision_id=decision.decision_id,
                    )
                )

        burst = self._maybe_burst_incident(decision)
        if burst is not None:
            opened.append(burst)
        return [i for i in opened if i is not None]

    def record_authorization_issued(self, service_id: str, authorization_id: str) -> None:
        with self._lock:
            self._bump("authorizations_issued")
            self._events.appendleft(
                {
                    "at": _utc_now(),
                    "kind": "AUTHORIZATION_ISSUED",
                    "service_id": service_id,
                    "authorization_id": authorization_id,
                }
            )

    def record_signer_outcome(
        self,
        *,
        service_id: str | None,
        authorization_id: str | None,
        outcome: str,
        state: str,
        detail: str,
        request_id: str | None = None,
    ) -> Incident | None:
        """Record a signing attempt. A refusal is a first-class security event."""
        with self._lock:
            self._events.appendleft(
                {
                    "at": _utc_now(),
                    "kind": "SIGNER",
                    "outcome": outcome,
                    "state": state,
                    "service_id": service_id,
                    "authorization_id": authorization_id,
                    "detail": detail,
                }
            )
            if outcome == "EXECUTED":
                self._bump("signings_executed")
                return None
            self._bump("signer_refusals")

        return self.open_incident(
            code=RULE_SIGNER_REFUSAL if outcome == "REFUSED" else RULE_AUTHORIZATION_REJECTION,
            severity=IncidentSeverity.HIGH,
            title="Signer refused a transaction",
            detail=f"Signing refused ({state}): {detail}",
            service_id=service_id,
            request_id=request_id,
            decision_id=None,
        )

    def _note_block(self, service_id: str) -> None:
        # Called with the lock held.
        now = datetime.now(timezone.utc)
        self._block_times.append(now.timestamp())
        self._blocked_by_service[service_id] = self._blocked_by_service.get(service_id, 0) + 1
        cutoff = (now - self._block_burst_window).timestamp()
        while self._block_times and self._block_times[0] < cutoff:
            self._block_times.popleft()

    def _maybe_burst_incident(self, decision: GuardDecision) -> Incident | None:
        with self._lock:
            if len(self._block_times) >= self._block_burst_threshold:
                count = len(self._block_times)
                # Avoid opening a new burst incident for every subsequent block:
                # the incident already open for this code absorbs them.
                existing = self._find_open(RULE_REPEATED_BLOCKS)
                if existing is not None:
                    return self._touch(existing, f"{count} blocked requests in the last "
                                                f"{int(self._block_burst_window.total_seconds())}s")
                return self.open_incident(
                    code=RULE_REPEATED_BLOCKS,
                    severity=IncidentSeverity.HIGH,
                    title="Repeated blocked transaction requests",
                    detail=f"{count} requests were blocked in the last "
                    f"{int(self._block_burst_window.total_seconds())}s.",
                    service_id=decision.request.service_id,
                    request_id=decision.request.request_id,
                    decision_id=decision.decision_id,
                )
        return None

    # -- incidents ----------------------------------------------------------

    def _find_open(self, code: str) -> Incident | None:
        # Called with the lock held.
        for incident in reversed(self._incidents):
            if incident.code == code and incident.status is not IncidentStatus.RESOLVED:
                return incident
        return None

    def _touch(self, incident: Incident, detail: str) -> Incident:
        # Called with the lock held.
        updated = Incident(
            incident_id=incident.incident_id,
            created_at=incident.created_at,
            updated_at=_utc_now(),
            severity=incident.severity,
            status=incident.status,
            code=incident.code,
            title=incident.title,
            detail=detail,
            service_id=incident.service_id,
            request_id=incident.request_id,
            decision_id=incident.decision_id,
            occurrence_count=incident.occurrence_count + 1,
        )
        try:
            index = next(
                i for i, item in enumerate(self._incidents) if item.incident_id == incident.incident_id
            )
            self._incidents[index] = updated
        except StopIteration:
            pass
        return updated

    def open_incident(
        self,
        *,
        code: str,
        severity: IncidentSeverity,
        title: str,
        detail: str,
        service_id: str | None = None,
        request_id: str | None = None,
        decision_id: str | None = None,
    ) -> Incident:
        now = _utc_now()
        with self._lock:
            incident = Incident(
                incident_id=f"inc_{abs(hash((code, service_id, request_id, now))) & 0xFFFFFFFFFFFF:012x}",
                created_at=now,
                updated_at=now,
                severity=severity,
                status=IncidentStatus.OPEN,
                code=code,
                title=title,
                detail=detail,
                service_id=service_id,
                request_id=request_id,
                decision_id=decision_id,
            )
            self._incidents.appendleft(incident)
            return incident

    def incidents(self, *, status: IncidentStatus | None = None, limit: int = 100) -> tuple[Incident, ...]:
        with self._lock:
            items = list(self._incidents)
        if status is not None:
            items = [i for i in items if i.status is status]
        return tuple(items[:limit])

    def set_status(self, incident_id: str, status: IncidentStatus) -> Incident | None:
        with self._lock:
            for index, incident in enumerate(self._incidents):
                if incident.incident_id == incident_id:
                    updated = Incident(
                        incident_id=incident.incident_id,
                        created_at=incident.created_at,
                        updated_at=_utc_now(),
                        severity=incident.severity,
                        status=status,
                        code=incident.code,
                        title=incident.title,
                        detail=incident.detail,
                        service_id=incident.service_id,
                        request_id=incident.request_id,
                        decision_id=incident.decision_id,
                        occurrence_count=incident.occurrence_count,
                    )
                    self._incidents[index] = updated
                    return updated
        return None

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)[:limit]

    # -- context for the guard ---------------------------------------------

    def recent_blocked_count(self, service_id: str, *, window_seconds: int) -> int:
        """Blocked requests for a service within the window, for the velocity control."""
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=window_seconds)).timestamp()
        with self._lock:
            events = list(self._events)
        count = 0
        for event in events:
            if event.get("kind") != "DECISION" or event.get("decision") != Decision.BLOCK.value:
                continue
            if event.get("service_id") != service_id:
                continue
            at = event.get("at")
            if isinstance(at, str) and _epoch(at) >= cutoff:
                count += 1
        return count

    def rejected_authorization_count(self, service_id: str | None, *, window_seconds: int) -> int:
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=window_seconds)).timestamp()
        with self._lock:
            events = list(self._events)
        count = 0
        for event in events:
            if event.get("kind") != "SIGNER":
                continue
            if event.get("outcome") == "EXECUTED":
                continue
            if service_id is not None and event.get("service_id") != service_id:
                continue
            at = event.get("at")
            if isinstance(at, str) and _epoch(at) >= cutoff:
                count += 1
        return count


def _epoch(iso_seconds: str) -> float:
    try:
        return datetime.strptime(iso_seconds, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        ).timestamp()
    except ValueError:
        return 0.0


def _incident_severity(severity: Any) -> IncidentSeverity:
    value = getattr(severity, "value", str(severity))
    try:
        return IncidentSeverity(value)
    except ValueError:
        return IncidentSeverity.MEDIUM
