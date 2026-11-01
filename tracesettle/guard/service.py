"""The guard service: the single entry point the rest of the app uses.

Responsibilities:

* validate and describe an incoming transaction request (never trusting it);
* run the deterministic controls and compute the decision;
* issue a transaction-bound authorization only for an ``ALLOW`` decision;
* expose the metrics, incidents, and audit trail the console reads;
* provide the signer the service hands to a signing integration.

Every step writes to the audit log, so a decision can be reconstructed from the
record even if the in-memory state is gone.
"""

from __future__ import annotations

import re
import secrets
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Deque

from .audit import AuditLog
from .authorization import (
    AuthorizationAuthority,
    AuthVerification,
    InMemoryReplayStore,
)
from .model import (
    ASSERTED_APPROVAL_FIELDS,
    AmountError,

    ControlOutcome,
    Decision,
    EvaluationContext,
    FindingSeverity,
    GuardDecision,
    RequestFingerprint,
    SignResult,
    TransactionRequest,
    canonical_fields,
    fingerprint_of,
    parse_amount,
)
from .monitor import SecurityMonitor
from .policy import DEFAULT_POLICY, PolicyConfig
from .rules import evaluate_controls
from .signer import ReferenceSigner, SignRequest

_SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_OPERATION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
_CHAIN_RE = re.compile(r"^[a-z][a-z0-9]{0,31}$")
_ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

MAX_FIELD_CHARS = 128
_KNOWN_FIELDS = frozenset(
    {
        "request_id",
        "service_id",
        "operation",
        "chain",
        "asset",
        "amount",
        "destination",
        "idempotency_key",
        "client_reference",
        "simulated",
        "metadata",
    }
)


class RequestValidationError(ValueError):
    """A request that cannot be described safely. The message is client-safe."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(value: Any, field: str, *, max_chars: int = MAX_FIELD_CHARS) -> str:
    if not isinstance(value, str):
        raise RequestValidationError(f"field '{field}' must be a string")
    text = value.strip()
    if not text:
        raise RequestValidationError(f"field '{field}' must not be empty")
    if len(text) > max_chars:
        raise RequestValidationError(f"field '{field}' exceeds {max_chars} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise RequestValidationError(f"field '{field}' contains control characters")
    return text


def request_from_payload(payload: dict[str, Any], *, simulated: bool = False) -> TransactionRequest:
    """Build a :class:`TransactionRequest` from an untrusted JSON object.

    Strict: an unexpected shape is rejected rather than coerced. Fields that look
    like an attempt to assert approval are recorded by name (never honoured), and
    arbitrary extra keys are recorded by name only, so nothing sensitive from the
    caller is copied into the audit trail.
    """
    if not isinstance(payload, dict):
        raise RequestValidationError("request body must be a JSON object")

    asserted: list[str] = []
    for key, value in payload.items():
        name = str(key).strip().lower()
        if name in ASSERTED_APPROVAL_FIELDS and value not in (None, False, 0, "", [], {}):
            asserted.append(name)

    service_id = _clean_text(payload.get("service_id"), "service_id", max_chars=64)
    if not _SERVICE_ID_RE.match(service_id):
        raise RequestValidationError(
            "field 'service_id' must be 1-64 characters of letters, digits, '.', '_', ':' or '-'"
        )
    operation = _clean_text(payload.get("operation"), "operation", max_chars=32)
    if not _OPERATION_RE.match(operation):
        raise RequestValidationError("field 'operation' has an unsupported format")
    chain = _clean_text(payload.get("chain"), "chain", max_chars=32).lower()
    if not _CHAIN_RE.match(chain):
        raise RequestValidationError("field 'chain' has an unsupported format")
    asset = _clean_text(payload.get("asset"), "asset", max_chars=32)
    if not _ASSET_RE.match(asset):
        raise RequestValidationError("field 'asset' has an unsupported format")
    destination = _clean_text(payload.get("destination"), "destination")
    try:
        amount = parse_amount(payload.get("amount"))
    except AmountError as exc:
        raise RequestValidationError(f"field 'amount': {exc}") from exc
    amount_raw = str(payload.get("amount")).strip()

    request_id = payload.get("request_id")
    if request_id is None:
        request_id = f"req_{secrets.token_hex(8)}"
    request_id = _clean_text(request_id, "request_id")

    idempotency_key = payload.get("idempotency_key")
    if idempotency_key is not None:
        idempotency_key = _clean_text(idempotency_key, "idempotency_key")

    client_reference = payload.get("client_reference")
    if client_reference is not None:
        client_reference = _clean_text(client_reference, "client_reference")

    extra_keys = sorted(str(k) for k in payload.keys() if str(k) not in _KNOWN_FIELDS)

    return TransactionRequest(
        request_id=request_id,
        service_id=service_id,
        operation=operation,
        chain=chain,
        asset=asset,
        amount=amount,
        destination=destination,
        amount_raw=amount_raw,
        idempotency_key=idempotency_key,
        client_reference=client_reference,
        requested_at=_utc_now(),
        simulated=simulated,
        asserted_approval_fields=tuple(asserted),
        # Record key names only: values from a caller are never copied into the
        # audit trail, where they would outlive the request.
        metadata={"unrecognised_fields": extra_keys} if extra_keys else {},
    )


class _WindowVolume:
    """Bounded rolling-window volume of authorized amounts, per service and asset."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._lock = threading.Lock()
        self._entries: Deque[tuple[float, str, Decimal]] = deque(maxlen=max_entries)

    def add(self, service_id: str, asset: str, amount: Decimal) -> None:
        with self._lock:
            self._entries.append((datetime.now(timezone.utc).timestamp(), f"{service_id}:{asset}", amount))

    def totals(self, *, window_seconds: int) -> dict[str, Decimal]:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).timestamp()
        out: dict[str, Decimal] = {}
        with self._lock:
            entries = list(self._entries)
        for at, key, amount in entries:
            if at >= cutoff:
                out[key] = out.get(key, Decimal(0)) + amount
        return out


class GuardService:
    """Evaluates requests, issues authorizations, and records everything."""

    def __init__(
        self,
        *,
        policy: PolicyConfig | None = None,
        authority: AuthorizationAuthority | None = None,
        monitor: SecurityMonitor | None = None,
        audit: AuditLog | None = None,
        signer: ReferenceSigner | None = None,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        self.audit = audit or AuditLog()
        self.monitor = monitor or SecurityMonitor()
        self.authority = authority or AuthorizationAuthority(
            replay_store=InMemoryReplayStore(),
            ttl_seconds=self.policy.authorization_ttl_seconds,
        )
        self._volume = _WindowVolume()
        self._signer = signer or ReferenceSigner(self.authority, on_outcome=self._on_sign_outcome)

    # -- evaluation ---------------------------------------------------------

    def _context(self, request: TransactionRequest) -> EvaluationContext:
        window = self.policy.window_seconds
        return EvaluationContext(
            recent_request_count=self._service_request_count(request.service_id, window),
            recent_blocked_count=self.monitor.recent_blocked_count(
                request.service_id, window_seconds=window
            ),
            recent_rejected_authorizations=self.monitor.rejected_authorization_count(
                request.service_id, window_seconds=window
            ),
            window_volume=self._volume.totals(window_seconds=window),
            now=_utc_now(),
        )

    def _service_request_count(self, service_id: str, window_seconds: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).timestamp()
        count = 0
        for event in self.monitor.events(limit=500):
            if event.get("kind") != "DECISION" or event.get("service_id") != service_id:
                continue
            at = event.get("at")
            if isinstance(at, str) and _epoch(at) >= cutoff:
                count += 1
        return count

    def evaluate(self, request: TransactionRequest) -> GuardDecision:
        """Run the controls, decide, and (on ALLOW) issue an authorization."""
        ctx = self._context(request)
        controls = evaluate_controls(request, self.policy, ctx)
        findings = tuple(f for control in controls for f in control.findings)
        decision = _worst_decision(controls)
        risk_level = _worst_severity(findings)
        decision_id = f"dec_{secrets.token_hex(10)}"
        created_at = _utc_now()

        authorization = None
        if decision is Decision.ALLOW:
            parameters = canonical_fields(
                service_id=request.service_id,
                operation=request.operation,
                chain=request.chain,
                asset=request.asset,
                amount=request.amount,
                destination=request.destination,
            )
            authorization = self.authority.issue(
                decision_id=decision_id,
                decision=decision,
                service_id=request.service_id,
                parameters=parameters,
            )

        summary, explanation = _explain(decision, request, controls, findings)
        result = GuardDecision(
            decision_id=decision_id,
            created_at=created_at,
            request=request,
            decision=decision,
            fingerprint=fingerprint_of(
                canonical_fields(
                    service_id=request.service_id,
                    operation=request.operation,
                    chain=request.chain,
                    asset=request.asset,
                    amount=request.amount,
                    destination=request.destination,
                )
            ),
            risk_level=risk_level,
            summary=summary,
            explanation=explanation,
            controls=controls,
            findings=findings,
            applicable_policies=tuple(sorted({c.policy for c in controls})),
            authorization=authorization,
            simulated=request.simulated,
        )

        if authorization is not None:
            self.monitor.record_authorization_issued(request.service_id, authorization.authorization_id)
            self._volume.add(request.service_id, request.asset.strip().upper(), request.amount)

        self.monitor.record_decision(result)
        self.audit.append(
            event_type="DECISION",
            actor=request.service_id,
            outcome=decision.value,
            detail=summary,
            request_id=request.request_id,
            decision_id=decision_id,
            authorization_id=authorization.authorization_id if authorization else None,
            service_id=request.service_id,
            extra={
                "risk_level": risk_level.value,
                "finding_codes": [f.code for f in findings],
                "controls": {c.code: c.outcome.value for c in controls},
                "simulated": request.simulated,
            },
        )
        return result

    def evaluate_payload(self, payload: dict[str, Any], *, simulated: bool = False) -> GuardDecision:
        return self.evaluate(request_from_payload(payload, simulated=simulated))

    # -- signing ------------------------------------------------------------

    def sign(self, sign_request: SignRequest) -> SignResult:
        """Hand a signing request to the reference signer (the enforcement point)."""
        return self._signer.sign(sign_request)

    def sign_transaction(
        self,
        transaction: TransactionRequest,
        authorization: Any,
        *,
        expected_service_id: str | None = None,
    ) -> SignResult:
        return self._signer.sign(
            SignRequest(
                transaction=transaction,
                authorization=authorization,
                expected_service_id=expected_service_id,
            )
        )

    def verify_authorization(
        self,
        token: Any,
        *,
        expected: dict[str, str] | RequestFingerprint | None,
        consume: bool = False,
        expected_service_id: str | None = None,
    ) -> AuthVerification:
        return self.authority.validate(
            token, expected=expected, consume=consume, expected_service_id=expected_service_id
        )

    def _on_sign_outcome(self, result: SignResult) -> None:
        incident = self.monitor.record_signer_outcome(
            service_id=result.service_id,
            authorization_id=result.authorization_id,
            outcome=result.outcome.value,
            state=result.state.value,
            detail=result.detail,
            request_id=result.request_id,
        )
        self.audit.append(
            event_type="SIGNING",
            actor=result.service_id or "unknown",
            outcome=result.outcome.value,
            detail=result.detail,
            request_id=result.request_id,
            authorization_id=result.authorization_id,
            service_id=result.service_id,
            extra={
                "state": result.state.value,
                "simulated": result.simulated,
                "incident_id": incident.incident_id if incident else None,
            },
        )

    # -- reporting ----------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        metrics = self.monitor.metrics()
        metrics["policy"] = {
            "policy_id": self.policy.policy_id,
            "name": self.policy.name,
            "version": self.policy.version,
        }
        metrics["authorization"] = {
            "key_id": self.authority.key_id,
            "ephemeral_key": self.authority.ephemeral,
            "ttl_seconds": self.authority.ttl_seconds,
        }
        metrics["audit"] = {
            "length": len(self.audit),
            "head_digest": self.audit.head_digest,
        }
        return metrics

    def incidents(self, *, status: Any = None, limit: int = 100):
        return self.monitor.incidents(status=status, limit=limit)

    def set_incident_status(self, incident_id: str, status: Any):
        updated = self.monitor.set_status(incident_id, status)
        if updated is not None:
            self.audit.append(
                event_type="INCIDENT",
                actor="operator",
                outcome=updated.status.value,
                detail=f"incident {updated.incident_id} ({updated.code}) set to {updated.status.value}",
                service_id=updated.service_id,
                extra={"incident_id": updated.incident_id, "code": updated.code},
            )
        return updated

    def audit_records(self, *, limit: int = 100):
        return self.audit.recent(limit)

    def audit_verification(self):
        return self.audit.verify()

    @property
    def signer(self) -> ReferenceSigner:
        return self._signer


def _worst_decision(controls) -> Decision:
    worst = Decision.ALLOW
    for control in controls:
        candidate = control.decision
        if candidate.severity > worst.severity:
            worst = candidate
    return worst


def _worst_severity(findings) -> FindingSeverity:
    if not findings:
        return FindingSeverity.INFO
    return max(findings, key=lambda f: f.severity.rank).severity


def _explain(decision, request, controls, findings):
    """A summary and a human-readable explanation, both derived from the controls."""
    if decision is Decision.ALLOW:
        summary = (
            f"Authorized: {request.amount_raw} {request.asset} to {request.destination} "
            f"for '{request.service_id}' passed every control."
        )
        explanation = (
            "All controls passed. A transaction-bound authorization was issued; it expires "
            "shortly and can be used once, and it is bound to these exact parameters."
        )
        return summary, explanation

    failed = [c for c in controls if c.outcome is not ControlOutcome.PASS]
    reasons = "; ".join(f"{c.title}: {c.detail}" for c in failed)
    headline = {
        Decision.BLOCK: "Blocked",
        Decision.HOLD: "Held for investigation",
        Decision.REQUIRE_APPROVAL: "Approval required",
    }[decision]
    summary = (
        f"{headline}: {request.amount_raw} {request.asset} to {request.destination} "
        f"for '{request.service_id}'."
    )
    explanation = reasons or "No control detail was recorded."
    if decision is not Decision.ALLOW:
        explanation += (
            " No authorization was issued, so a signer that consults TraceSettle will refuse "
            "this transaction."
        )
    return summary, explanation


def _epoch(iso_seconds: str) -> float:
    try:
        return datetime.strptime(iso_seconds, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        ).timestamp()
    except ValueError:
        return 0.0
