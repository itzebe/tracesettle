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
    ControlResult,
    Decision,
    EvaluationContext,
    FindingSeverity,
    GuardDecision,
    RequestFingerprint,
    RiskFinding,
    SignResult,
    TransactionRequest,
    canonical_fields,
    fingerprint_of,
    parse_amount,
)
from .learning import LearningLoop, SafeguardApplication
from .monitor import SecurityMonitor
from .policy import DEFAULT_POLICY, PolicyConfig
from .rules import evaluate_controls
from .signer import ReferenceSigner, SignRequest
from .state import (
    EVENT_AUTHORIZATION_ISSUED,
    EVENT_DECISION,
    EVENT_SIGNER,
    OUTCOME_BLOCK,
    OUTCOME_EXECUTED,
    GuardStateStore,
    StateStoreError,
)

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
        state_store: GuardStateStore | None = None,
        http_client: Any = None,
        safeguard_store: Any = None,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        # ``is not None`` rather than truthiness: an empty AuditLog is falsy
        # (it defines __len__), so ``audit or AuditLog()`` would silently drop a
        # configured persistent log on every fresh start.
        self.audit = audit if audit is not None else AuditLog()
        self.monitor = monitor or SecurityMonitor()
        #: The learning loop. When no safeguard store is configured it is inert,
        #: so a deployment without durable learning behaves exactly as before.
        self.learning = LearningLoop(safeguard_store)
        #: When set, the counters that decide velocity, volume, and rejection
        #: limits are read from and written to durable storage, so a restart does
        #: not reset a limit. When None the guard keeps its in-memory behaviour.
        self.state_store = state_store
        self.authority = authority or AuthorizationAuthority(
            replay_store=InMemoryReplayStore(),
            ttl_seconds=self.policy.authorization_ttl_seconds,
        )
        self._volume = _WindowVolume()
        self._signer = signer or ReferenceSigner(self.authority, on_outcome=self._on_sign_outcome)
        #: Optional HTTP client used only by the NEAR policy adapter to read
        #: provider policy state. None disables live reads; a local fixture is
        #: then used. The guard itself never performs network I/O.
        self.http_client = http_client

    # -- evaluation ---------------------------------------------------------

    def _context(self, request: TransactionRequest) -> EvaluationContext:
        window = self.policy.window_seconds
        if self.state_store is not None:
            return self._durable_context(request, window)
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

    def _durable_context(self, request: TransactionRequest, window: int) -> EvaluationContext:
        """Build the context from durable counters.

        Raises :class:`StateStoreError` on a database problem; :meth:`evaluate`
        turns that into a fail-closed HOLD rather than evaluating against an
        empty (and therefore permissive) context.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window)).timestamp()
        events = self.state_store.events_since(since=cutoff)  # type: ignore[union-attr]
        request_count = 0
        blocked_count = 0
        rejected_count = 0
        volume: dict[str, Decimal] = {}
        for event in events:
            if event.kind == EVENT_DECISION:
                if event.service_id != request.service_id:
                    continue
                request_count += 1
                if event.outcome == OUTCOME_BLOCK:
                    blocked_count += 1
            elif event.kind == EVENT_AUTHORIZATION_ISSUED:
                if event.service_id != request.service_id:
                    continue
                asset = (event.asset or "").strip().upper()
                if asset and event.amount is not None:
                    key = f"{request.service_id}:{asset}"
                    volume[key] = volume.get(key, Decimal(0)) + event.amount
            elif event.kind == EVENT_SIGNER:
                if event.outcome == OUTCOME_EXECUTED:
                    continue
                if event.service_id != request.service_id:
                    continue
                rejected_count += 1
        return EvaluationContext(
            recent_request_count=request_count,
            recent_blocked_count=blocked_count,
            recent_rejected_authorizations=rejected_count,
            window_volume=volume,
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
        """Run the controls, decide, and (on ALLOW) issue an authorization.

        When a durable store is configured, the entire read-decide-record cycle
        runs in one database transaction (``BEGIN IMMEDIATE``). That is what stops
        two concurrent evaluations from both reading an empty window and both
        authorizing past the limit. A store error anywhere in the cycle rolls the
        transaction back and yields a fail-closed HOLD, so no authorization is
        issued against state that could not be read.
        """
        if self.state_store is None:
            return self._finalize(request, self._evaluate_locked(request))
        try:
            with self.state_store.decision_cycle():
                result = self._evaluate_locked(request)
        except StateStoreError as exc:
            return self._fail_closed(request, exc)
        return self._finalize(request, result)

    def _evaluate_locked(self, request: TransactionRequest) -> GuardDecision:
        """The body of a decision: read counters, run controls, claim, issue.

        Pure with respect to the process-local monitor and audit log; those are
        written by :meth:`_finalize` only after the durable transaction commits,
        so a rolled-back decision is never recorded as if it had happened.
        """
        ctx = self._context(request)
        controls = evaluate_controls(request, self.policy, ctx)
        findings = tuple(f for control in controls for f in control.findings)
        decision = _worst_decision(controls)
        risk_level = _worst_severity(findings)
        decision_id = f"dec_{secrets.token_hex(10)}"
        created_at = _utc_now()

        # The learning loop: apply any durable safeguard learned from a previous
        # security failure. A safeguard only ever *tightens* the decision, so this
        # can turn an ALLOW into REQUIRE_APPROVAL or HOLD, never the reverse. It is
        # applied before the idempotency claim so a safeguarded request never
        # consumes a client idempotency key as if it had been authorized.
        application = self.learning.apply(request)
        safeguards_applied: tuple[Any, ...] = ()
        safeguard_reasons: tuple[str, ...] = ()
        if application.applied and application.decision is not None:
            decision = _stricter(decision, application.decision)
            safeguards_applied = application.safeguards
            safeguard_reasons = application.reasons
            findings = findings + (
                RiskFinding(
                    code="LEARNED_SAFEGUARD_APPLIED",
                    severity=FindingSeverity.HIGH,
                    title="A learned safeguard tightened this decision",
                    detail=" ".join(application.reasons),
                    policy="learning loop (durable safeguard)",
                    observed={"safeguard_ids": ", ".join(application.safeguard_ids)},
                ),
            )
            risk_level = _worst_severity(findings)

        # Idempotency: an ALLOW with a client idempotency key is claimed durably
        # before the authorization is issued, so a retried request cannot obtain a
        # second token or be accounted twice. A key already claimed is a duplicate.
        if decision is Decision.ALLOW and request.idempotency_key and self.state_store is not None:
            key = f"{request.service_id}:{request.idempotency_key}"
            if not self.state_store.remember_decision(key, decision_id):
                return _build_hold_decision(
                    request,
                    code="DUPLICATE_REQUEST",
                    title="Duplicate request (idempotency key already used)",
                    detail=(
                        f"Idempotency key '{request.idempotency_key}' was already decided for "
                        f"'{request.service_id}'; no second authorization is issued."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )

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
        if safeguard_reasons:
            explanation = explanation + " " + " ".join(safeguard_reasons)

        # The learning loop records the lesson of this decision, if it teaches one.
        # It runs after the decision is fixed so a lesson can never change the
        # decision that produced it; it only affects later requests.
        learned_safeguard = self.learning.observe(
            request,
            decision,
            tuple(f.code for f in findings),
            decision_id=decision_id,
        )

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
            safeguards_applied=safeguards_applied,
            safeguard_reasons=safeguard_reasons,
            learned_safeguard=learned_safeguard,
        )

        if self.state_store is not None:
            self._record_durable_decision(request, decision, authorization)
        return result

    def _finalize(self, request: TransactionRequest, result: GuardDecision) -> GuardDecision:
        """Record a decided result in the process-local monitor and the audit log."""
        if result.authorization is not None:
            self.monitor.record_authorization_issued(
                request.service_id, result.authorization.authorization_id
            )
            self._volume.add(request.service_id, request.asset.strip().upper(), request.amount)
        if result.influenced_by_learning:
            self.learning.note_applied(
                SafeguardApplication(
                    decision=result.decision,
                    reasons=result.safeguard_reasons,
                    safeguard_ids=tuple(
                        getattr(s, "safeguard_id", "") for s in result.safeguards_applied
                    ),
                    safeguards=result.safeguards_applied,
                )
            )
        self.monitor.record_decision(result)
        self.audit.append(
            event_type="DECISION",
            actor=request.service_id,
            outcome=result.decision.value,
            detail=result.summary,
            request_id=request.request_id,
            decision_id=result.decision_id,
            authorization_id=result.authorization.authorization_id if result.authorization else None,
            service_id=request.service_id,
            extra={
                "risk_level": result.risk_level.value,
                "finding_codes": [f.code for f in result.findings],
                "controls": {c.code: c.outcome.value for c in result.controls},
                "simulated": request.simulated,
            },
        )
        return result

    def evaluate_agent_transaction(
        self,
        payload: dict[str, Any],
        *,
        policy_read: Any = None,
        access_key: Any = None,
    ) -> Any:
        """Evaluate an agent transaction through the NEAR authorization wrapper.

        This is the pre-execution boundary an AI agent must pass before it may
        sign. The wrapper inspects the *actual* transaction parameters (never the
        agent's explanation), the NEAR Intents policy scope, and the access-key
        scope, and returns one of ALLOW, REQUIRE_APPROVAL, BLOCK, HOLD or
        UNKNOWN. Nothing is signed or broadcast here.

        Imported lazily so the NEAR integration never becomes a hard dependency
        of the core guard, and so a deployment that does not use it pays nothing.
        """
        from ..near.agent_wrapper import AgentAuthorizationWrapper, AgentTransaction
        from ..near.policy import PolicyScope

        scope_raw = str(payload.get("scope", "INTENTS")).strip().upper()
        try:
            scope = PolicyScope(scope_raw)
        except ValueError as exc:
            raise RequestValidationError(
                "field 'scope' must be one of INTENTS, NATIVE_NEAR, NATIVE_EVM, NATIVE_SOLANA"
            ) from exc

        asserted = tuple(
            str(k)
            for k, v in payload.items()
            if str(k).strip().lower() in ASSERTED_APPROVAL_FIELDS and v not in (None, False, 0, "", [], {})
        )
        transaction = AgentTransaction(
            service_id=str(payload.get("service_id", "")),
            operation=str(payload.get("operation", "")),
            chain=str(payload.get("chain", "")),
            asset=str(payload.get("asset", "")),
            amount=str(payload.get("amount", "")),
            destination=str(payload.get("destination", "")),
            scope=scope,
            policy_action=(str(payload["policy_action"]) if payload.get("policy_action") else None),
            request_id=(str(payload["request_id"]) if payload.get("request_id") else None),
            idempotency_key=(
                str(payload["idempotency_key"]) if payload.get("idempotency_key") else None
            ),
            client_reference=(
                str(payload["client_reference"]) if payload.get("client_reference") else None
            ),
            receiver_id=(str(payload["receiver_id"]) if payload.get("receiver_id") else None),
            method_name=(str(payload["method_name"]) if payload.get("method_name") else None),
            transfers_near=bool(payload.get("transfers_near", False)),
            simulated=bool(payload.get("simulated", True)),
            asserted_approval_fields=asserted,
            metadata=(
                payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            ),
        )
        wrapper = AgentAuthorizationWrapper(
            self, policy_read=policy_read, access_key=access_key
        )
        return wrapper.evaluate(transaction)

    def evaluate_payload(self, payload: dict[str, Any], *, simulated: bool = False) -> GuardDecision:
        return self.evaluate(request_from_payload(payload, simulated=simulated))

    # -- durable counters ---------------------------------------------------

    def _record_durable_decision(self, request, decision, authorization) -> None:
        """Append the durable counter events for one decision.

        The volume event is written only when an authorization was issued, so a
        duplicate or failed evaluation can never be accounted twice. The
        idempotency claim (if any) was made earlier in :meth:`_evaluate_locked`.

        A :class:`StateStoreError` is deliberately **not** caught here: this runs
        inside the decision transaction, so raising rolls the whole decision back
        and :meth:`evaluate` turns it into a fail-closed HOLD. A decision whose
        counters could not be persisted must not become an authorization.
        """
        self.state_store.record_event(  # type: ignore[union-attr]
            kind=EVENT_DECISION,
            service_id=request.service_id,
            outcome=decision.value,
        )
        if authorization is not None:
            self.state_store.record_event(  # type: ignore[union-attr]
                kind=EVENT_AUTHORIZATION_ISSUED,
                service_id=request.service_id,
                asset=request.asset.strip().upper(),
                amount=request.amount,
            )

    def _fail_closed(self, request: TransactionRequest, exc: StateStoreError) -> GuardDecision:
        """Return a HOLD decision when the durable state store cannot be read.

        This is the fail-closed path: without the counters we cannot prove the
        request is within its limits, so we never ALLOW. No authorization is
        issued, so a signer that consults TraceSettle refuses.
        """
        detail = (
            "The durable authorization state store could not be read, so velocity, "
            "volume, and rejection limits cannot be enforced. The request is held."
        )
        result = _build_hold_decision(
            request,
            code="STATE_STORE_UNAVAILABLE",
            title="Durable state store unavailable",
            detail=detail,
            severity=FindingSeverity.HIGH,
        )
        self.monitor.open_incident(
            code="STATE_STORE_UNAVAILABLE",
            severity=FindingSeverity.HIGH,
            title="Durable state store unavailable",
            detail=str(exc),
            service_id=request.service_id,
            request_id=request.request_id,
            decision_id=result.decision_id,
        )
        return self._finalize(request, result)

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
        if self.state_store is not None:
            try:
                self.state_store.record_event(
                    kind=EVENT_SIGNER,
                    service_id=result.service_id or "unknown",
                    outcome=result.outcome.value,
                )
            except StateStoreError:
                self.monitor.open_incident(
                    code="STATE_STORE_UNAVAILABLE",
                    severity=FindingSeverity.HIGH,
                    title="Durable state store write failed",
                    detail="A signer counter event could not be persisted; the next evaluation will fail closed.",
                    service_id=result.service_id,
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
        metrics["state"] = {
            "backend": getattr(self.state_store, "backend", "in-memory")
            if self.state_store is not None
            else "in-memory",
            "durable": self.state_store is not None,
            "note": (
                (
                    "durable shared state across instances"
                    if getattr(self.state_store, "backend", "") == "postgresql"
                    else "durable single-instance state"
                )
                if self.state_store is not None
                else "process-local: spent nonces and counters reset on restart"
            ),
        }
        metrics["audit"] = {
            "length": len(self.audit),
            "head_digest": self.audit.head_digest,
        }
        metrics["learning"] = {
            "enabled": self.learning.enabled,
            "backend": getattr(self.learning.store, "backend", "in-memory")
            if self.learning.enabled
            else "disabled",
            "safeguards": len(self.learning.list()),
            "note": (
                "durable safeguards: a security failure tightens later decisions"
                if self.learning.enabled
                else "learning loop disabled: no durable safeguard store is configured"
            ),
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


def _build_hold_decision(
    request: TransactionRequest,
    *,
    code: str,
    title: str,
    detail: str,
    severity: FindingSeverity,
) -> GuardDecision:
    """Build a HOLD decision with no authorization, for the guard's refuse paths.

    Used where the guard cannot (or must not) authorize: an unreadable state
    store, a duplicate request, or any future control that can only refuse. The
    decision is recorded by the caller, not here, so it travels through the same
    finalize path as a normal decision.
    """
    decision_id = f"dec_{secrets.token_hex(10)}"
    finding = RiskFinding(
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        policy="durable state",
        observed={},
    )
    control = ControlResult(
        code="STATE_STORE",
        title=title,
        outcome=ControlOutcome.HOLD,
        detail=detail,
        policy="durable state",
        findings=(finding,),
    )
    return GuardDecision(
        decision_id=decision_id,
        created_at=_utc_now(),
        request=request,
        decision=Decision.HOLD,
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
        risk_level=severity,
        summary=f"Held: {request.amount_raw} {request.asset} to {request.destination} for "
        f"'{request.service_id}' could not be authorized.",
        explanation=detail,
        controls=(control,),
        findings=(finding,),
        applicable_policies=("durable state",),
        authorization=None,
        simulated=request.simulated,
    )


def _worst_decision(controls) -> Decision:
    worst = Decision.ALLOW
    for control in controls:
        candidate = control.decision
        if candidate.severity > worst.severity:
            worst = candidate
    return worst


def _stricter(current: Decision, candidate: Decision) -> Decision:
    """The stricter of two decisions. Used by the learning loop, never the reverse."""
    return candidate if candidate.severity > current.severity else current


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
