"""Typed model for the transaction security layer.

Design rules, mirroring the settlement engine:

* A request is *described*, never trusted. Client-supplied approval flags are
  recorded and reported, never honoured.
* Every decision is the deterministic maximum of the evaluated control results.
  Identical inputs produce an identical decision.
* Amounts are exact decimals, never floats. A value that cannot be parsed is a
  finding, never a silent zero.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

#: Guards against absurd exponent/precision inputs. A real transfer is nowhere
#: near this, and an unbounded Decimal is a cheap denial-of-service vector.
MAX_AMOUNT_DIGITS = 40
MAX_AMOUNT_SCALE = 18

#: Fields a caller might send hoping to skip evaluation. They are never honoured.
#: Their presence is itself a finding.
ASSERTED_APPROVAL_FIELDS = frozenset(
    {
        "approved",
        "approve",
        "authorized",
        "authorised",
        "auto_approve",
        "skip_checks",
        "skip_policy",
        "bypass",
        "trusted",
        "force",
        "override",
    }
)


class Decision(str, enum.Enum):
    """Outcome of a pre-execution evaluation."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    HOLD = "HOLD"
    BLOCK = "BLOCK"

    @property
    def severity(self) -> int:
        return _DECISION_SEVERITY[self]


_DECISION_SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.HOLD: 2,
    Decision.BLOCK: 3,
}

#: Decisions that must never yield a signing authorization.
NON_AUTHORIZING_DECISIONS = frozenset({Decision.BLOCK, Decision.HOLD, Decision.REQUIRE_APPROVAL})


class FindingSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _FINDING_RANK[self]


_FINDING_RANK: dict[FindingSeverity, int] = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


class ControlOutcome(str, enum.Enum):
    """What one deterministic control concluded.

    ``PASS``     — the control ran and the request satisfies it.
    ``NOTICE``   — informational; does not change the decision.
    ``REVIEW``   — a human must approve before signing.
    ``HOLD``     — the control could not be evaluated safely; do not authorize.
    ``BLOCK``    — the request must never reach a signer.
    """

    PASS = "PASS"
    NOTICE = "NOTICE"
    REVIEW = "REVIEW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"

    @property
    def decision(self) -> Decision:
        return _OUTCOME_DECISION[self]


_OUTCOME_DECISION: dict[ControlOutcome, Decision] = {
    ControlOutcome.PASS: Decision.ALLOW,
    ControlOutcome.NOTICE: Decision.ALLOW,
    ControlOutcome.REVIEW: Decision.REQUIRE_APPROVAL,
    ControlOutcome.HOLD: Decision.HOLD,
    ControlOutcome.BLOCK: Decision.BLOCK,
}


class AuthState(str, enum.Enum):
    """Result of validating a transaction-bound authorization.

    Every non-``VALID`` state is a refusal. There is no state that means
    "probably fine": the signer refuses unless the state is exactly ``VALID``.
    """

    VALID = "VALID"
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    WRONG_PARAMETERS = "WRONG_PARAMETERS"
    WRONG_SERVICE = "WRONG_SERVICE"
    REPLAYED = "REPLAYED"
    REVOKED = "REVOKED"
    NON_AUTHORIZING_DECISION = "NON_AUTHORIZING_DECISION"
    #: The durable state store could not be read, so single-use/replay could not
    #: be proven. A refusal, never an acceptance.
    STATE_STORE_UNAVAILABLE = "STATE_STORE_UNAVAILABLE"

    @property
    def valid(self) -> bool:
        return self is AuthState.VALID


class SignOutcome(str, enum.Enum):
    """What the reference signer did."""

    #: The authorization was valid and the simulated executor ran.
    EXECUTED = "EXECUTED"
    #: The signer refused; nothing was executed.
    REFUSED = "REFUSED"
    #: The authorization was valid but the executor reported a failure.
    FAILED = "FAILED"


@dataclass(frozen=True)
class SignResult:
    """The outcome of one signing attempt.

    ``state`` is the authorization state that decided the outcome. On a refusal
    it is never ``VALID``; on an execution it is exactly ``VALID``.
    """

    outcome: SignOutcome
    state: AuthState
    detail: str
    authorization_id: str | None = None
    service_id: str | None = None
    request_id: str | None = None
    simulated: bool = False
    receipt: dict[str, Any] | None = None

    @property
    def executed(self) -> bool:
        return self.outcome is SignOutcome.EXECUTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "state": self.state.value,
            "detail": self.detail,
            "authorization_id": self.authorization_id,
            "service_id": self.service_id,
            "request_id": self.request_id,
            "simulated": self.simulated,
            "receipt": self.receipt,
        }



class IncidentSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _INCIDENT_RANK[self]


_INCIDENT_RANK: dict[IncidentSeverity, int] = {
    IncidentSeverity.LOW: 0,
    IncidentSeverity.MEDIUM: 1,
    IncidentSeverity.HIGH: 2,
    IncidentSeverity.CRITICAL: 3,
}


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


# ---------------------------------------------------------------------------
# Amounts
# ---------------------------------------------------------------------------


class AmountError(ValueError):
    """Raised when an amount string cannot be used safely."""


def parse_amount(raw: Any) -> Decimal:
    """Parse a transfer amount into an exact non-negative Decimal.

    Rejects floats (which cannot represent decimal money), NaN, infinities,
    negative values, and absurd precision. Raises :class:`AmountError` with a
    short reason that is safe to show a client.
    """
    if isinstance(raw, bool) or isinstance(raw, float):
        raise AmountError("amount must be a decimal string, not a float or boolean")
    if isinstance(raw, int):
        text = str(raw)
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        raise AmountError("amount must be a decimal string")
    if not text:
        raise AmountError("amount is empty")
    try:
        value = Decimal(text)
    except (InvalidOperation, ValueError) as exc:
        raise AmountError("amount is not a valid decimal number") from exc
    if not value.is_finite():
        raise AmountError("amount must be finite")
    if value < 0:
        raise AmountError("amount must not be negative")
    sign, digits, exponent = value.as_tuple()
    if len(digits) > MAX_AMOUNT_DIGITS:
        raise AmountError("amount has too many significant digits")
    if isinstance(exponent, int) and exponent < -MAX_AMOUNT_SCALE:
        raise AmountError("amount has too many decimal places")
    return value


def canonical_amount(value: Decimal) -> str:
    """A stable string for hashing: no exponent, no trailing zeros, no sign."""
    normalized = value.normalize()
    # ``normalize`` can produce an exponent form (1E+2); format it back out.
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransactionRequest:
    """A transaction-requesting application's intent, as declared.

    Nothing here is trusted. It is validated against policy and against the
    authorization the signer later receives.
    """

    request_id: str
    service_id: str
    operation: str
    chain: str
    asset: str
    amount: Decimal
    destination: str
    amount_raw: str
    idempotency_key: str | None = None
    client_reference: str | None = None
    requested_at: str | None = None
    #: True when this request is part of a labelled, controlled simulation.
    simulated: bool = False
    #: Caller-supplied fields that must never influence the decision.
    asserted_approval_fields: tuple[str, ...] = ()
    #: Free-form extras, recorded for audit but never evaluated as policy input.
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "service_id": self.service_id,
            "operation": self.operation,
            "chain": self.chain,
            "asset": self.asset,
            "amount": self.amount_raw,
            "destination": self.destination,
            "idempotency_key": self.idempotency_key,
            "client_reference": self.client_reference,
            "requested_at": self.requested_at,
            "simulated": self.simulated,
            "asserted_approval_fields": list(self.asserted_approval_fields),
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class RequestFingerprint:
    """A canonical digest of the security-relevant parameters of a request.

    The signer recomputes this from the *actual* transaction it is asked to sign
    and compares it to the value inside the authorization. Any substitution of
    destination, amount, asset, chain, operation, or service changes the digest,
    so a swapped parameter cannot ride on a valid authorization.
    """

    digest: str
    fields: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {"digest": self.digest, "fields": dict(self.fields)}


def canonical_fields(
    *,
    service_id: str,
    operation: str,
    chain: str,
    asset: str,
    amount: Decimal,
    destination: str,
) -> dict[str, str]:
    """The exact parameter set that an authorization is bound to.

    Case is normalised only where the chain's own encoding is case-insensitive
    (EVM hex addresses, asset symbols, chain ids, operations). Addresses are
    compared exactly otherwise.
    """
    chain_norm = chain.strip().lower()
    dest = destination.strip()
    if dest[:2].lower() == "0x":
        dest = "0x" + dest[2:].lower()
    return {
        "service_id": service_id.strip(),
        "operation": operation.strip().upper(),
        "chain": chain_norm,
        "asset": asset.strip().upper(),
        "amount": canonical_amount(amount),
        "destination": dest,
    }


def fingerprint_of(fields: dict[str, str]) -> RequestFingerprint:
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return RequestFingerprint(digest=hashlib.sha256(payload).hexdigest(), fields=dict(fields))


def fingerprint_request(request: TransactionRequest) -> RequestFingerprint:
    return fingerprint_of(
        canonical_fields(
            service_id=request.service_id,
            operation=request.operation,
            chain=request.chain,
            asset=request.asset,
            amount=request.amount,
            destination=request.destination,
        )
    )


# ---------------------------------------------------------------------------
# Controls and decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskFinding:
    """One explained, deterministic observation about a request."""

    code: str
    severity: FindingSeverity
    title: str
    detail: str
    policy: str
    #: The request parameters that triggered it, so the finding is reproducible.
    observed: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "policy": self.policy,
            "observed": dict(self.observed),
        }


@dataclass(frozen=True)
class ControlResult:
    """The result of one named control.

    A control is a pure function of (request, policy, context). It always
    reports a stable ``code`` and a human-readable ``detail``, so the decision
    can be explained without re-deriving it.
    """

    code: str
    title: str
    outcome: ControlOutcome
    detail: str
    policy: str
    findings: tuple[RiskFinding, ...] = ()

    @property
    def decision(self) -> Decision:
        return self.outcome.decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "outcome": self.outcome.value,
            "decision": self.decision.value,
            "detail": self.detail,
            "policy": self.policy,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class EvaluationContext:
    """Read-only facts from outside the request that a control may consult.

    These are supplied by the service from its own stores (velocity history,
    incident history). They are never taken from the request itself.
    """

    recent_request_count: int = 0
    recent_blocked_count: int = 0
    recent_rejected_authorizations: int = 0
    #: Sum of amounts already authorized for this service/asset in the window.
    window_volume: dict[str, Decimal] = field(default_factory=dict)
    now: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "recent_request_count": self.recent_request_count,
            "recent_blocked_count": self.recent_blocked_count,
            "recent_rejected_authorizations": self.recent_rejected_authorizations,
            "window_volume": {k: canonical_amount(v) for k, v in self.window_volume.items()},
            "now": self.now,
        }


@dataclass(frozen=True)
class GuardDecision:
    """The complete, explainable, auditable result of a pre-execution evaluation."""

    decision_id: str
    created_at: str
    request: TransactionRequest
    decision: Decision
    fingerprint: RequestFingerprint
    risk_level: FindingSeverity
    summary: str
    explanation: str
    controls: tuple[ControlResult, ...] = ()
    findings: tuple[RiskFinding, ...] = ()
    applicable_policies: tuple[str, ...] = ()
    #: Present only when the decision is ALLOW.
    authorization: Any = None
    #: An internal, never-exposed key material reference is deliberately absent:
    #: this process holds no private key.
    simulated: bool = False
    #: The safeguards that changed this decision, if any (the learning loop).
    safeguards_applied: tuple[Any, ...] = ()
    #: Human-readable reasons each applied safeguard fired.
    safeguard_reasons: tuple[str, ...] = ()
    #: The lesson this decision created, if it created one.
    learned_safeguard: Any = None

    @property
    def authorizes_signing(self) -> bool:
        return self.decision is Decision.ALLOW and self.authorization is not None

    @property
    def influenced_by_learning(self) -> bool:
        return bool(self.safeguards_applied)

    def to_dict(self, *, include_authorization: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "decision_id": self.decision_id,
            "created_at": self.created_at,
            "request": self.request.to_dict(),
            "decision": self.decision.value,
            "risk_level": self.risk_level.value,
            "summary": self.summary,
            "explanation": self.explanation,
            "fingerprint": self.fingerprint.to_dict(),
            "applicable_policies": list(self.applicable_policies),
            "findings": [f.to_dict() for f in self.findings],
            "controls": [c.to_dict() for c in self.controls],
            "simulated": self.simulated,
            "authorizes_signing": self.authorizes_signing,
            "safeguards_applied": [
                s.to_dict() if hasattr(s, "to_dict") else s for s in self.safeguards_applied
            ],
            "safeguard_reasons": list(self.safeguard_reasons),
            "influenced_by_learning": self.influenced_by_learning,
            "learned_safeguard": (
                self.learned_safeguard.to_dict()
                if hasattr(self.learned_safeguard, "to_dict")
                else self.learned_safeguard
            ),
        }
        if include_authorization and self.authorization is not None:
            out["authorization"] = self.authorization.to_dict()
        return out


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Incident:
    incident_id: str
    created_at: str
    updated_at: str
    severity: IncidentSeverity
    status: IncidentStatus
    code: str
    title: str
    detail: str
    service_id: str | None = None
    request_id: str | None = None
    decision_id: str | None = None
    occurrence_count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "severity": self.severity.value,
            "status": self.status.value,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "service_id": self.service_id,
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "occurrence_count": self.occurrence_count,
        }
