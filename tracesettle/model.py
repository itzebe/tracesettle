"""Typed evidence model.

Design rule: an adapter records *what a source returned* (facts + provenance).
It never decides whether the transaction settled. Reconciliation state is
computed exclusively by :mod:`tracesettle.reconcile`.

Two axes are kept strictly separate:

* ``StageState``      — how far the *transaction* got.
* ``SourceStatus``    — whether the *source* could be queried.

An unavailable source can never, on its own, advance or regress a stage.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Stage(str, enum.Enum):
    """Ordered transaction stages for the supported ORIGIN_CHAIN swap path."""

    SOURCE_CHAIN_DEPOSIT = "SOURCE_CHAIN_DEPOSIT"
    BRIDGE_DEPOSIT_CREDIT = "BRIDGE_DEPOSIT_CREDIT"
    NEAR_SETTLEMENT = "NEAR_SETTLEMENT"
    DESTINATION_CHAIN_DELIVERY = "DESTINATION_CHAIN_DELIVERY"
    REFUND = "REFUND"


#: Canonical chronological order of the happy path (REFUND is off-path).
STAGE_ORDER: tuple[Stage, ...] = (
    Stage.SOURCE_CHAIN_DEPOSIT,
    Stage.BRIDGE_DEPOSIT_CREDIT,
    Stage.NEAR_SETTLEMENT,
    Stage.DESTINATION_CHAIN_DELIVERY,
)


class EventType(str, enum.Enum):
    """What kind of thing was observed."""

    SOURCE_TX_INCLUDED = "SOURCE_TX_INCLUDED"
    SOURCE_TX_EXECUTED = "SOURCE_TX_EXECUTED"
    DEPOSIT_OBSERVED = "DEPOSIT_OBSERVED"
    UPSTREAM_STATUS = "UPSTREAM_STATUS"
    SETTLEMENT_CLAIMED = "SETTLEMENT_CLAIMED"
    NEAR_TX_INCLUDED = "NEAR_TX_INCLUDED"
    NEAR_TX_FINAL = "NEAR_TX_FINAL"
    NEAR_TX_EXECUTION = "NEAR_TX_EXECUTION"
    INTENT_EVENT_OBSERVED = "INTENT_EVENT_OBSERVED"
    INTENT_WITHDRAWAL_OBSERVED = "INTENT_WITHDRAWAL_OBSERVED"
    DESTINATION_TX_INCLUDED = "DESTINATION_TX_INCLUDED"
    DESTINATION_TX_EXECUTED = "DESTINATION_TX_EXECUTED"
    DESTINATION_TRANSFER_OBSERVED = "DESTINATION_TRANSFER_OBSERVED"
    REFUND_CLAIMED = "REFUND_CLAIMED"
    REFUND_TX_CONFIRMED = "REFUND_TX_CONFIRMED"
    SOURCE_ISSUE = "SOURCE_ISSUE"


class Verification(str, enum.Enum):
    """Verification classification of a single evidence item."""

    #: Supported by the required authoritative evidence.
    CONFIRMED = "CONFIRMED"
    #: Stated by an upstream service but not independently verified.
    REPORTED = "REPORTED"
    #: Expected evidence has not been obtained.
    MISSING = "MISSING"
    #: The required source could not be queried or does not support the operation.
    UNAVAILABLE = "UNAVAILABLE"
    #: The source was reachable, but a required search could not be completed, so
    #: the evidence is insufficient. Distinct from UNAVAILABLE (a source problem):
    #: here the source answered and simply could not be searched exhaustively.
    INCOMPLETE = "INCOMPLETE"
    #: Independently obtained evidence conflicts in a material way.
    CONTRADICTORY = "CONTRADICTORY"
    #: Evidence belongs to a controlled test case, not a real transaction.
    SIMULATED = "SIMULATED"


class SourceStatus(str, enum.Enum):
    """Outcome of querying a data source (source health, not transaction state)."""

    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    UNAUTHORIZED = "UNAUTHORIZED"
    RATE_LIMITED = "RATE_LIMITED"
    SERVER_ERROR = "SERVER_ERROR"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    MALFORMED = "MALFORMED"
    UNSUPPORTED = "UNSUPPORTED"


#: Source outcomes that mean "we could not learn anything", never "it failed".
SOURCE_UNAVAILABLE_STATUSES = frozenset(
    {
        SourceStatus.UNAUTHORIZED,
        SourceStatus.RATE_LIMITED,
        SourceStatus.SERVER_ERROR,
        SourceStatus.TIMEOUT,
        SourceStatus.NETWORK_ERROR,
        SourceStatus.MALFORMED,
        SourceStatus.UNSUPPORTED,
    }
)


class Provenance(str, enum.Enum):
    """Where a piece of evidence came from."""

    REAL = "REAL"
    SIMULATED = "SIMULATED"


class StageState(str, enum.Enum):
    """Reconciled state of a transaction stage."""

    #: Required authoritative evidence obtained.
    CONFIRMED = "CONFIRMED"
    #: Reported by an upstream service; not independently verified.
    REPORTED = "REPORTED"
    #: No evidence either way.
    MISSING = "MISSING"
    #: The source needed to assess it could not be queried.
    UNAVAILABLE = "UNAVAILABLE"
    #: Independent evidence materially conflicts.
    CONTRADICTORY = "CONTRADICTORY"
    #: Evidence exists only in a simulated test case.
    SIMULATED = "SIMULATED"
    #: Evidence was insufficient to decide.
    UNKNOWN = "UNKNOWN"


class OverallOutcome(str, enum.Enum):
    """Top-level investigation verdict."""

    SETTLED_VERIFIED = "SETTLED_VERIFIED"
    SETTLED_REPORTED_ONLY = "SETTLED_REPORTED_ONLY"
    DELIVERY_UNVERIFIED = "DELIVERY_UNVERIFIED"
    REFUND_VERIFIED = "REFUND_VERIFIED"
    REFUND_REPORTED_UNVERIFIED = "REFUND_REPORTED_UNVERIFIED"
    FAILED_VERIFIED = "FAILED_VERIFIED"
    FAILED_REPORTED_UNVERIFIED = "FAILED_REPORTED_UNVERIFIED"
    INCOMPLETE = "INCOMPLETE"
    CONTRADICTORY = "CONTRADICTORY"
    NOT_FOUND = "NOT_FOUND"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class IdentifierType(str, enum.Enum):
    DEPOSIT_ADDRESS = "DEPOSIT_ADDRESS"
    ORIGIN_CHAIN_TX_HASH = "ORIGIN_CHAIN_TX_HASH"
    INTENT_HASH = "INTENT_HASH"
    NEAR_TX_HASH = "NEAR_TX_HASH"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceItem:
    """One normalized piece of evidence from one source."""

    id: str
    stage: Stage
    event_type: EventType
    source: str
    verification: Verification
    provenance: Provenance = Provenance.REAL
    source_record_id: str | None = None
    tx_hash: str | None = None
    chain: str | None = None
    reported_status: str | None = None
    timestamp: str | None = None
    evidence_url: str | None = None
    #: How the verification class was reached (e.g. a locally recomputed txid, a
    #: script-level match, an upstream report). ``None`` when the source states the
    #: fact without a distinct method.
    verification_method: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # ``limitations`` must be a tuple of strings. A bare string passed by
        # mistake would otherwise iterate character by character in ``to_dict``
        # and every renderer, turning one limitation into a list of letters.
        if isinstance(self.limitations, str):
            object.__setattr__(self, "limitations", (self.limitations,))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "stage": self.stage.value,
            "event_type": self.event_type.value,
            "source": self.source,
            "verification": self.verification.value,
            "provenance": self.provenance.value,
            "source_record_id": self.source_record_id,
            "tx_hash": self.tx_hash,
            "chain": self.chain,
            "reported_status": self.reported_status,
            "timestamp": self.timestamp,
            "evidence_url": self.evidence_url,
            "verification_method": self.verification_method,
            "details": self.details,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class SourceReport:
    """Result of querying one source: health + the evidence it produced."""

    source: str
    status: SourceStatus
    evidence: tuple[EvidenceItem, ...] = ()
    message: str | None = None
    endpoint: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is SourceStatus.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "message": self.message,
            "endpoint": self.endpoint,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass(frozen=True)
class StageAssessment:
    stage: Stage
    state: StageState
    summary: str
    supporting_evidence_ids: tuple[str, ...] = ()
    conflicting_evidence_ids: tuple[str, ...] = ()
    #: Health of the sources relevant to this stage. Lets a consumer tell
    #: "no source was queried" apart from "the source was queried and failed".
    source_statuses: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "state": self.state.value,
            "summary": self.summary,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "conflicting_evidence_ids": list(self.conflicting_evidence_ids),
            "source_statuses": dict(self.source_statuses),
        }


@dataclass(frozen=True)
class Contradiction:
    description: str
    evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"description": self.description, "evidence_ids": list(self.evidence_ids)}


@dataclass(frozen=True)
class ReconciliationResult:
    """Deterministic engine output. Identical evidence -> identical result."""

    stages: tuple[StageAssessment, ...]
    last_confirmed_stage: Stage | None
    outcome: OverallOutcome
    summary: str
    contradictions: tuple[Contradiction, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    safety: dict[str, bool] = field(default_factory=dict)
    source_statuses: dict[str, str] = field(default_factory=dict)

    def stage(self, stage: Stage) -> StageAssessment | None:
        for s in self.stages:
            if s.stage is stage:
                return s
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "summary": self.summary,
            "last_confirmed_stage": (
                self.last_confirmed_stage.value if self.last_confirmed_stage else None
            ),
            "stages": [s.to_dict() for s in self.stages],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "unresolved_questions": list(self.unresolved_questions),
            "safety": self.safety,
            "source_statuses": self.source_statuses,
        }
