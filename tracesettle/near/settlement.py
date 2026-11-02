"""Post-settlement assurance for NEAR Intents.

This module does not re-implement the settlement engine. The deterministic
engine in :mod:`tracesettle.reconcile` remains the only thing that decides
whether a transaction settled, and the correlation rules there (link stages only
via explicit identifiers, never by amount or timestamp) are untouched.

What this module adds is a small, documented *view* over an existing
:class:`~tracesettle.model.ReconciliationResult`, phrased for the NEAR
settlement path and for the "provider says success" question the mission asks:

    A provider's success is a ``REPORTED`` claim, never independent proof.

It maps the reconciliation outcome and per-stage states onto the NEAR settlement
stages the mission lists (deposit address, source-chain transaction, deposit
confirmation, intent execution, destination transaction, destination receipt,
refund, partial settlement, conflicting evidence) and reports, honestly, which
are independently confirmed and which are only reported.

``UNKNOWN``/``UNAVAILABLE`` are first-class: when the provider claims success but
independent evidence is missing, the assurance level is not "settled".
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from ..model import OverallOutcome, ReconciliationResult, Stage, StageState, Verification


class AssuranceLevel(str, enum.Enum):
    """How strongly the settlement is established.

    Deliberately finer than the engine's ``OverallOutcome`` so the mission's
    "provider reports success without independent evidence -> UNKNOWN or
    UNAVAILABLE" requirement is explicit and testable.
    """

    #: Every decisive stage independently confirmed from authoritative evidence.
    VERIFIED = "VERIFIED"
    #: The provider reports success and no independent evidence contradicts it,
    #: but at least one decisive stage is only reported.
    REPORTED_ONLY = "REPORTED_ONLY"
    #: Independent evidence conflicts materially.
    CONTRADICTORY = "CONTRADICTORY"
    #: The sources needed could not be queried, so settlement cannot be assessed.
    UNAVAILABLE = "UNAVAILABLE"
    #: Evidence was insufficient to decide (an incomplete search, or no evidence).
    UNKNOWN = "UNKNOWN"


#: The NEAR settlement stages the mission names, in order, and how each maps to
#: the engine's stages. Kept explicit so a reader can check the mapping.
NEAR_SETTLEMENT_STAGES: tuple[tuple[str, Stage], ...] = (
    ("deposit_address", Stage.SOURCE_CHAIN_DEPOSIT),
    ("source_chain_transaction", Stage.SOURCE_CHAIN_DEPOSIT),
    ("deposit_confirmation", Stage.BRIDGE_DEPOSIT_CREDIT),
    ("intent_execution", Stage.NEAR_SETTLEMENT),
    ("destination_transaction", Stage.DESTINATION_CHAIN_DELIVERY),
    ("destination_receipt", Stage.DESTINATION_CHAIN_DELIVERY),
    ("refund", Stage.REFUND),
)


@dataclass(frozen=True)
class StageAssurance:
    name: str
    stage: Stage
    state: StageState
    confirmed: bool
    reported: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stage": self.stage.value,
            "state": self.state.value,
            "confirmed": self.confirmed,
            "reported": self.reported,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class NearSettlementAssurance:
    """A deterministic, honest view of a NEAR Intents settlement."""

    outcome: OverallOutcome
    level: AssuranceLevel
    provider_claimed_success: bool
    independently_verified: bool
    stages: tuple[StageAssurance, ...] = ()
    conflicting_evidence: tuple[str, ...] = ()
    partial_settlement: bool = False
    summary: str = ""
    limitations: tuple[str, ...] = ()
    engine: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "level": self.level.value,
            "provider_claimed_success": self.provider_claimed_success,
            "independently_verified": self.independently_verified,
            "partial_settlement": self.partial_settlement,
            "stages": [s.to_dict() for s in self.stages],
            "conflicting_evidence": list(self.conflicting_evidence),
            "summary": self.summary,
            "limitations": list(self.limitations),
            "engine": self.engine,
        }


#: Overall outcomes in which the engine has independently confirmed the money
#: arrived (or was refunded).
_VERIFIED_OUTCOMES = frozenset(
    {OverallOutcome.SETTLED_VERIFIED, OverallOutcome.REFUND_VERIFIED}
)
#: Overall outcomes that assert a provider success claim without independent proof.
_REPORTED_OUTCOMES = frozenset(
    {OverallOutcome.SETTLED_REPORTED_ONLY, OverallOutcome.DELIVERY_UNVERIFIED}
)
#: Overall outcomes that mean we could not assess settlement.
_UNKNOWN_OUTCOMES = frozenset({OverallOutcome.UNKNOWN, OverallOutcome.INCOMPLETE})


def settlement_assurance_from_result(
    result: ReconciliationResult,
    *,
    provider_reported_success: bool = False,
) -> NearSettlementAssurance:
    """Build a :class:`NearSettlementAssurance` from a reconciliation result.

    ``provider_reported_success`` is the caller's record of what the upstream
    service claimed (for example, a 1Click ``SUCCESS`` status). It is used only
    to phrase the summary and to distinguish "the provider says so" from "we
    verified it"; it never raises the assurance level.
    """
    stages = tuple(
        StageAssurance(
            name=name,
            stage=stage,
            state=_state_of(result, stage),
            confirmed=_state_of(result, stage) is StageState.CONFIRMED,
            reported=_state_of(result, stage) is StageState.REPORTED,
            detail=_stage_detail(result, stage),
        )
        for name, stage in NEAR_SETTLEMENT_STAGES
    )

    outcome = result.outcome
    if outcome is OverallOutcome.CONTRADICTORY:
        level = AssuranceLevel.CONTRADICTORY
    elif outcome in _VERIFIED_OUTCOMES:
        level = AssuranceLevel.VERIFIED
    elif outcome in _REPORTED_OUTCOMES:
        level = AssuranceLevel.REPORTED_ONLY
    elif outcome is OverallOutcome.NOT_FOUND or outcome is OverallOutcome.UNSUPPORTED:
        level = AssuranceLevel.UNKNOWN
    elif outcome in _UNKNOWN_OUTCOMES:
        level = AssuranceLevel.UNAVAILABLE if _any_source_unavailable(result) else AssuranceLevel.UNKNOWN
    else:
        # FAILED_* and anything else: the money is not established as delivered.
        level = AssuranceLevel.UNKNOWN

    verified = level is AssuranceLevel.VERIFIED
    partial = _is_partial(result)
    conflicts = tuple(c.description for c in result.contradictions)

    limitations: list[str] = [
        "A provider success status is a REPORTED claim, not independent settlement proof.",
    ]
    if provider_reported_success and not verified:
        limitations.append(
            "The provider reported success, but independent evidence did not confirm it, so the "
            "assurance level is not VERIFIED."
        )
    if partial:
        limitations.append(
            "Partial settlement: the destination stage is not confirmed while an earlier stage is."
        )

    summary = _summary(level, outcome, verified, provider_reported_success, partial)
    return NearSettlementAssurance(
        outcome=outcome,
        level=level,
        provider_claimed_success=provider_reported_success,
        independently_verified=verified,
        stages=stages,
        conflicting_evidence=conflicts,
        partial_settlement=partial,
        summary=summary,
        limitations=tuple(limitations),
        engine=result.to_dict(),
    )


def _state_of(result: ReconciliationResult, stage: Stage) -> StageState:
    assessment = result.stage(stage)
    return assessment.state if assessment else StageState.MISSING


def _stage_detail(result: ReconciliationResult, stage: Stage) -> str:
    assessment = result.stage(stage)
    return assessment.summary if assessment else "no assessment was produced for this stage"


def _any_source_unavailable(result: ReconciliationResult) -> bool:
    return any(state == StageState.UNAVAILABLE.value for state in result.source_statuses.values()) or any(
        s.state is StageState.UNAVAILABLE for s in result.stages
    )


def _is_partial(result: ReconciliationResult) -> bool:
    """Partial settlement: an earlier stage confirmed, delivery not confirmed."""
    settle = _state_of(result, Stage.NEAR_SETTLEMENT)
    delivery = _state_of(result, Stage.DESTINATION_CHAIN_DELIVERY)
    return settle is StageState.CONFIRMED and delivery is not StageState.CONFIRMED


def _summary(
    level: AssuranceLevel,
    outcome: OverallOutcome,
    verified: bool,
    provider_reported_success: bool,
    partial: bool,
) -> str:
    if level is AssuranceLevel.VERIFIED:
        return "Independently verified: the decisive NEAR settlement stages are confirmed."
    if level is AssuranceLevel.REPORTED_ONLY:
        return (
            "Reported only: the provider claims success, but at least one decisive stage is not "
            "independently confirmed."
        )
    if level is AssuranceLevel.CONTRADICTORY:
        return "Contradictory: independent evidence about the settlement conflicts materially."
    if level is AssuranceLevel.UNAVAILABLE:
        return "Unavailable: the sources needed to assess settlement could not be queried."
    if partial:
        return "Unknown: partial settlement; the destination stage is not confirmed."
    if provider_reported_success:
        return (
            "Unknown: the provider reports success, but there is not enough independent evidence "
            "to verify settlement."
        )
    return f"Unknown: evidence was insufficient to establish settlement (engine outcome {outcome.value})."


# Re-exported so a caller can build a result from raw evidence without importing
# the engine directly. The engine remains the sole decision-maker.
def verify_settlement(
    evidence: list[Any],
    source_statuses: dict[str, Any] | None = None,
    *,
    expected_intent_hashes: list[str] | None = None,
    expected_origin_tx_hashes: list[str] | None = None,
    provider_reported_success: bool = False,
) -> NearSettlementAssurance:
    """Run the deterministic engine and wrap the result as an assurance view."""
    from ..reconcile import reconcile

    result = reconcile(
        evidence,
        source_statuses,
        expected_intent_hashes=expected_intent_hashes,
        expected_origin_tx_hashes=expected_origin_tx_hashes,
    )
    return settlement_assurance_from_result(
        result, provider_reported_success=provider_reported_success
    )


def provider_claims_success_from_evidence(evidence: list[Any]) -> bool:
    """Whether any evidence records a provider-reported success status.

    A helper for the wrapper: the caller passes the evidence it collected, and
    this reports whether the provider claimed success, so the assurance view can
    say "provider says so, we did not confirm it".
    """
    success_statuses = {"SUCCESS", "SETTLED", "COMPLETED", "FILLED"}
    for item in evidence:
        status = getattr(item, "reported_status", None)
        if isinstance(status, str) and status.strip().upper() in success_statuses:
            return True
    return False


def evidence_carries_confirmation(evidence: list[Any]) -> bool:
    """Whether any evidence is independently CONFIRMED (not merely reported)."""
    return any(
        getattr(item, "verification", None) is Verification.CONFIRMED for item in evidence
    )
