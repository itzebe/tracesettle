"""Deterministic reconciliation engine.

Pure function: ``reconcile(evidence, source_statuses) -> ReconciliationResult``.
No I/O, no clock, no randomness, no LLM. Identical inputs always produce an
identical result (evidence is processed in a stable order).

The engine is the *only* place that decides whether a stage is confirmed. An
adapter merely reports what a source said.

Safety invariants enforced here (see ``SAFETY_INVARIANTS`` for the machine-readable
list asserted by the test-suite):

1. A missing destination transaction is never classified as a failed transfer.
2. ``refundedAmount: "0"`` is never taken as proof that no refund occurred/can occur.
3. A reported refund is not independently confirmed without the refund transaction.
4. A reported intent failure is not proof that funds were lost.
5. A successful source transaction is not proof the overall swap settled.
6. An unavailable RPC never causes a stage to be labelled failed.
7. Amount/timestamp similarity is never used as a correlation basis.
8. A hash commitment is not represented as proof the committed event is true.
"""

from __future__ import annotations

import enum

from .model import (
    STAGE_ORDER,
    Contradiction,
    EventType,
    EvidenceItem,
    OverallOutcome,
    Provenance,
    ReconciliationResult,
    SOURCE_UNAVAILABLE_STATUSES,
    SourceStatus,
    Stage,
    StageAssessment,
    StageState,
    Verification,
)

#: Machine-readable list of the invariants the engine promises to uphold.
SAFETY_INVARIANTS: dict[str, str] = {
    "no_missing_destination_is_failure": (
        "A missing destination transaction is never classified as a failed destination transfer."
    ),
    "zero_refund_is_not_proof_of_no_refund": (
        "A reported refund amount of zero is never taken as proof that no refund occurred or can occur."
    ),
    "reported_refund_not_confirmed": (
        "A reported refund is not labelled independently confirmed without the refund transaction."
    ),
    "reported_failure_is_not_loss": (
        "A reported intent failure is not treated as proof that funds were lost."
    ),
    "source_success_is_not_settlement": (
        "A successful source transaction is not treated as proof that the overall swap settled."
    ),
    "unavailable_rpc_is_not_failure": (
        "An unavailable RPC never causes a transaction to be labelled failed."
    ),
    "no_amount_or_time_correlation": (
        "Amount or timestamp similarity is never used as the sole basis for transaction correlation."
    ),
    "hash_commitment_is_not_proof": (
        "A hash commitment is not represented as proof that the committed real-world event is true."
    ),
}


class _StageEval(enum.Enum):
    """Outcome of evaluating a single stage from its evidence."""

    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"
    SIMULATED = "SIMULATED"
    CONTRADICTORY = "CONTRADICTORY"
    UNAVAILABLE = "UNAVAILABLE"
    MISSING = "MISSING"


#: The single authoritative evidence type that can *confirm* each stage.
#:
#: Everything else at that stage is supporting context. In particular, on-chain
#: inclusion or execution of a transaction does NOT confirm settlement or delivery:
#: only observing the investigated intent in authoritative event logs (settlement)
#: or the expected asset transfer in receipt logs (delivery) does.
DECISIVE_EVENT_TYPES: dict[Stage, EventType] = {
    Stage.SOURCE_CHAIN_DEPOSIT: EventType.SOURCE_TX_EXECUTED,
    Stage.BRIDGE_DEPOSIT_CREDIT: EventType.DEPOSIT_OBSERVED,
    Stage.NEAR_SETTLEMENT: EventType.INTENT_EVENT_OBSERVED,
    Stage.DESTINATION_CHAIN_DELIVERY: EventType.DESTINATION_TRANSFER_OBSERVED,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def reconcile(
    evidence: list[EvidenceItem],
    source_statuses: dict[str, SourceStatus] | None = None,
) -> ReconciliationResult:
    """Reconcile normalized evidence into a deterministic result."""
    source_statuses = source_statuses or {}
    items = sorted(evidence, key=lambda e: e.id)

    # REFUND is off the happy path, so it is assessed but excluded from ordering.
    assessed_stages = (*STAGE_ORDER, Stage.REFUND)
    stages = tuple(_assess_stage(stage, items, source_statuses) for stage in assessed_stages)
    contradictions = tuple(_detect_contradictions(items))
    last_confirmed = _last_confirmed_stage(stages)

    has_simulated = any(e.provenance is Provenance.SIMULATED for e in items)
    outcome = _derive_outcome(stages, items, source_statuses, contradictions, has_simulated)
    unresolved = _unresolved_questions(stages, items, source_statuses, contradictions)
    safety = _safety_report(items, stages, outcome)
    summary = _summarize(outcome, stages, items, source_statuses, has_simulated)

    return ReconciliationResult(
        stages=stages,
        last_confirmed_stage=last_confirmed,
        outcome=outcome,
        summary=summary,
        contradictions=contradictions,
        unresolved_questions=unresolved,
        safety=safety,
        source_statuses={k: v.value for k, v in sorted(source_statuses.items())},
    )


# ---------------------------------------------------------------------------
# Stage assessment
# ---------------------------------------------------------------------------


def _assess_stage(
    stage: Stage, items: list[EvidenceItem], source_statuses: dict[str, SourceStatus]
) -> StageAssessment:
    stage_items = [e for e in items if e.stage is stage]

    if stage is Stage.REFUND:
        return _assess_refund(stage_items)

    # Material contradiction at this stage?
    if _has_material_conflict(stage_items):
        return StageAssessment(
            stage=stage,
            state=StageState.CONTRADICTORY,
            summary="Independent evidence at this stage conflicts materially.",
            conflicting_evidence_ids=tuple(e.id for e in stage_items),
        )

    confirmed = [e for e in stage_items if e.verification is Verification.CONFIRMED]
    decisive = DECISIVE_EVENT_TYPES.get(stage)
    decisive_confirmed = [e for e in confirmed if e.event_type is decisive]
    supporting_confirmed = [e for e in confirmed if e.event_type is not decisive]
    reported = [e for e in stage_items if e.verification is Verification.REPORTED]
    simulated = [e for e in stage_items if e.provenance is Provenance.SIMULATED]
    unavailable = [e for e in stage_items if e.verification is Verification.UNAVAILABLE]

    # A stage is CONFIRMED only by its decisive authoritative evidence. On-chain
    # inclusion/execution alone is corroboration, not confirmation.
    if decisive_confirmed:
        summary = _confirmed_summary(stage, decisive_confirmed)
        if supporting_confirmed:
            summary += (
                " Supporting on-chain evidence was also observed, but does not by itself "
                "confirm this stage."
            )
        return StageAssessment(
            stage=stage,
            state=StageState.CONFIRMED,
            summary=summary,
            supporting_evidence_ids=tuple(e.id for e in decisive_confirmed),
        )
    if simulated:
        return StageAssessment(
            stage=stage,
            state=StageState.SIMULATED,
            summary=(
                "This stage is supported only by simulated test evidence and must not be "
                "presented as a live transaction."
            ),
            supporting_evidence_ids=tuple(e.id for e in simulated),
        )

    # A reported claim whose authoritative verification source was unavailable is
    # reported *and* unverifiable. That must be visible, not silently downgraded to
    # a plain report.
    if reported and unavailable:
        return StageAssessment(
            stage=stage,
            state=StageState.UNAVAILABLE,
            summary=(
                f"{_reported_summary(stage, reported)} The source needed to verify it was "
                "unavailable, so it could not be independently checked."
            ),
            supporting_evidence_ids=tuple(e.id for e in reported + unavailable),
        )
    if reported:
        return StageAssessment(
            stage=stage,
            state=StageState.REPORTED,
            summary=_reported_summary(stage, reported),
            supporting_evidence_ids=tuple(e.id for e in reported),
        )

    # On-chain inclusion/execution without decisive evidence: the transaction
    # exists, but this stage is not confirmed. If the decisive check itself could
    # not be performed, say so explicitly.
    if unavailable:
        reasons = sorted({str(e.details.get("reason") or e.source) for e in unavailable})
        return StageAssessment(
            stage=stage,
            state=StageState.UNAVAILABLE,
            summary=(
                "No evidence was obtained for this stage because a required source was "
                f"unavailable ({'; '.join(reasons)}). This is a source-availability problem, "
                "not a transaction failure."
            ),
            supporting_evidence_ids=tuple(e.id for e in unavailable + supporting_confirmed),
        )
    if supporting_confirmed:
        return StageAssessment(
            stage=stage,
            state=StageState.REPORTED,
            summary=(
                "A transaction at this stage was independently confirmed to exist on-chain, but "
                "the decisive evidence needed to confirm this stage was not obtained."
            ),
            supporting_evidence_ids=tuple(e.id for e in supporting_confirmed),
        )

    # No usable evidence at all.
    return _missing_or_unavailable(stage, source_statuses)


def _assess_refund(items: list[EvidenceItem]) -> StageAssessment:
    confirmed = [e for e in items if e.verification is Verification.CONFIRMED]
    if confirmed:
        return StageAssessment(
            stage=Stage.REFUND,
            state=StageState.CONFIRMED,
            summary="A refund transaction was independently confirmed on-chain.",
            supporting_evidence_ids=tuple(e.id for e in confirmed),
        )
    claimed = [e for e in items if e.event_type is EventType.REFUND_CLAIMED]
    if claimed:
        return StageAssessment(
            stage=Stage.REFUND,
            state=StageState.REPORTED,
            summary=(
                "A refund is reported by an upstream service but is not independently "
                "confirmed; the refund transaction has not been verified on-chain."
            ),
            supporting_evidence_ids=tuple(e.id for e in claimed),
        )
    return StageAssessment(
        stage=Stage.REFUND,
        state=StageState.MISSING,
        summary=(
            "No refund is claimed and no refund transaction was found. This does not mean "
            "a refund is impossible or will not occur."
        ),
    )


def _missing_or_unavailable(
    stage: Stage, source_statuses: dict[str, SourceStatus]
) -> StageAssessment:
    unavailable_sources = sorted(
        name
        for name, status in source_statuses.items()
        if status in SOURCE_UNAVAILABLE_STATUSES
    )
    if unavailable_sources:
        return StageAssessment(
            stage=stage,
            state=StageState.UNAVAILABLE,
            summary=(
                "No evidence was obtained for this stage because a required source was "
                f"unavailable ({', '.join(unavailable_sources)}). This is a source-availability "
                "problem, not a transaction failure."
            ),
        )
    return StageAssessment(
        stage=stage,
        state=StageState.MISSING,
        summary=(
            "No evidence was obtained for this stage. Missing evidence is not proof that "
            "the stage failed or did not happen."
        ),
    )


def _confirmed_summary(stage: Stage, confirmed: list[EvidenceItem]) -> str:
    if stage is Stage.SOURCE_CHAIN_DEPOSIT:
        return "The source-chain deposit transaction was independently confirmed."
    if stage is Stage.BRIDGE_DEPOSIT_CREDIT:
        return "The deposit was observed by an authoritative source."
    if stage is Stage.NEAR_SETTLEMENT:
        # Distinguish inclusion from semantic settlement evidence.
        if any(e.event_type is EventType.INTENT_EVENT_OBSERVED for e in confirmed):
            return (
                "Settlement was independently confirmed: the investigated intent hash appears "
                "in on-chain intent-execution event logs."
            )
        return (
            "A NEAR transaction was independently confirmed on-chain. Semantic settlement of "
            "the specific intent is not established by inclusion alone."
        )
    if stage is Stage.DESTINATION_CHAIN_DELIVERY:
        if any(e.event_type is EventType.DESTINATION_TRANSFER_OBSERVED for e in confirmed):
            return (
                "The destination transfer was independently confirmed: the expected asset "
                "transfer to the expected recipient appears in the receipt logs."
            )
        return "The destination transaction was independently confirmed on-chain."
    return "Independently confirmed."


def _reported_summary(stage: Stage, reported: list[EvidenceItem]) -> str:
    statuses = sorted({e.reported_status for e in reported if e.reported_status})
    joined = ", ".join(statuses) if statuses else "no status"
    if stage is Stage.SOURCE_CHAIN_DEPOSIT:
        return f"The source-chain deposit is reported by an upstream service ({joined}) but not independently confirmed."
    if stage is Stage.BRIDGE_DEPOSIT_CREDIT:
        return f"A deposit is reported by an upstream service ({joined}) but not independently confirmed."
    if stage is Stage.NEAR_SETTLEMENT:
        return f"Settlement is reported by an upstream service ({joined}) but not independently confirmed on-chain."
    if stage is Stage.DESTINATION_CHAIN_DELIVERY:
        return f"Destination delivery is reported by an upstream service ({joined}) but not independently confirmed."
    return f"Reported by an upstream service ({joined}) but not independently confirmed."


def _has_material_conflict(items: list[EvidenceItem]) -> bool:
    """True only when two *specific* claims at this stage actually conflict."""
    successful = [
        e
        for e in items
        if e.reported_status in {"SUCCESS", "SETTLED", "SUCCESS_RECEIPT"}
        and e.verification is Verification.CONFIRMED
    ]
    reverted = [
        e
        for e in items
        if e.reported_status == "REVERTED"
        or (e.event_type is EventType.NEAR_TX_EXECUTION and e.details.get("execution_failed"))
    ]
    # A confirmed revert alongside a confirmed success at the same stage is a real conflict.
    return bool(successful) and bool(reverted)


# ---------------------------------------------------------------------------
# Contradictions
# ---------------------------------------------------------------------------


def _detect_contradictions(items: list[EvidenceItem]) -> list[Contradiction]:
    out: list[Contradiction] = []

    confirmed_failures = [
        e
        for e in items
        if e.event_type is EventType.NEAR_TX_EXECUTION
        and e.details.get("execution_failed")
        and e.verification is Verification.CONFIRMED
    ]
    confirmed_successes = [
        e
        for e in items
        if e.event_type in {EventType.NEAR_TX_EXECUTION, EventType.DESTINATION_TX_EXECUTED}
        and e.reported_status == "SUCCESS"
        and e.verification is Verification.CONFIRMED
    ]
    if confirmed_failures and confirmed_successes:
        out.append(
            Contradiction(
                description=(
                    "Independently confirmed on-chain evidence includes both a failed execution "
                    "and a successful execution. These claims conflict and must be resolved manually."
                ),
                evidence_ids=tuple(sorted(e.id for e in confirmed_failures + confirmed_successes)),
            )
        )

    # Confirmed on-chain settlement (intent observed) vs a reported outright failure.
    intent_confirmed = [
        e
        for e in items
        if e.event_type is EventType.INTENT_EVENT_OBSERVED and e.verification is Verification.CONFIRMED
    ]
    reported_failed = [
        e
        for e in items
        if e.reported_status == "FAILED" and e.verification is Verification.REPORTED
    ]
    if intent_confirmed and reported_failed:
        out.append(
            Contradiction(
                description=(
                    "An upstream service reports the intent as FAILED, but the intent hash was "
                    "independently observed in on-chain intent-execution logs. The claims conflict."
                ),
                evidence_ids=tuple(sorted(e.id for e in intent_confirmed + reported_failed)),
            )
        )

    # Confirmed delivery vs a reported failure.
    delivery_confirmed = [
        e
        for e in items
        if e.event_type is EventType.DESTINATION_TRANSFER_OBSERVED
        and e.verification is Verification.CONFIRMED
    ]
    reported_refund = [e for e in items if e.event_type is EventType.REFUND_CLAIMED]
    if delivery_confirmed and reported_refund:
        out.append(
            Contradiction(
                description=(
                    "A refund is reported while a destination transfer is independently confirmed. "
                    "The claims conflict (a partial refund alongside delivery is possible, but the "
                    "discrepancy must be checked)."
                ),
                evidence_ids=tuple(sorted(e.id for e in delivery_confirmed + reported_refund)),
            )
        )

    # Explicitly flagged contradictory evidence items.
    flagged = [e for e in items if e.verification is Verification.CONTRADICTORY]
    for item in flagged:
        out.append(
            Contradiction(
                description=item.details.get(
                    "contradiction", "Evidence was flagged as contradictory."
                ),
                evidence_ids=(item.id,),
            )
        )

    return out


# ---------------------------------------------------------------------------
# Outcome derivation
# ---------------------------------------------------------------------------


def _state(stages: tuple[StageAssessment, ...], stage: Stage) -> StageState | None:
    for s in stages:
        if s.stage is stage:
            return s.state
    return None


#: Reported statuses that indicate the intent did not settle successfully.
_FAILURE_STATUSES = frozenset({"FAILED", "INCOMPLETE_DEPOSIT", "REFUNDED", "NOT_FOUND_OR_NOT_VALID"})


def _has_successful_settlement_claim(items: list[EvidenceItem]) -> bool:
    """True when a source positively claims settlement (not merely 'a status exists')."""
    for item in items:
        if item.stage is not Stage.NEAR_SETTLEMENT:
            continue
        if item.event_type is EventType.INTENT_EVENT_OBSERVED:
            return True
        if item.reported_status in {"SUCCESS", "SETTLED", "PROCESSING"}:
            return True
    return False


def _has_reported_failure(items: list[EvidenceItem]) -> bool:
    return any(
        item.reported_status in {"FAILED", "INCOMPLETE_DEPOSIT"} for item in items
    )


def _last_confirmed_stage(stages: tuple[StageAssessment, ...]) -> Stage | None:
    last: Stage | None = None
    for stage in STAGE_ORDER:
        for s in stages:
            if s.stage is stage and s.state is StageState.CONFIRMED:
                last = stage
    return last


def _derive_outcome(
    stages: tuple[StageAssessment, ...],
    items: list[EvidenceItem],
    source_statuses: dict[str, SourceStatus],
    contradictions: list[Contradiction],
    has_simulated: bool,
) -> OverallOutcome:
    src = _state(stages, Stage.SOURCE_CHAIN_DEPOSIT)
    settle = _state(stages, Stage.NEAR_SETTLEMENT)
    delivery = _state(stages, Stage.DESTINATION_CHAIN_DELIVERY)
    refund = _state(stages, Stage.REFUND)

    # Source could not be queried at all.
    oneclick = source_statuses.get("oneclick_status")
    if oneclick is SourceStatus.NOT_FOUND and not items:
        return OverallOutcome.NOT_FOUND

    # A material contradiction dominates, but only when confirmed claims conflict.
    if contradictions and any(
        e.verification is Verification.CONFIRMED for c in contradictions for e in items if e.id in c.evidence_ids
    ):
        return OverallOutcome.CONTRADICTORY

    # Refund path.
    if refund is StageState.CONFIRMED:
        return OverallOutcome.REFUND_VERIFIED
    if refund is StageState.REPORTED:
        return OverallOutcome.REFUND_REPORTED_UNVERIFIED

    # Failure, only when independently established.
    confirmed_failure = any(
        e.event_type is EventType.NEAR_TX_EXECUTION
        and e.details.get("execution_failed")
        and e.verification is Verification.CONFIRMED
        for e in items
    )
    if confirmed_failure:
        return OverallOutcome.FAILED_VERIFIED

    # Delivery path.
    if delivery is StageState.CONFIRMED:
        if settle is StageState.CONFIRMED:
            return OverallOutcome.SETTLED_VERIFIED
        return OverallOutcome.DELIVERY_UNVERIFIED
    if delivery is StageState.REPORTED:
        return OverallOutcome.DELIVERY_UNVERIFIED
    if delivery is StageState.CONTRADICTORY:
        return OverallOutcome.CONTRADICTORY

    # Settlement without confirmed delivery. A settlement stage that is merely
    # REPORTED because a source attached a status (possibly a failure status) must
    # not be read as a successful settlement claim.
    if settle is StageState.CONFIRMED:
        return OverallOutcome.DELIVERY_UNVERIFIED
    if settle is StageState.REPORTED and _has_successful_settlement_claim(items):
        return OverallOutcome.SETTLED_REPORTED_ONLY
    if settle is StageState.CONTRADICTORY:
        return OverallOutcome.CONTRADICTORY

    # Reported failure without independent confirmation.
    if _has_reported_failure(items):
        return OverallOutcome.FAILED_REPORTED_UNVERIFIED

    # Nothing conclusive.
    if src is StageState.CONFIRMED:
        return OverallOutcome.INCOMPLETE
    if src is StageState.REPORTED:
        return OverallOutcome.INCOMPLETE
    if src in {StageState.MISSING, StageState.UNAVAILABLE} and not items:
        return OverallOutcome.UNKNOWN
    return OverallOutcome.INCOMPLETE


# ---------------------------------------------------------------------------
# Unresolved questions & summary
# ---------------------------------------------------------------------------


def _unresolved_questions(
    stages: tuple[StageAssessment, ...],
    items: list[EvidenceItem],
    source_statuses: dict[str, SourceStatus],
    contradictions: list[Contradiction],
) -> list[str]:
    questions: list[str] = []
    for stage in STAGE_ORDER:
        state = _state(stages, stage)
        if state is StageState.CONFIRMED:
            continue
        label = _stage_label(stage)
        if state is StageState.REPORTED:
            questions.append(f"Can {label} be independently verified, rather than only reported?")
        elif state is StageState.UNAVAILABLE:
            questions.append(f"Can {label} be assessed once the unavailable source is reachable?")
        elif state is StageState.CONTRADICTORY:
            questions.append(f"Which claim about {label} is correct?")
        else:
            questions.append(f"Is there any evidence of {label}?")

    refund_state = _state(stages, Stage.REFUND)
    if refund_state is StageState.REPORTED:
        questions.append(
            "Can the reported refund be confirmed by locating the refund transaction on the "
            "origin chain? A reported refund is not proof the funds moved."
        )
    for contradiction in contradictions:
        questions.append(f"Resolve contradiction: {contradiction.description}")
    return questions


def _stage_label(stage: Stage) -> str:
    return {
        Stage.SOURCE_CHAIN_DEPOSIT: "the source-chain deposit",
        Stage.BRIDGE_DEPOSIT_CREDIT: "the bridge deposit credit",
        Stage.NEAR_SETTLEMENT: "NEAR settlement",
        Stage.DESTINATION_CHAIN_DELIVERY: "destination delivery",
        Stage.REFUND: "a refund",
    }[stage]


def _summarize(
    outcome: OverallOutcome,
    stages: tuple[StageAssessment, ...],
    items: list[EvidenceItem],
    source_statuses: dict[str, SourceStatus],
    has_simulated: bool,
) -> str:
    last = _last_confirmed_stage(stages)
    last_text = (
        f"The last independently confirmed stage is {_stage_label(last)}."
        if last
        else "No stage could be independently confirmed."
    )
    outcome_text = _OUTCOME_TEXT[outcome]
    unavailable = sorted(
        name for name, status in source_statuses.items() if status in SOURCE_UNAVAILABLE_STATUSES
    )
    suffix = ""
    if unavailable:
        suffix += f" Unavailable sources: {', '.join(unavailable)}."
    if has_simulated:
        suffix += " This result includes simulated test evidence and is not a live finding."
    return f"{outcome_text} {last_text}{suffix}"


_OUTCOME_TEXT: dict[OverallOutcome, str] = {
    OverallOutcome.SETTLED_VERIFIED: (
        "The swap settled and destination delivery was independently verified."
    ),
    OverallOutcome.SETTLED_REPORTED_ONLY: (
        "Settlement is reported by an upstream service but could not be independently verified."
    ),
    OverallOutcome.DELIVERY_UNVERIFIED: (
        "Settlement was confirmed, but destination delivery could not be independently verified."
    ),
    OverallOutcome.REFUND_VERIFIED: "A refund was independently confirmed on-chain.",
    OverallOutcome.REFUND_REPORTED_UNVERIFIED: (
        "A refund is reported but is not independently confirmed."
    ),
    OverallOutcome.FAILED_VERIFIED: "An intent execution failure was independently confirmed on-chain.",
    OverallOutcome.FAILED_REPORTED_UNVERIFIED: (
        "A failure is reported but is not independently confirmed. This is not proof that funds were lost."
    ),
    OverallOutcome.INCOMPLETE: "The investigation is incomplete; downstream stages are unresolved.",
    OverallOutcome.CONTRADICTORY: "Independent evidence conflicts materially.",
    OverallOutcome.NOT_FOUND: (
        "No record was found for this identifier. Not found is not proof that the swap failed."
    ),
    OverallOutcome.UNSUPPORTED: "The identifier or chain is not supported.",
    OverallOutcome.UNKNOWN: (
        "The available evidence is insufficient to establish what happened."
    ),
}


# ---------------------------------------------------------------------------
# Safety report
# ---------------------------------------------------------------------------


def _safety_report(
    items: list[EvidenceItem],
    stages: tuple[StageAssessment, ...],
    outcome: OverallOutcome,
) -> dict[str, bool]:
    delivery_state = _state(stages, Stage.DESTINATION_CHAIN_DELIVERY)
    refund_state = _state(stages, Stage.REFUND)
    settle_state = _state(stages, Stage.NEAR_SETTLEMENT)

    refund_claims = [e for e in items if e.event_type is EventType.REFUND_CLAIMED]
    confirmed_refund = [e for e in items if e.verification is Verification.CONFIRMED and e.stage is Stage.REFUND]

    return {
        # A missing destination is never reported as a failure.
        "no_missing_destination_is_failure": not (
            delivery_state is StageState.MISSING and outcome is OverallOutcome.FAILED_VERIFIED
        ),
        # Zero refund is never treated as proof no refund can occur.
        "zero_refund_is_not_proof_of_no_refund": not (
            any(e.details.get("refunded_amount") == "0" for e in refund_claims)
            and refund_state is StageState.CONFIRMED
        ),
        # A reported refund is never confirmed without a confirmed refund transaction.
        "reported_refund_not_confirmed": not (
            refund_state is StageState.CONFIRMED and not confirmed_refund
        ),
        # A reported failure is never equated with fund loss (we never emit a loss claim).
        "reported_failure_is_not_loss": True,
        # Source-chain success alone never yields a settled verdict.
        "source_success_is_not_settlement": not (
            outcome is OverallOutcome.SETTLED_VERIFIED and settle_state is not StageState.CONFIRMED
        ),
        # An unavailable RPC never produces a failed verdict.
        "unavailable_rpc_is_not_failure": not (
            delivery_state is StageState.UNAVAILABLE and outcome is OverallOutcome.FAILED_VERIFIED
        ),
        # The engine never correlates by amount/timestamp (structural guarantee).
        "no_amount_or_time_correlation": True,
        # A hash commitment is never presented as proof of the committed event.
        "hash_commitment_is_not_proof": True,
    }
