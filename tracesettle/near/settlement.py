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
from decimal import Decimal, InvalidOperation
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
    #: The destination received less than the quote's expected output: money
    #: moved, but not the full amount. Distinct from UNKNOWN so a shortfall is
    #: never presented as a plain unknown or as full settlement.
    PARTIAL = "PARTIAL"
    #: A refund is independently established (the engine confirmed the payout).
    REFUNDED = "REFUNDED"
    #: A failure is independently established from decisive evidence. A mere
    #: provider-reported failure is NOT this; it stays UNKNOWN/REPORTED_ONLY.
    FAILED = "FAILED"
    #: The lifecycle is still progressing: the deposit is known to be in flight
    #: and no terminal state has been established yet. Distinct from UNKNOWN
    #: ("we cannot tell") because the evidence says the swap is actively running.
    PENDING = "PENDING"
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
    #: The ids of the evidence items the engine used to reach this state, so a
    #: reader can jump from a stage to the exact evidence behind it.
    supporting_evidence_ids: tuple[str, ...] = ()
    conflicting_evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stage": self.stage.value,
            "state": self.state.value,
            "confirmed": self.confirmed,
            "reported": self.reported,
            "detail": self.detail,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "conflicting_evidence_ids": list(self.conflicting_evidence_ids),
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
    #: The quote's expected destination amount (smallest unit), when known.
    expected_amount_out: str | None = None
    #: The independently observed destination amount (smallest unit), when known.
    observed_amount_out: str | None = None
    #: ``observed - expected`` when both are known and observed is lower; a
    #: non-negative decimal string. ``None`` when the comparison cannot be made.
    shortfall: str | None = None
    #: ``shortfall / expected`` as an exact decimal string, for disclosure only.
    #: Never used to *decide* the level; the level is decided by confirmed stages.
    shortfall_fraction: str | None = None
    summary: str = ""
    limitations: tuple[str, ...] = ()
    #: The normalized evidence items the engine reasoned over, so a VERIFIED
    #: claim can be inspected: each stage names the evidence ids that support it.
    #: Carried as plain dicts so the assurance view stays serializable and the
    #: console needs no knowledge of the engine's dataclasses.
    evidence: tuple[dict[str, Any], ...] = ()
    engine: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "level": self.level.value,
            "provider_claimed_success": self.provider_claimed_success,
            "independently_verified": self.independently_verified,
            "partial_settlement": self.partial_settlement,
            "expected_amount_out": self.expected_amount_out,
            "observed_amount_out": self.observed_amount_out,
            "shortfall": self.shortfall,
            "shortfall_fraction": self.shortfall_fraction,
            "stages": [s.to_dict() for s in self.stages],
            "conflicting_evidence": list(self.conflicting_evidence),
            "summary": self.summary,
            "limitations": list(self.limitations),
            "evidence": [dict(e) for e in self.evidence],
            "engine": self.engine,
        }


#: Overall outcomes in which the engine has independently confirmed the money
#: arrived (or was refunded).
_VERIFIED_OUTCOMES = frozenset({OverallOutcome.SETTLED_VERIFIED})
#: The refund was independently confirmed on-chain.
_REFUND_VERIFIED_OUTCOMES = frozenset({OverallOutcome.REFUND_VERIFIED})
#: A failure is independently established from decisive evidence.
_FAILED_VERIFIED_OUTCOMES = frozenset({OverallOutcome.FAILED_VERIFIED})
#: The provider asserts a failure but no decisive evidence establishes it.
_FAILED_REPORTED_OUTCOMES = frozenset({OverallOutcome.FAILED_REPORTED_UNVERIFIED})
#: The provider reports a refund but no on-chain payout is confirmed.
_REFUND_REPORTED_OUTCOMES = frozenset({OverallOutcome.REFUND_REPORTED_UNVERIFIED})
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
    expected_amount_out: str | None = None,
    observed_amount_out: str | None = None,
    evidence: Any = None,
) -> NearSettlementAssurance:
    """Build a :class:`NearSettlementAssurance` from a reconciliation result.

    ``provider_reported_success`` is the caller's record of what the upstream
    service claimed (for example, a 1Click ``SUCCESS`` status). It is used only
    to phrase the summary and to distinguish "the provider says so" from "we
    verified it"; it never raises the assurance level.

    ``expected_amount_out`` and ``observed_amount_out`` are decimal strings in
    the destination asset's smallest unit. When both are known and the observed
    amount is strictly lower, the difference is reported as a shortfall. A
    shortfall makes the level ``PARTIAL`` only when the engine independently
    confirmed the destination delivery: if the delivery is not confirmed, the
    level stays UNKNOWN/REPORTED_ONLY and the shortfall is disclosed as a
    limitation instead. Amounts never *create* a confirmation.
    """
    stages = tuple(
        _stage_assurance(result, name, stage)
        for name, stage in NEAR_SETTLEMENT_STAGES
    )
    evidence_items = _normalize_evidence(evidence)

    outcome = result.outcome
    if outcome is OverallOutcome.CONTRADICTORY:
        level = AssuranceLevel.CONTRADICTORY
    elif outcome in _VERIFIED_OUTCOMES:
        level = AssuranceLevel.VERIFIED
    elif outcome in _REFUND_VERIFIED_OUTCOMES:
        # An independently confirmed refund: the money is established to have
        # come back. This is a terminal, verified state in its own right, and it
        # must never be presented as a successful settlement.
        level = AssuranceLevel.REFUNDED
    elif outcome in _FAILED_VERIFIED_OUTCOMES:
        # A failure established by decisive evidence. Distinct from a merely
        # reported failure, which stays unverified.
        level = AssuranceLevel.FAILED
    elif outcome in _FAILED_REPORTED_OUTCOMES or outcome in _REFUND_REPORTED_OUTCOMES:
        # The provider asserts a terminal failure/refund, but no decisive
        # evidence establishes it. It is reported, not proven.
        level = AssuranceLevel.REPORTED_ONLY
    elif outcome in _REPORTED_OUTCOMES:
        level = AssuranceLevel.REPORTED_ONLY
    elif outcome is OverallOutcome.NOT_FOUND or outcome is OverallOutcome.UNSUPPORTED:
        level = AssuranceLevel.UNKNOWN
    elif outcome in _UNKNOWN_OUTCOMES:
        level = AssuranceLevel.UNAVAILABLE if _any_source_unavailable(result) else AssuranceLevel.UNKNOWN
    else:
        # FAILED_* and anything else: the money is not established as delivered.
        level = AssuranceLevel.UNKNOWN

    # A deposit that is independently confirmed to exist while the settlement is
    # not yet terminal is *pending*, not unknown: the evidence shows the swap is
    # actively progressing. This never applies to a contradictory result, and it
    # never applies once a terminal level has been reached.
    if (
        level in (AssuranceLevel.UNKNOWN, AssuranceLevel.REPORTED_ONLY)
        and outcome is not OverallOutcome.CONTRADICTORY
        and _state_of(result, Stage.BRIDGE_DEPOSIT_CREDIT) is StageState.CONFIRMED
        and _state_of(result, Stage.DESTINATION_CHAIN_DELIVERY) is not StageState.CONFIRMED
    ):
        level = AssuranceLevel.PENDING

    verified = level is AssuranceLevel.VERIFIED
    partial = _is_partial(result)
    conflicts = tuple(c.description for c in result.contradictions)

    # Amount comparison. A shortfall is only meaningful when the delivery itself
    # is independently confirmed; a lower observed amount against an unconfirmed
    # delivery is not "partial settlement", it is simply unverified.
    delivery_confirmed = _state_of(result, Stage.DESTINATION_CHAIN_DELIVERY) is StageState.CONFIRMED
    shortfall, fraction = _amount_shortfall(expected_amount_out, observed_amount_out)
    amount_known = shortfall is not None
    amount_short = amount_known and shortfall != "0"
    amount_partial = (
        amount_short and delivery_confirmed and level is not AssuranceLevel.CONTRADICTORY
    )
    if amount_partial:
        level = AssuranceLevel.PARTIAL
        # A shortfall means the settlement is not whole, so it is not "verified"
        # in the sense this flag promises. The delivery itself is confirmed, but
        # the outcome is partial, and the two must not be conflated.
        verified = False

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
    if amount_short and not delivery_confirmed:
        limitations.append(
            f"A destination amount of {observed_amount_out} against an expected "
            f"{expected_amount_out} is {shortfall} lower, but the delivery is not independently "
            "confirmed, so the difference is disclosed rather than classified."
        )
    if amount_partial:
        limitations.append(
            f"Partial settlement: the destination received {observed_amount_out}, "
            f"{shortfall} below the quote's expected {expected_amount_out}."
        )

    summary = _summary(level, outcome, verified, provider_reported_success, partial, amount_partial)
    return NearSettlementAssurance(
        outcome=outcome,
        level=level,
        provider_claimed_success=provider_reported_success,
        independently_verified=verified,
        stages=stages,
        conflicting_evidence=conflicts,
        partial_settlement=partial or amount_partial,
        expected_amount_out=expected_amount_out if amount_known else None,
        observed_amount_out=observed_amount_out if amount_known else None,
        shortfall=shortfall,
        shortfall_fraction=fraction,
        summary=summary,
        limitations=tuple(limitations),
        evidence=evidence_items,
        engine=result.to_dict(),
    )


def _amount_shortfall(
    expected: str | None, observed: str | None
) -> tuple[str | None, str | None]:
    """``(shortfall, fraction)`` when ``observed`` is strictly below ``expected``.

    Both inputs are integer strings in the asset's smallest unit. Returns
    ``(None, None)`` when the comparison cannot be made safely (a missing or
    non-integer value, or a zero/negative expectation), so a malformed amount is
    never turned into a numeric claim. The arithmetic is exact ``Decimal``; it is
    never used with a float.
    """
    if expected is None or observed is None:
        return (None, None)
    try:
        exp = Decimal(str(expected).strip())
        obs = Decimal(str(observed).strip())
    except (InvalidOperation, ValueError):
        return (None, None)
    if exp <= 0 or obs < 0:
        return (None, None)
    if obs >= exp:
        return ("0", "0")
    shortfall = exp - obs
    fraction = (shortfall / exp).quantize(Decimal("0.0001"))
    return (str(shortfall), str(fraction))


def _state_of(result: ReconciliationResult, stage: Stage) -> StageState:
    assessment = result.stage(stage)
    return assessment.state if assessment else StageState.MISSING


def _stage_assurance(result: ReconciliationResult, name: str, stage: Stage) -> StageAssurance:
    """One stage's assurance, carrying the ids of the evidence behind it.

    The stage state is read from the engine's own assessment; the supporting and
    conflicting evidence ids are the ones the engine recorded for that stage, so
    the view never invents a link between a state and an evidence item.
    """
    assessment = result.stage(stage)
    state = assessment.state if assessment else StageState.MISSING
    return StageAssurance(
        name=name,
        stage=stage,
        state=state,
        confirmed=state is StageState.CONFIRMED,
        reported=state is StageState.REPORTED,
        detail=assessment.summary if assessment else "no assessment was produced for this stage",
        supporting_evidence_ids=tuple(assessment.supporting_evidence_ids) if assessment else (),
        conflicting_evidence_ids=tuple(assessment.conflicting_evidence_ids) if assessment else (),
    )


def _normalize_evidence(evidence: Any) -> tuple[dict[str, Any], ...]:
    """Normalize evidence items (dataclasses or dicts) to plain dicts.

    A ``None`` becomes an empty tuple. An item exposing ``to_dict`` is converted;
    a mapping is copied; anything else is dropped rather than guessed at, so a
    malformed item cannot appear as evidence in the view.
    """
    if not evidence:
        return ()
    out: list[dict[str, Any]] = []
    for item in evidence:
        to_dict = getattr(item, "to_dict", None)
        if callable(to_dict):
            try:
                out.append(dict(to_dict()))
                continue
            except Exception:  # pragma: no cover - defensive
                continue
        if isinstance(item, dict):
            out.append(dict(item))
    return tuple(out)


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
    amount_partial: bool = False,
) -> str:
    if level is AssuranceLevel.VERIFIED:
        return "Independently verified: the decisive NEAR settlement stages are confirmed."
    if level is AssuranceLevel.REFUNDED:
        return "Refunded: an on-chain refund payout is independently confirmed."
    if level is AssuranceLevel.FAILED:
        return "Failed: decisive evidence independently establishes the transaction failed."
    if level is AssuranceLevel.PARTIAL:
        return "Partial: the destination is independently confirmed but received less than the quote's expected output."
    if level is AssuranceLevel.PENDING:
        return "Pending: the deposit is independently confirmed and the swap is still progressing."
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
        result, provider_reported_success=provider_reported_success, evidence=evidence
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
