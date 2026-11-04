"""The learning loop: turn a security failure into a durable safeguard.

This is the last step of the mission's lifecycle — *identify, authorize, protect,
execute, verify, investigate, learn*. It connects an observed failure or
unverified condition to a persistent restriction that changes a later decision.

Two pure functions and one application step:

* :func:`derive_safeguard` — given a decided request and its outcome, decide
  whether a lesson is warranted, and what it is. Pure; no side effects.
* :func:`apply_safeguards` — given a request and the safeguards in force, return
  the strictest outcome they impose. Pure; no side effects.
* :class:`LearningLoop` — wires a durable :class:`SafeguardStore` to a service:
  it records the lessons of a decision and applies the safeguards to the next one.

Hard rules, so learning can never weaken security:

1. A safeguard only ever *tightens*. It can raise an outcome to
   ``REQUIRE_APPROVAL`` or ``HOLD``, never lower one.
2. The operator's policy stays authoritative. A safeguard is evaluated on top of
   the policy decision, and the strictest of the two wins.
3. Nothing is learned from a request that already did the right thing. An
   ALLOW, or a BLOCK/HOLD the policy already produced, is not a new lesson.
4. Every lesson names the evidence that produced it, and the decision that a
   safeguard later changed says so explicitly.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .model import Decision, TransactionRequest
from .safeguards import (
    DIM_REQUIRE_APPROVAL_ABOVE,
    DIM_REQUIRE_VERIFICATION,
    Safeguard,
    SafeguardStore,
)

#: The guard finding codes that justify a durable lesson, and the lesson each
#: teaches. Deliberately a small, explicit set: an unknown code is never a
#: reason to tighten, because that would let a caller drive policy by triggering
#: arbitrary findings.
LESSON_BY_FINDING: dict[str, tuple[str, str]] = {
    "CLIENT_ASSERTED_APPROVAL_IGNORED": (
        "CLIENT_ASSERTED_APPROVAL",
        "A caller tried to assert its own approval; require a human to approve this "
        "service's operations above the smallest amount seen.",
    ),
    "UNAPPROVED_DESTINATION": (
        "UNAPPROVED_DESTINATION_ATTEMPT",
        "A transfer to an unapproved destination was attempted; require a human to "
        "approve this service's operations above the smallest amount seen.",
    ),
    "DESTINATION_DENIED": (
        "DENIED_DESTINATION_ATTEMPT",
        "A transfer to a denied destination was attempted; require verification for "
        "this service and asset.",
    ),
    "WINDOW_VOLUME_EXCEEDED": (
        "WINDOW_VOLUME_EXCEEDED",
        "The rolling-window volume limit was exceeded; require a human to approve "
        "operations above the amount that tripped it.",
    ),
}

#: A lesson is never drawn from an ALLOW: an allowed request, by definition, did
#: not surface a risk finding, so there is nothing to learn. Every other outcome
#: can teach, because it reflects a real security signal.
_NOT_LEARNABLE_FROM: frozenset[Decision] = frozenset({Decision.ALLOW})


@dataclass(frozen=True)
class Lesson:
    """A lesson derived from one decision, before it is persisted."""

    dimension: str
    threshold: Decimal | None
    reason_code: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "threshold": None if self.threshold is None else str(self.threshold),
            "reason_code": self.reason_code,
            "reason": self.reason,
        }


def derive_safeguard(
    request: TransactionRequest,
    decision: Decision,
    finding_codes: tuple[str, ...] | list[str],
) -> Lesson | None:
    """Decide whether a decided request teaches a durable lesson.

    Returns ``None`` when there is nothing to learn. A lesson is drawn only when
    the request carried a specific, recognised risk finding and the decision was
    not an ALLOW.
    """
    codes = [str(c) for c in finding_codes]
    matched = next((c for c in codes if c in LESSON_BY_FINDING), None)
    if matched is None:
        return None
    if decision in _NOT_LEARNABLE_FROM:
        return None

    reason_code, reason = LESSON_BY_FINDING[matched]

    if matched in {"CLIENT_ASSERTED_APPROVAL_IGNORED", "UNAPPROVED_DESTINATION", "WINDOW_VOLUME_EXCEEDED"}:
        # Tighten to "any amount above what we just saw needs approval". Using the
        # observed amount keeps the restriction as small as the lesson justifies.
        return Lesson(
            dimension=DIM_REQUIRE_APPROVAL_ABOVE,
            threshold=request.amount,
            reason_code=reason_code,
            reason=reason,
        )
    # A denied destination is a stronger signal: require independent verification.
    return Lesson(
        dimension=DIM_REQUIRE_VERIFICATION,
        threshold=None,
        reason_code=reason_code,
        reason=reason,
    )


@dataclass(frozen=True)
class SafeguardApplication:
    """What the safeguards in force do to a request."""

    #: The strictest decision the safeguards impose, or ``None`` if none apply.
    decision: Decision | None
    #: Human-readable reasons, one per safeguard that fired.
    reasons: tuple[str, ...]
    #: The ids of the safeguards that fired (for the applied counter).
    safeguard_ids: tuple[str, ...]
    #: Full records, for the decision's explanation.
    safeguards: tuple[Safeguard, ...]

    @property
    def applied(self) -> bool:
        return self.decision is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "decision": self.decision.value if self.decision else None,
            "reasons": list(self.reasons),
            "safeguard_ids": list(self.safeguard_ids),
            "safeguards": [s.to_dict() for s in self.safeguards],
        }


def apply_safeguards(
    request: TransactionRequest, safeguards: tuple[Safeguard, ...]
) -> SafeguardApplication:
    """Compute the strictest decision the given safeguards impose on a request.

    Deterministic and side-effect free. Only ever returns a decision at least as
    strict as ALLOW; it can never relax anything.
    """
    fired: list[Safeguard] = []
    reasons: list[str] = []
    decision: Decision | None = None

    for sg in safeguards:
        if sg.dimension == DIM_REQUIRE_APPROVAL_ABOVE:
            if sg.threshold is not None and request.amount > sg.threshold:
                fired.append(sg)
                reasons.append(
                    f"safeguard {sg.safeguard_id} ({sg.reason_code}) requires approval for "
                    f"amounts above {_canonical(sg.threshold)} {request.asset} for {sg.service_id}"
                )
                decision = _strictest(decision, Decision.REQUIRE_APPROVAL)
        elif sg.dimension == DIM_REQUIRE_VERIFICATION:
            fired.append(sg)
            reasons.append(
                f"safeguard {sg.safeguard_id} ({sg.reason_code}) requires independent "
                f"verification before {sg.service_id} may sign"
            )
            decision = _strictest(decision, Decision.HOLD)

    return SafeguardApplication(
        decision=decision,
        reasons=tuple(reasons),
        safeguard_ids=tuple(s.safeguard_id for s in fired),
        safeguards=tuple(fired),
    )


def _strictest(current: Decision | None, candidate: Decision) -> Decision:
    if current is None or candidate.severity > current.severity:
        return candidate
    return current


def _canonical(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


class LearningLoop:
    """Record lessons and apply safeguards, backed by a durable store.

    When ``store`` is ``None`` the loop is inert: :meth:`apply` returns an empty
    application and :meth:`observe` records nothing, so a deployment without a
    safeguard store behaves exactly as before. The loop never invents a lesson.
    """

    def __init__(self, store: SafeguardStore | None) -> None:
        self.store = store

    @property
    def enabled(self) -> bool:
        return self.store is not None

    def apply(self, request: TransactionRequest) -> SafeguardApplication:
        """Return the safeguards in force for this request (fail closed on error)."""
        if self.store is None:
            return SafeguardApplication(None, (), (), ())
        try:
            safeguards = self.store.for_request(request.service_id, request.asset)
        except Exception:
            # A safeguard store we cannot read is treated as "assume the strictest":
            # require approval rather than silently ignoring a learned restriction.
            return SafeguardApplication(
                decision=Decision.REQUIRE_APPROVAL,
                reasons=(
                    "the durable safeguard store could not be read, so any learned "
                    "restriction must be assumed in force",
                ),
                safeguard_ids=(),
                safeguards=(),
            )
        return apply_safeguards(request, safeguards)

    def observe(
        self,
        request: TransactionRequest,
        decision: Decision,
        finding_codes: tuple[str, ...] | list[str],
        *,
        decision_id: str | None = None,
    ) -> Safeguard | None:
        """Record a lesson from a decided request, if it teaches one.

        Returns the persisted safeguard, or ``None`` when nothing was learned.
        """
        if self.store is None:
            return None
        lesson = derive_safeguard(request, decision, finding_codes)
        if lesson is None:
            return None
        safeguard = Safeguard(
            safeguard_id=f"sg_{secrets.token_hex(8)}",
            service_id=request.service_id,
            asset=(request.asset.strip().upper() or None),
            dimension=lesson.dimension,
            threshold=lesson.threshold,
            reason_code=lesson.reason_code,
            reason=lesson.reason,
            created_at=time.time(),
            source_decision_id=decision_id,
        )
        try:
            return self.store.record(safeguard)
        except Exception:
            # Failing to persist a lesson must not break the decision itself;
            # the decision already ran. It is surfaced by the console instead.
            return None

    def note_applied(self, application: SafeguardApplication) -> None:
        if self.store is None or not application.safeguard_ids:
            return
        try:
            self.store.note_applied(list(application.safeguard_ids))
        except Exception:
            pass

    def list(self) -> tuple[Safeguard, ...]:
        if self.store is None:
            return ()
        try:
            return self.store.all()
        except Exception:
            return ()

    def clear(self, safeguard_id: str) -> bool:
        if self.store is None:
            return False
        try:
            return self.store.clear(safeguard_id)
        except Exception:
            return False
