"""Verifiable-execution (TEE) research, kept honest and out of the critical path.

The mission asks whether verifiable execution could materially strengthen
TRACESETTLE, and forbids paying for it. The findings, recorded here so the code
matches the documentation:

* **OutLayer** (``app.outlayer.ai``) runs every execution inside Intel TDX and
  emits a hardware-signed attestation covering code, input, output and worker
  identity. Its pricing page states a dynamic pay-per-resource model
  (``base_fee + instructions x rate + time x rate``) with **failed executions
  not refunded**. That is a cost and a financial commitment, so this project
  does **not** integrate OutLayer execution. ``docs/TEE_RESEARCH.md`` records the
  decision.
* **NEAR Intents Agent API** runs in an attested TEE and publishes transparency
  proofs. That is relevant to reading policy state, but this project still does
  not claim TEE protection for its own decisions: no attestation is verified
  here, so none is asserted.

This module therefore models the *shape* of a verification verdict and refuses
to claim protection without a verified attestation. It performs no network call.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class AttestationStatus(str, enum.Enum):
    """Whether a verifiable-execution attestation was actually checked."""

    #: A provider attestation was obtained and its signature verified locally.
    VERIFIED = "VERIFIED"
    #: An attestation was offered but could not be verified (no verifier, no key).
    UNVERIFIABLE = "UNVERIFIABLE"
    #: No attestation was obtained.
    ABSENT = "ABSENT"
    #: Verification was not attempted (for example, it would incur a cost).
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


@dataclass(frozen=True)
class TeeAssessment:
    """An honest statement about verifiable execution for one operation.

    ``claims_protection`` is true only when an attestation was actually
    verified. Anything else is reported as unprotected, because a TEE claim
    without a verified attestation is not a security property.
    """

    provider: str
    status: AttestationStatus
    detail: str
    requires_payment: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def claims_protection(self) -> bool:
        return self.status is AttestationStatus.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "claims_protection": self.claims_protection,
            "requires_payment": self.requires_payment,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


#: What the research established about each candidate provider.
OUTLAYER_NOTES = (
    "OutLayer runs each execution in Intel TDX and emits an attestation over code, input, output "
    "and worker identity. Its pricing is dynamic and pay-per-resource, and failed executions are "
    "not refunded. That is a financial commitment, so TRACESETTLE does not integrate OutLayer "
    "execution; it records the option and the reason."
)

NEAR_AI_CLOUD_NOTES = (
    "The NEAR Intents Agent API runs in an attested TEE and publishes transparency proofs. That "
    "supports trusting a policy read, but TRACESETTLE does not verify that attestation itself, so "
    "it makes no TEE claim about its own decisions."
)


def assess_verifiable_execution(
    provider: str,
    *,
    attestation: dict[str, Any] | None = None,
    verifier: Any = None,
    requires_payment: bool = False,
) -> TeeAssessment:
    """Assess whether verifiable execution can be claimed for an operation.

    A claim of TEE protection is made **only** when an attestation is supplied
    and a verifier accepts it. If verification would require payment, the status
    is ``NOT_ATTEMPTED`` and no protection is claimed. This function never
    fabricates an attestation.
    """
    if requires_payment:
        return TeeAssessment(
            provider=provider,
            status=AttestationStatus.NOT_ATTEMPTED,
            detail=(
                "Verification was not attempted because it would require a paid service. "
                "The zero-budget rule forbids it; no TEE protection is claimed."
            ),
            requires_payment=True,
        )
    if attestation is None:
        return TeeAssessment(
            provider=provider,
            status=AttestationStatus.ABSENT,
            detail="No attestation was supplied, so no verifiable-execution claim is made.",
        )
    if verifier is None:
        return TeeAssessment(
            provider=provider,
            status=AttestationStatus.UNVERIFIABLE,
            detail=(
                "An attestation was supplied but no verifier is available to check it. "
                "Unverified attestation is not protection, so none is claimed."
            ),
            evidence={"attestation_keys": sorted(str(k) for k in attestation.keys())},
        )
    try:
        accepted = bool(verifier(attestation))
    except Exception as exc:  # noqa: BLE001 - a failing verifier is not an acceptance
        return TeeAssessment(
            provider=provider,
            status=AttestationStatus.UNVERIFIABLE,
            detail=f"The attestation verifier raised {type(exc).__name__}; no protection is claimed.",
        )
    if accepted:
        return TeeAssessment(
            provider=provider,
            status=AttestationStatus.VERIFIED,
            detail="The attestation was verified locally; verifiable execution is established.",
            evidence={"attestation_keys": sorted(str(k) for k in attestation.keys())},
        )
    return TeeAssessment(
        provider=provider,
        status=AttestationStatus.UNVERIFIABLE,
        detail="The attestation did not verify; no protection is claimed.",
    )
