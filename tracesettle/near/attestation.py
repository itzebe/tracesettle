"""Real TEE attestation retrieval and verification for the guard decision.

This is the concrete, working counterpart to the honest research in
:mod:`tracesettle.near.tee`. It fetches a **genuine** Intel TDX attestation from
the NEAR AI Cloud gateway (a free, public endpoint that returns a hardware-signed
quote), verifies it locally with :mod:`tracesettle.near.tdx`, and binds it to a
specific decision through a fresh, unpredictable nonce.

Nothing here is simulated: the quote is real hardware attestation, the signature
chain is checked to the pinned Intel root, and the nonce ties the quote to the
decision it is used for. If verification fails for any reason the status is
``UNVERIFIABLE`` and the caller must fail closed - no protection is ever claimed
without a verified attestation.

The nonce is the binding. It is derived from the operation's transaction
fingerprint, the policy revision, and fresh randomness, so an attestation
obtained for one decision cannot be replayed for another: the replayed quote's
``report_data`` embeds the old nonce, which will not match the new expected
nonce.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..httpclient import HttpClient
from ..model import SourceStatus
from . import tdx
from .tee import AttestationStatus, TeeAssessment

#: The NEAR AI Cloud gateway attestation endpoint (public, no key required).
DEFAULT_ATTESTATION_URL = "https://cloud-api.near.ai/v1/attestation/report"


def derive_nonce(
    *,
    transaction_fingerprint: str,
    policy_revision: str = "",
    operation_id: str = "",
    salt: bytes | None = None,
) -> bytes:
    """Derive a fresh nonce bound to one decision.

    The nonce commits to the transaction fingerprint, the policy revision and the
    operation id, plus fresh random salt, so it is both specific to the decision
    and unpredictable.
    """
    material = b"TRACESETTLE-TEE-ATTESTATION-V1\x00"
    material += transaction_fingerprint.encode("utf-8") + b"\x00"
    material += policy_revision.encode("utf-8") + b"\x00"
    material += operation_id.encode("utf-8") + b"\x00"
    material += salt if salt is not None else secrets.token_bytes(32)
    return hashlib.sha256(material).digest()


@dataclass
class AttestationResult:
    """The outcome of one attestation attempt, bound to a nonce."""

    status: AttestationStatus
    detail: str
    nonce: str
    provider: str = "near-ai-cloud"
    verification: dict[str, Any] = field(default_factory=dict)
    fetched: bool = False
    source_status: str = ""

    @property
    def verified(self) -> bool:
        return self.status is AttestationStatus.VERIFIED

    def to_assessment(self) -> TeeAssessment:
        return TeeAssessment(
            provider=self.provider,
            status=self.status,
            detail=self.detail,
            requires_payment=False,
            evidence={
                "nonce": self.nonce,
                "fetched": self.fetched,
                "source_status": self.source_status,
                "verification": self.verification,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "verified": self.verified,
            "detail": self.detail,
            "nonce": self.nonce,
            "fetched": self.fetched,
            "source_status": self.source_status,
            "verification": dict(self.verification),
        }


class TeeAttestationProvider:
    """Fetches and verifies a real TDX attestation bound to a decision nonce.

    ``client`` is the shared :class:`~tracesettle.httpclient.HttpClient`; in tests
    its opener is substituted so no network call is made. ``now`` may be supplied
    for deterministic certificate-window checks.
    """

    def __init__(
        self,
        *,
        url: str = DEFAULT_ATTESTATION_URL,
        client: HttpClient | None = None,
        now: int | None = None,
        timeout: float | None = None,
        collateral_client: Any = None,
    ) -> None:
        self.url = url
        self._client = client if client is not None else HttpClient(timeout=timeout)
        self._now = now
        self._collateral_client = collateral_client

    def attest(self, nonce: bytes) -> AttestationResult:
        """Fetch an attestation for ``nonce`` and verify it locally."""
        if len(nonce) != 32:
            raise ValueError("attestation nonce must be 32 bytes")
        nonce_hex = nonce.hex()
        result = self._client.get_json(
            self.url,
            params={"include_tls_fingerprint": "true", "nonce": nonce_hex},
        )
        source_status = getattr(result.status, "value", str(result.status))
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            return AttestationResult(
                status=AttestationStatus.UNVERIFIABLE,
                detail=(
                    "The attestation endpoint did not return a usable report "
                    f"({source_status}); no TEE protection is claimed."
                ),
                nonce=nonce_hex,
                fetched=False,
                source_status=source_status,
            )

        gateway = result.data.get("gateway_attestation")
        if not isinstance(gateway, dict):
            return AttestationResult(
                status=AttestationStatus.UNVERIFIABLE,
                detail="The attestation report has no gateway_attestation; no protection is claimed.",
                nonce=nonce_hex,
                fetched=True,
                source_status=source_status,
            )

        quote_hex = gateway.get("intel_quote")
        if not isinstance(quote_hex, str):
            return AttestationResult(
                status=AttestationStatus.UNVERIFIABLE,
                detail="The attestation report has no intel_quote; no protection is claimed.",
                nonce=nonce_hex,
                fetched=True,
                source_status=source_status,
            )
        try:
            quote = bytes.fromhex(quote_hex)
        except ValueError:
            return AttestationResult(
                status=AttestationStatus.UNVERIFIABLE,
                detail="The intel_quote is not valid hex; no protection is claimed.",
                nonce=nonce_hex,
                fetched=True,
                source_status=source_status,
            )

        signing_address = _hex_or_none(gateway.get("signing_address"))
        tls_fingerprint = _hex_or_none(gateway.get("tls_cert_fingerprint"))
        event_log = _extract_event_log(gateway)

        verification = tdx.verify_tdx_quote(
            quote,
            nonce=nonce,
            signing_address=signing_address,
            tls_cert_fingerprint=tls_fingerprint,
            event_log=event_log,
            now=self._now,
            collateral_client=self._collateral_client,
        )

        # The documentation requires the echoed report_data/request_nonce to match the values read
        # from the verified quote; a mismatch is a tampering signal, so it is a failure.
        echoed_report_data = gateway.get("report_data")
        echoed_nonce = gateway.get("request_nonce")
        echo_ok = True
        if isinstance(echoed_report_data, str):
            echo_ok = echo_ok and echoed_report_data.lower() == verification.report_data.lower()
        if isinstance(echoed_nonce, str):
            echo_ok = echo_ok and echoed_nonce.lower() == nonce_hex
        if not echo_ok:
            verification.checks["echoed_fields_match_verified_quote"] = False
            verification.failures.append(
                "echoed report_data/request_nonce differ from the verified quote"
            )
            verification.verified = False

        detail = (
            "The TDX quote was verified locally against the pinned Intel root, the nonce is bound, "
            "and the signing identity and TLS key are bound to the verified quote."
            if verification.verified
            else "TDX attestation verification failed: " + "; ".join(verification.failures)
        )
        return AttestationResult(
            status=AttestationStatus.VERIFIED
            if verification.verified
            else AttestationStatus.UNVERIFIABLE,
            detail=detail,
            nonce=nonce_hex,
            verification=verification.to_dict(),
            fetched=True,
            source_status=source_status,
        )


def _hex_or_none(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _extract_event_log(gateway: dict[str, Any]) -> list[dict[str, Any]] | None:
    info = gateway.get("info")
    if isinstance(info, dict):
        tcb = info.get("tcb_info")
        if isinstance(tcb, dict) and isinstance(tcb.get("event_log"), list):
            return tcb["event_log"]
    return None


def verified_tee_verifier(provider: TeeAttestationProvider, nonce: bytes):
    """Adapt :class:`TeeAttestationProvider` to the ``verifier`` callable of
    :func:`tracesettle.near.tee.assess_verifiable_execution`.

    The returned callable ignores the ``attestation`` dict (it fetches its own) and
    accepts only when the fetched attestation verifies for the bound nonce.
    """

    def _verify(_attestation: dict[str, Any]) -> bool:
        return provider.attest(nonce).verified

    return _verify
