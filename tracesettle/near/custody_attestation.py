"""Per-operation TEE attestation verification for the OutLayer custody boundary.

The OutLayer Agent Custody API is a **signing** service. Its wallet-signing
surface (``/wallet/v1/*``) returns no Intel TDX quote, no collateral and no
signed execution receipt: the OpenAPI document for that surface defines no
attestation schema or endpoint at all. The only attestation material OutLayer
exposes belongs to the *separate* Agent Connect / compute ("inbox") path, which
attests a compute run, not a wallet signature.

So this module does two honest things:

1. **If** a per-operation attestation is supplied - a TDX quote whose
   ``report_data`` cryptographically commits to this operation's ``custody_digest``
   and to the wallet's signing key - it verifies that quote for real, using the
   standard-library Intel TDX verifier in :mod:`tracesettle.near.tdx` (signature
   chain to the pinned Intel SGX Root CA, QE binding, event-log replay), and then
   binds it to the exact authorized operation, the signing key and the network.
   Only then is ``ATTESTATION_VERIFIED`` returned.
2. **Otherwise** it returns ``PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE`` and
   fails closed. It never promotes a provider ``status == "success"``, a mere
   approved-measurement list, or a software signature to a TEE claim.

The binding is the whole point: a valid quote proving *some* enclave exists does
not prove *this* transaction was signed inside it. The ``report_data`` commitment
is what ties the hardware evidence to the one authorized operation.

Evidence states (a strict, non-promoting ladder - a weaker state never implies a
stronger one):

``PROVIDER_CLAIMED``
    The provider reported success. Nothing is proven.
``CUSTODY_BOUND``
    The operation matches the authorization (digest re-derived, nonce consumed).
``SETTLEMENT_VERIFIED``
    Independent NEAR RPC verification passed (see
    :func:`tracesettle.near.outlayer_execution.verify_custody_transaction`).
``ATTESTATION_VERIFIED``
    A genuine TDX quote verified to the pinned Intel root and bound to this
    operation's digest and the signing key.
``TEE_SIGNING_VERIFIED``
    ``ATTESTATION_VERIFIED`` *and* independent settlement verification both hold:
    the exact authorized operation, the signing key, the hardware evidence and the
    resulting NEAR transaction are cryptographically tied together.
``PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE``
    The provider supplies no per-operation attestation (the OutLayer custody case).
``INSUFFICIENT_EVIDENCE`` / ``DISPUTED``
    No usable evidence, or evidence that contradicts the authorized operation.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..base58 import b58decode
from . import tdx

#: The prefix mixed into the operation commitment so a bare hash cannot be
#: mistaken for a different scheme.
CUSTODY_ATTESTATION_PREFIX = b"TRACESETTLE-CUSTODY-ATTESTATION-V1"

#: ``report_data`` is 64 bytes: ``sha256(signing_key_raw) || operation_commitment``.
_REPORT_DATA_SIZE = 64
_HALF = _REPORT_DATA_SIZE // 2


class CustodyEvidenceState(str, enum.Enum):
    """The evidence ladder for a custody operation. Never promotes implicitly."""

    PROVIDER_CLAIMED = "PROVIDER_CLAIMED"
    CUSTODY_BOUND = "CUSTODY_BOUND"
    SETTLEMENT_VERIFIED = "SETTLEMENT_VERIFIED"
    ATTESTATION_VERIFIED = "ATTESTATION_VERIFIED"
    TEE_SIGNING_VERIFIED = "TEE_SIGNING_VERIFIED"
    PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE = "PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    DISPUTED = "DISPUTED"


def signing_key_raw(public_key: str) -> bytes | None:
    """Decode an ``ed25519:<base58>`` NEAR public key to its 32 raw bytes.

    Returns ``None`` for any other key type or a malformed value; a caller must
    treat ``None`` as "cannot bind" and fail closed.
    """
    if not isinstance(public_key, str) or not public_key.startswith("ed25519:"):
        return None
    raw = b58decode(public_key.split(":", 1)[1])
    if raw is None or len(raw) != 32:
        return None
    return raw


def operation_commitment(*, custody_digest: str, wallet_public_key: str) -> bytes | None:
    """The 32-byte commitment that binds hardware evidence to this operation.

    It mixes the prefix, ``sha256(custody_digest)`` (the exact authorized
    operation) and ``sha256(signing_key_raw)`` (the wallet's signing key). A
    quote for any other operation or workload yields a different commitment.
    """
    key_raw = signing_key_raw(wallet_public_key)
    if key_raw is None:
        return None
    material = (
        CUSTODY_ATTESTATION_PREFIX
        + hashlib.sha256(custody_digest.encode("utf-8")).digest()
        + hashlib.sha256(key_raw).digest()
    )
    return hashlib.sha256(material).digest()


def expected_report_data(*, custody_digest: str, wallet_public_key: str) -> bytes | None:
    """The 64-byte ``report_data`` a valid per-operation attestation must carry.

    The first half is ``sha256(signing_key_raw)`` (the signing-key binding the TDX
    verifier checks from ``signing_address``); the second half is the operation
    commitment (checked as the verifier's ``nonce``).
    """
    key_raw = signing_key_raw(wallet_public_key)
    commitment = operation_commitment(
        custody_digest=custody_digest, wallet_public_key=wallet_public_key
    )
    if key_raw is None or commitment is None:
        return None
    return hashlib.sha256(key_raw).digest() + commitment


@dataclass
class CustodyAttestationEvidence:
    """The verified (or refused) per-operation attestation, with its binding."""

    state: CustodyEvidenceState
    detail: str
    quote_present: bool = False
    quote_verified: bool = False
    operation_bound: bool = False
    signing_key_bound: bool = False
    measurement_approved: bool | None = None
    failures: list[str] = field(default_factory=list)
    measurement: dict[str, Any] = field(default_factory=dict)
    intel_root_fingerprint: str = ""
    transaction_digest: str = ""
    wallet_public_key: str = ""

    @property
    def tee_attested(self) -> bool:
        """True only when the quote verified, both bindings held, and the
        measurement was not rejected. A rejected measurement is never attested."""
        return (
            self.quote_verified
            and self.operation_bound
            and self.signing_key_bound
            and self.measurement_approved is not False
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "detail": self.detail,
            "quote_present": self.quote_present,
            "quote_verified": self.quote_verified,
            "operation_bound": self.operation_bound,
            "signing_key_bound": self.signing_key_bound,
            "measurement_approved": self.measurement_approved,
            "tee_attested": self.tee_attested,
            "failures": list(self.failures),
            "measurement": dict(self.measurement),
            "intel_root_fingerprint": self.intel_root_fingerprint,
            "transaction_digest": self.transaction_digest,
            "wallet_public_key": self.wallet_public_key,
        }


def _measurement_matches(
    measurement: Mapping[str, Any], approved: Sequence[Mapping[str, Any]] | None
) -> bool | None:
    """Whether the quote's measurement is in the operator-approved set.

    ``None`` means "not checked" (no approved set supplied); a caller must not
    read ``None`` as approval. A measurement matches when every field named in an
    approved entry equals the quote's corresponding value (case-insensitive hex),
    so an approved entry can be as strict as the operator chooses.
    """
    if not approved:
        return None
    quote_fields = {
        "mrtd": str(measurement.get("mr_seam", "")),
        "mr_seam": str(measurement.get("mr_seam", "")),
        "mr_signer_seam": str(measurement.get("mr_signer_seam", "")),
        "mr_config_id": str(measurement.get("mr_config_id", "")),
        "mr_owner": str(measurement.get("mr_owner", "")),
        "mr_owner_config": str(measurement.get("mr_owner_config", "")),
        "rtmr0": str(measurement.get("rt_mr0", "")),
        "rtmr1": str(measurement.get("rt_mr1", "")),
        "rtmr2": str(measurement.get("rt_mr2", "")),
        "rtmr3": str(measurement.get("rt_mr3", "")),
    }
    for entry in approved:
        if not isinstance(entry, Mapping):
            continue
        named = {str(k).lower(): v for k, v in entry.items() if str(k).lower() in quote_fields}
        if not named:
            continue
        if all(
            str(quote_fields[key]).lower() == str(value).lower() for key, value in named.items()
        ):
            return True
    return False


def _decode_quote(attestation: Mapping[str, Any]) -> bytes | None:
    """Decode the TDX quote from the common provider field names (hex or base64)."""
    for key in ("intel_quote", "quote", "tdx_quote", "attestation"):
        value = attestation.get(key)
        if not isinstance(value, str) or not value:
            continue
        try:
            raw = bytes.fromhex(value)
            if len(raw) > 1000:
                return raw
        except ValueError:
            pass
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) > 1000:
            return raw
    return None


def verify_custody_attestation(
    attestation: Mapping[str, Any] | None,
    *,
    custody_digest: str,
    wallet_public_key: str,
    wallet_account: str,
    network: str,
    approved_measurements: Sequence[Mapping[str, Any]] | None = None,
    now: int | None = None,
    collateral_client: Any = None,
    quote_verifier: Any = None,
) -> CustodyAttestationEvidence:
    """Verify a per-operation custody attestation and bind it to the operation.

    ``attestation`` is a provider-supplied mapping carrying the quote under one of
    ``intel_quote`` / ``quote`` (hex or base64) and, optionally, ``event_log``.
    The quote's ``report_data`` must equal
    :func:`expected_report_data` for *this* ``custody_digest`` and
    ``wallet_public_key``; that is the binding that makes the evidence specific to
    the authorized operation rather than to some other enclave.

    Missing, malformed, tampered, mismatched, unapproved or otherwise
    unverifiable evidence never yields ``ATTESTATION_VERIFIED``.

    ``quote_verifier`` defaults to the real
    :func:`tracesettle.near.tdx.verify_tdx_quote`. It is overridable *only* so the
    binding logic can be exercised against a synthetic quote in tests: a genuine
    Intel-signed quote cannot be minted for an arbitrary custody digest, and the
    real hardware signature path is covered separately by ``tests/test_near_tdx.py``.
    Production callers must leave it unset.
    """
    evidence = CustodyAttestationEvidence(
        state=CustodyEvidenceState.INSUFFICIENT_EVIDENCE,
        detail="no per-operation attestation was supplied",
        transaction_digest=custody_digest,
        wallet_public_key=wallet_public_key,
    )
    if not attestation:
        evidence.state = CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE
        evidence.detail = (
            "the provider supplied no per-operation attestation; the OutLayer Agent "
            "Custody signing API defines no attestation endpoint, so TEE signing cannot "
            "be cryptographically established"
        )
        return evidence

    key_raw = signing_key_raw(wallet_public_key)
    expected = expected_report_data(
        custody_digest=custody_digest, wallet_public_key=wallet_public_key
    )
    if key_raw is None or expected is None:
        evidence.failures.append("the wallet public key is not a decodable ed25519 key")
        return evidence

    raw_quote = _decode_quote(attestation)
    if raw_quote is None:
        evidence.failures.append("the attestation carries no decodable TDX quote")
        return evidence
    evidence.quote_present = True

    event_log = attestation.get("event_log")
    if not isinstance(event_log, list):
        event_log = None

    # Drive the verifier's own bindings from our commitment: ``signing_address``
    # makes it check report_data[:32] == sha256(signing_key_raw), and ``nonce``
    # makes it check report_data[32:64] == the operation commitment. A quote for
    # another key or another operation then fails inside the verifier.
    verification = (quote_verifier or tdx.verify_tdx_quote)(
        raw_quote,
        nonce=expected[_HALF:],
        signing_address=key_raw,
        event_log=event_log,
        now=now,
        collateral_client=collateral_client,
    )
    evidence.failures = list(verification.failures)
    evidence.measurement = dict(verification.measurement)
    evidence.intel_root_fingerprint = verification.intel_root_fingerprint

    if not verification.verified:
        evidence.state = CustodyEvidenceState.DISPUTED
        evidence.detail = "the attestation quote did not verify against the pinned Intel root"
        return evidence
    evidence.quote_verified = True
    evidence.signing_key_bound = bool(verification.checks.get("signing_identity_bound"))
    evidence.operation_bound = bool(verification.checks.get("nonce_bound"))

    # Explicit equality as a final, independent confirmation of both halves.
    if bytes.fromhex(verification.report_data or "") != expected:
        evidence.operation_bound = False
        evidence.signing_key_bound = False
    if not (evidence.operation_bound and evidence.signing_key_bound):
        evidence.state = CustodyEvidenceState.DISPUTED
        evidence.detail = (
            "the attestation does not commit to this operation's custody digest and "
            "signing key; a quote for another operation or workload is refused"
        )
        return evidence

    approved = _measurement_matches(verification.measurement, approved_measurements)
    evidence.measurement_approved = approved
    if approved is False:
        evidence.state = CustodyEvidenceState.DISPUTED
        evidence.detail = (
            "the attested workload measurement is not in the operator-approved set; "
            "an unapproved build is refused"
        )
        return evidence

    evidence.state = CustodyEvidenceState.ATTESTATION_VERIFIED
    evidence.detail = (
        "the TDX quote verified to the pinned Intel root and commits to this operation's "
        "custody digest and signing key"
        + (
            "; the measurement is operator-approved"
            if approved is True
            else "; no approved-measurement set was supplied, so approval was not checked"
        )
    )
    return evidence


def combine_evidence(
    *,
    provider_claimed_success: bool,
    custody_bound: bool,
    settlement_verified: bool,
    attestation: CustodyAttestationEvidence,
) -> CustodyEvidenceState:
    """The single strongest state the evidence actually supports.

    ``TEE_SIGNING_VERIFIED`` requires *both* the attested hardware evidence bound
    to this operation *and* independent settlement verification; neither alone is
    enough, and a provider claim is never sufficient for anything above
    ``PROVIDER_CLAIMED``.
    """
    if attestation.tee_attested and settlement_verified:
        return CustodyEvidenceState.TEE_SIGNING_VERIFIED
    if settlement_verified:
        return CustodyEvidenceState.SETTLEMENT_VERIFIED
    if attestation.tee_attested:
        return CustodyEvidenceState.ATTESTATION_VERIFIED
    if attestation.state is CustodyEvidenceState.DISPUTED:
        return CustodyEvidenceState.DISPUTED
    if custody_bound:
        return CustodyEvidenceState.CUSTODY_BOUND
    if attestation.state is CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE:
        return CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE
    if provider_claimed_success:
        return CustodyEvidenceState.PROVIDER_CLAIMED
    return CustodyEvidenceState.INSUFFICIENT_EVIDENCE
