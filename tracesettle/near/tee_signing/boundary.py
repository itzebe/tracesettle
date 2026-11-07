"""The TEE signing boundary: authorization in, verified signature out.

This is the single place that turns an authorized transaction into a signature
produced by a remote, attested enclave — and refuses otherwise. It is deliberately
narrow:

* it accepts only a transaction that the guard already **ALLOW**ed and that has a
  durable, unexpired execution record whose digest matches the exact bytes;
* it builds a canonical :class:`TeeSigningRequest` from that transaction, so the
  enclave is asked to sign a *description it can recompute the digest from*, never
  raw caller bytes;
* it verifies the returned signature over the exact NEAR digest, under the
  returned public key, and requires that key to be the transaction's signer key;
* it verifies the attestation as a *set of separate claims* and only then reports
  a TEE signing state — a verified attestation alone is never "signed by the TEE".

An authorization that is BLOCK, HOLD, REQUIRE_APPROVAL, expired or missing never
reaches the provider: :meth:`TeeSigningBoundary.sign` raises before the provider is
called, and the tests assert the provider was never invoked.

The evidence ladder is monotonic and non-promoting:

``EXECUTION_BLOCKED`` — not authorized (the guard refused, or no record);
``PROVIDER_UNAVAILABLE`` — authorized but no signing route is configured;
``SIGNATURE_VERIFIED`` — a signature verified over the exact digest under the
transaction's key, but **no** attestation evidence was available;
``ATTESTATION_REJECTED`` — attestation evidence was present and did not verify;
``TEE_SIGNING_VERIFIED`` — every attestation claim holds *and* the signature
verifies: the only state that may be called TEE signing.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Mapping

from .. import ed25519
from .attestation import AttestationVerdict, verify_signing_attestation
from .provider import (
    SigningProvider,
    SigningResult,
    TeeProviderError,
    TeeProviderUnavailable,
)
from .request import TeeSigningRequest, build_signing_request


class TeeSigningRefusal(ValueError):
    """The boundary refused to sign. No signature was produced or accepted."""


class _State:
    """The evidence ladder labels. Monotonic: a weaker state never implies stronger."""

    EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
    ATTESTATION_REJECTED = "ATTESTATION_REJECTED"
    TEE_SIGNING_VERIFIED = "TEE_SIGNING_VERIFIED"

    ORDER = (
        EXECUTION_BLOCKED,
        PROVIDER_UNAVAILABLE,
        ATTESTATION_REJECTED,
        SIGNATURE_VERIFIED,
        TEE_SIGNING_VERIFIED,
    )

    @classmethod
    def rank(cls, state: str) -> int:
        try:
            return cls.ORDER.index(state)
        except ValueError:
            return -1


@dataclass
class TeeSignatureEvidence:
    """The full, honest record of one signing attempt."""

    state: str
    provider: str
    simulated: bool = False
    transaction_digest: str = ""
    request_digest: str = ""
    public_key: str = ""
    signature_b64: str = ""
    execution_id: str = ""
    build_hash: str = ""
    attestation_url: str = ""
    attestation: dict[str, Any] | None = None
    signature_verified: bool = False
    attestation_verified: bool = False
    refusal_reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def tee_signing_verified(self) -> bool:
        return self.state == _State.TEE_SIGNING_VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "provider": self.provider,
            "simulated": self.simulated,
            "transaction_digest": self.transaction_digest,
            "request_digest": self.request_digest,
            "public_key": self.public_key,
            "signature_b64": self.signature_b64,
            "execution_id": self.execution_id,
            "build_hash": self.build_hash,
            "attestation_url": self.attestation_url,
            "attestation": dict(self.attestation) if self.attestation else None,
            "signature_verified": self.signature_verified,
            "attestation_verified": self.attestation_verified,
            "tee_signing_verified": self.tee_signing_verified,
            "refusal_reason": self.refusal_reason,
            "details": dict(self.details),
        }


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


class TeeSigningBoundary:
    """Sign an authorized transaction inside a remote attested enclave."""

    def __init__(
        self,
        *,
        provider: SigningProvider,
        approved_build: str = "",
        approved_measurement: Any = None,
        expected_project: str = "",
        expected_caller: str = "",
        quote_verifier: Any = None,
        collateral_client: Any = None,
        clock: Any = None,
    ) -> None:
        self.provider = provider
        self.approved_build = approved_build
        self.approved_measurement = approved_measurement
        self.expected_project = expected_project
        self.expected_caller = expected_caller
        self._quote_verifier = quote_verifier
        self._collateral_client = collateral_client
        self._clock = clock

    # -- preconditions -----------------------------------------------------

    def _authorization(
        self,
        transaction: Any,
        *,
        decision: Any,
        authorization_record: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Refuse unless the transaction is authorized and bound to a record."""
        outcome = str(getattr(decision, "outcome", "") or "").upper()
        if outcome not in ("ALLOW", "APPROVED"):
            raise TeeSigningRefusal(
                f"the guard decision was {outcome or 'missing'}; refusing to reach the signing provider"
            )
        if authorization_record is None:
            raise TeeSigningRefusal(
                "no authorization record is bound to this transaction; refusing to sign"
            )
        digest = str(authorization_record.get("transaction_digest", ""))
        if digest != transaction.payload_fingerprint():
            raise TeeSigningRefusal(
                "the authorization record is bound to a different transaction; refusing to sign"
            )
        if authorization_record.get("expired"):
            raise TeeSigningRefusal("the authorization has expired; refusing to sign")
        return {
            "id": str(authorization_record.get("authorization_id") or ""),
            "digest": str(authorization_record.get("execution_digest") or ""),
            "expiry": str(authorization_record.get("expires_at") or ""),
            "policy_version": str(authorization_record.get("policy_version") or "unknown"),
        }

    # -- the one signing call ---------------------------------------------

    def sign(
        self,
        transaction: Any,
        *,
        decision: Any,
        authorization_record: Mapping[str, Any] | None,
        attestation: Mapping[str, Any] | None = None,
    ) -> TeeSignatureEvidence:
        """Sign the exact authorized transaction, or refuse.

        ``attestation`` optionally carries the run's quote material
        (``intel_quote`` hex, ``event_log``, ``input_hash``, ``output_hash``,
        ``wasm_hash``, ``caller``, ``project``, ``nonce``). When it is absent the
        result can at best be ``SIGNATURE_VERIFIED`` — never ``TEE_SIGNING_VERIFIED``.
        """
        cap = self.provider.capability()
        if not cap.available:
            raise TeeSigningRefusal(f"no signing provider is available: {cap.detail}")

        authorization = self._authorization(
            transaction, decision=decision, authorization_record=authorization_record
        )
        request = build_signing_request(
            transaction=transaction,
            authorization=authorization,
            provider=self.provider.name,
            approved_build=self.approved_build,
        )

        try:
            result = self.provider.sign(request)
        except TeeProviderUnavailable as exc:
            raise TeeSigningRefusal(str(exc)) from exc
        except TeeProviderError as exc:
            raise TeeSigningRefusal(f"the signing provider refused: {exc}") from exc

        return self._verify(transaction, request, result, attestation)

    # -- verification ------------------------------------------------------

    def _verify(
        self,
        transaction: Any,
        request: TeeSigningRequest,
        result: SigningResult,
        attestation: Mapping[str, Any] | None,
    ) -> TeeSignatureEvidence:
        digest_hex = request.transaction_digest.split(":")[-1]
        digest = bytes.fromhex(digest_hex)

        # 1. The returned key must be the transaction's signer key.
        if result.public_key != transaction.public_key:
            raise TeeSigningRefusal(
                "the provider signed with a different key than the transaction names; refusing"
            )
        # 2. The signature must verify over the exact NEAR digest.
        try:
            public_raw = _b58_decode(result.public_key.split(":")[-1])
        except Exception as exc:  # noqa: BLE001 - an unparseable key is a refusal
            raise TeeSigningRefusal("the provider returned an unparseable public key") from exc
        if not ed25519.verify(result.signature_raw64, digest, public_raw):
            raise TeeSigningRefusal(
                "the provider signature does not verify over the exact transaction digest; refusing"
            )
        # 3. The digest the provider reports must be the one we authorized.
        if result.transaction_digest != request.transaction_digest:
            raise TeeSigningRefusal(
                "the provider reports a different transaction digest than authorized; refusing"
            )

        evidence = TeeSignatureEvidence(
            state=_State.SIGNATURE_VERIFIED,
            provider=result.provider,
            simulated=result.simulated,
            transaction_digest=result.transaction_digest,
            request_digest=result.request_digest,
            public_key=result.public_key,
            signature_b64=result.signature_b64,
            execution_id=result.execution_id,
            build_hash=result.build_hash,
            attestation_url=result.attestation_url,
            signature_verified=True,
            details={"request": request.to_dict()},
        )

        if attestation is None:
            evidence.details["attestation_note"] = (
                "no per-execution attestation was supplied; the signature is verified but no "
                "TEE claim is made"
            )
            return evidence

        verdict = self._verify_attestation(request, result, attestation, public_raw)
        evidence.attestation = verdict.to_dict()
        evidence.attestation_verified = verdict.verified
        if not verdict.verified:
            evidence.state = _State.ATTESTATION_REJECTED
            evidence.refusal_reason = "the attestation did not verify: " + ", ".join(verdict.failures)
            return evidence
        evidence.state = _State.TEE_SIGNING_VERIFIED
        return evidence

    def _verify_attestation(
        self,
        request: TeeSigningRequest,
        result: SigningResult,
        attestation: Mapping[str, Any],
        public_raw: bytes,
    ) -> AttestationVerdict:
        quote_hex = attestation.get("intel_quote")
        nonce_hex = str(attestation.get("nonce") or "")
        if not isinstance(quote_hex, str) or not nonce_hex:
            return AttestationVerdict(
                verified=False,
                failures=["attestation_incomplete"],
                claims=[],
            )
        try:
            quote = bytes.fromhex(quote_hex)
            nonce = bytes.fromhex(nonce_hex)
        except ValueError:
            return AttestationVerdict(verified=False, failures=["attestation_not_hex"], claims=[])

        verifier = self._quote_verifier
        if verifier is None:
            from .. import tdx

            verifier = tdx.verify_tdx_quote

        return verify_signing_attestation(
            quote_verifier=verifier,
            quote=quote,
            nonce=nonce,
            signing_address=public_raw,
            event_log=attestation.get("event_log"),
            request_digest=request.digest(),
            transaction_digest=request.transaction_digest,
            signature_raw64=result.signature_raw64,
            public_key_raw=public_raw,
            approved_measurement=self.approved_measurement,
            approved_build=self.approved_build,
            observed_build=str(attestation.get("wasm_hash") or result.build_hash),
            caller=str(attestation.get("caller") or ""),
            expected_caller=self.expected_caller,
            project=str(attestation.get("project") or ""),
            expected_project=self.expected_project,
            input_hash=str(attestation.get("input_hash") or ""),
            output_hash=str(attestation.get("output_hash") or ""),
            collateral_client=self._collateral_client,
        )


def _b58_decode(text: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in text:
        n = n * 58 + alphabet.index(ch)
    if n >= 1 << 256:
        raise ValueError("base58 value is larger than 32 bytes")
    return n.to_bytes(32, "big")


class TeeSigningTransactionSigner:
    """Adapt the TEE signing boundary to the pipeline's ``TransactionSigner``.

    This is the genuine link between a remote attested enclave and the NEAR
    executor: the pipeline calls :meth:`sign` with the exact transaction-hash
    bytes, and this adapter asks the boundary to produce a signature over the
    authorized transaction. The boundary refuses unless the operation was
    authorized, the record is unexpired and digest-matched, and the returned
    signature verifies over the exact digest under the transaction's own key.

    Testnet-only, exactly like every other signer here, so it can never be pointed
    at mainnet. It holds no key: the provider holds the key inside its enclave.
    """

    def __init__(
        self,
        *,
        boundary: Any,
        transaction: Any,
        decision: Any,
        authorization_record: Mapping[str, Any] | None,
        attestation: Mapping[str, Any] | None = None,
        network: Any = None,
    ) -> None:
        from ..networks import NearNetwork

        if network is NearNetwork.MAINNET:
            raise TeeSigningRefusal("the TEE signing boundary is testnet-only; refusing mainnet")
        self.boundary = boundary
        self.transaction = transaction
        self.decision = decision
        self.authorization_record = authorization_record
        self.attestation = attestation
        self._network = network
        self.last_evidence: TeeSignatureEvidence | None = None

    @property
    def public_key(self) -> str:
        return self.transaction.public_key

    def sign(self, message: bytes) -> bytes:
        # The pipeline signs the transaction hash; the boundary recomputes and
        # checks that hash itself, so a mismatch between the bytes handed here and
        # the authorized transaction is caught there, not trusted here.
        if message != self.transaction.tx_hash_bytes:
            raise TeeSigningRefusal(
                "the pipeline asked to sign different bytes than the authorized transaction; refusing"
            )
        evidence = self.boundary.sign(
            self.transaction,
            decision=self.decision,
            authorization_record=self.authorization_record,
            attestation=self.attestation,
        )
        self.last_evidence = evidence
        return base64.b64decode(evidence.signature_b64)
