"""Genuine TEE-protected signing: an attestation-bound enclave signing boundary.

This module is the architecture for signing a transaction **inside** a trusted
execution environment whose measurement is verified before the key is trusted.

Honest scope (read this before believing anything else in the file):

* The boundary is real: it fetches a genuine Intel TDX attestation, verifies the
  quote and its Intel PCS collateral locally, **pins the approved measurement**,
  binds the attestation to the exact transaction digest through a host-controlled
  nonce, provisions the enclave's signing key only against that verified
  attestation, and verifies the enclave's signature over the exact bytes before
  it is accepted.
* The *host* cannot bypass it: :class:`EnclaveSigningBoundary` is the only object
  that produces a key that the boundary will accept, and it refuses to produce
  one without a verified, measurement-pinned, transaction-bound attestation. The
  software :class:`~tracesettle.near.pipeline.LocalKeySigner` is a **separate**
  type and is never used when enclave signing is required.
* The module does **not** claim that a signature was produced inside an enclave
  unless the attestation, the measurement pin, the binding and the returned
  signature all verify. If any step cannot be completed it raises and produces no
  signature — it fails closed.
* The signing RPC endpoint is **not invented**: it must be configured by the
  operator (``TRACESETTLE_ENCLAVE_SIGN_URL``). With no endpoint configured the
  boundary is *unavailable* and refuses to sign, so hardware-required production
  execution stays disabled until a genuine endpoint and measurement are supplied.
* The reproducible hardware harness lives in :mod:`tracesettle.near.enclave_harness`
  and drives the **real** attestation endpoint (``cloud-api.near.ai``) with a
  fresh nonce, so the measurement pin and the binding are exercised against
  genuine hardware evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from ..model import SourceStatus
from . import ed25519, tdx


class EnclaveError(ValueError):
    """An enclave operation was refused; no signature is produced."""


class MeasurementMismatch(EnclaveError):
    """The verified quote's measurement is not an approved identity."""


class KeyNotUsable(EnclaveError):
    """The signing key is revoked, rotated away, or unknown."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Measurement identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovedMeasurement:
    """One approved enclave identity.

    ``fields`` maps a measurement field of the verified quote (for example
    ``mr_config_id`` or ``rt_mr3``) to its expected lowercase hex value. Every
    field must be present in the verified measurement and match exactly. A field
    the operator did not pin is *not* checked, so pin at least the field that
    commits to the measured configuration (``mr_config_id`` for NEAR AI Cloud,
    which is ``sha256(app_compose)`` right-padded to 48 bytes).
    """

    name: str
    fields: dict[str, str]

    def __post_init__(self) -> None:
        if not self.fields:
            raise MeasurementMismatch(
                f"approved measurement {self.name!r} pins no fields; refusing to treat an "
                "empty pin as an approval"
            )
        normalised = {k: str(v).strip().lower() for k, v in self.fields.items()}
        object.__setattr__(self, "fields", normalised)

    def matches(self, measurement: dict[str, Any]) -> bool:
        for key, expected in self.fields.items():
            observed = measurement.get(key)
            if not isinstance(observed, str) or observed.strip().lower() != expected:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "fields": dict(self.fields)}


class MeasurementPolicy:
    """Decides whether a verified measurement is an approved identity.

    The policy is **fail-closed**: when ``require_pin`` is true (the default) and
    no approved measurement is configured, *every* measurement is rejected. An
    operator who has not pinned an identity has not approved one.
    """

    def __init__(
        self, approved: list[ApprovedMeasurement] | None = None, *, require_pin: bool = True
    ) -> None:
        self.approved = list(approved or [])
        self.require_pin = require_pin

    def evaluate(self, measurement: dict[str, Any]) -> ApprovedMeasurement:
        if not measurement:
            raise MeasurementMismatch("the verified quote carries no measurement to check")
        if not self.approved:
            if self.require_pin:
                raise MeasurementMismatch(
                    "no approved enclave measurement is configured; refusing to trust an "
                    "unpinned measurement"
                )
            # require_pin False is an explicit, audited operator choice for a
            # non-production harness; it still records what was observed.
            return ApprovedMeasurement("UNPINNED", {"__observed__": ""})
        for candidate in self.approved:
            if candidate.matches(measurement):
                return candidate
        raise MeasurementMismatch(
            "the verified quote's measurement matches no approved enclave identity "
            f"({len(self.approved)} approved)"
        )


# ---------------------------------------------------------------------------
# Provisioning request and its cryptographic binding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvisioningRequest:
    """The exact operation a key is provisioned for.

    Every field is an explicit identifier. The request is canonicalised and
    hashed into the attestation nonce, so the attestation a key is provisioned
    against is bound to *this* transaction and cannot be reused for another.
    """

    key_id: str
    purpose: str
    execution_id: str
    transaction_digest: str
    decision_nonce: str
    policy_version: str

    def canonical_bytes(self) -> bytes:
        material = {
            "key_id": self.key_id,
            "purpose": self.purpose,
            "execution_id": self.execution_id,
            "transaction_digest": self.transaction_digest,
            "decision_nonce": self.decision_nonce,
            "policy_version": self.policy_version,
            "v": "1",
        }
        return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def derive_provisioning_nonce(request: ProvisioningRequest, *, salt: bytes | None = None) -> bytes:
    """Derive the host-controlled attestation nonce that binds the request.

    The nonce commits to the request's canonical bytes plus fresh randomness, so
    the attestation is specific to this provisioning request and unpredictable.
    """
    material = b"TRACESETTLE-ENCLAVE-PROVISION-V1\x00"
    material += request.canonical_bytes() + b"\x00"
    material += salt if salt is not None else secrets.token_bytes(32)
    return hashlib.sha256(material).digest()


# ---------------------------------------------------------------------------
# Provisioned key and signature
# ---------------------------------------------------------------------------


@dataclass
class ProvisionedKey:
    """A signing key provisioned against a verified, pinned, bound attestation."""

    key_id: str
    signing_algo: str
    signing_address: str
    measurement_name: str
    measurement: dict[str, Any]
    nonce: str
    provisioning_digest: str
    provisioned_at: str
    verification: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "signing_algo": self.signing_algo,
            "signing_address": self.signing_address,
            "measurement_name": self.measurement_name,
            "nonce": self.nonce,
            "provisioning_digest": self.provisioning_digest,
            "provisioned_at": self.provisioned_at,
        }


@dataclass
class EnclaveSignature:
    """An enclave signature that was verified over the exact bytes."""

    key_id: str
    signing_algo: str
    signing_address: str
    signature: bytes
    signed_digest: str
    verified: bool
    detail: str = ""

    @property
    def signature_b64(self) -> str:
        return base64.b64encode(self.signature).decode("ascii")

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "signing_algo": self.signing_algo,
            "signing_address": self.signing_address,
            "signed_digest": self.signed_digest,
            "verified": self.verified,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class EnclaveTransport(Protocol):
    """How the boundary reaches the enclave host. Real HTTP or a test harness."""

    def attestation_report(self, nonce_hex: str) -> dict[str, Any]: ...

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class HttpEnclaveTransport:
    """The real transport: the attested gateway for quotes, a configured sign URL.

    The attestation endpoint is the documented NEAR AI Cloud gateway path. The
    signing endpoint is **not invented**: it must be configured by the operator
    (``sign_url``). With no sign URL the transport refuses to sign, so enclave
    signing is unavailable until a genuine endpoint is supplied.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        sign_url: str | None = None,
        client: Any = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self._api_key = api_key or None
        self.sign_url = (sign_url or "").strip() or None
        self._client = client

    def attestation_report(self, nonce_hex: str) -> dict[str, Any]:
        if not self.base_url or self._client is None:
            raise EnclaveError("no attestation endpoint is configured")
        url = f"{self.base_url}/v1/attestation/report"
        result = self._client.get_json(
            url, params={"include_tls_fingerprint": "true", "nonce": nonce_hex}
        )
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            raise EnclaveError(
                f"the attestation endpoint returned no usable report ({result.status.value})"
            )
        return result.data

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.sign_url:
            raise EnclaveError(
                "no enclave signing endpoint is configured (TRACESETTLE_ENCLAVE_SIGN_URL); "
                "refusing to sign"
            )
        result = self._client.post_json(self.sign_url, payload)
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            raise EnclaveError(
                f"the enclave signing endpoint returned no usable signature ({result.status.value})"
            )
        return result.data


# ---------------------------------------------------------------------------
# Key lifecycle
# ---------------------------------------------------------------------------


class EnclaveKeyRegistry:
    """Durable key lifecycle: ACTIVE, ROTATED, REVOKED.

    A revoked or rotated-away key is never usable again. The store is optional
    (in-memory by default); a configured path that cannot be opened is a hard
    failure, because a lifecycle that cannot be persisted would silently forget a
    revocation across a restart.
    """

    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"

    def __init__(self, path: str | None = None) -> None:
        self._lock = threading.RLock()
        self._memory: dict[str, dict[str, Any]] = {}
        self._conn: sqlite3.Connection | None = None
        self.path = path
        if path:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS enclave_keys ("
                "key_id TEXT PRIMARY KEY, state TEXT NOT NULL, signing_address TEXT NOT NULL, "
                "record TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            self._conn.commit()

    @property
    def backend(self) -> str:
        return "sqlite" if self._conn is not None else "in-memory"

    def _put(self, key_id: str, record: dict[str, Any]) -> None:
        blob = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with self._lock:
            if self._conn is not None:
                self._conn.execute(
                    "INSERT INTO enclave_keys (key_id, state, signing_address, record, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(key_id) DO UPDATE SET "
                    "state=excluded.state, record=excluded.record, updated_at=excluded.updated_at",
                    (
                        key_id,
                        str(record.get("state", "")),
                        str(record.get("signing_address", "")),
                        blob,
                        _iso(_utc_now()),
                    ),
                )
                self._conn.commit()
            else:
                self._memory[key_id] = record

    def _get(self, key_id: str) -> dict[str, Any] | None:
        with self._lock:
            if self._conn is not None:
                row = self._conn.execute(
                    "SELECT record FROM enclave_keys WHERE key_id = ?", (key_id,)
                ).fetchone()
                return json.loads(row[0]) if row else None
            return self._memory.get(key_id)

    def register(self, key: ProvisionedKey) -> None:
        self._put(
            key.key_id,
            {
                "key_id": key.key_id,
                "state": self.ACTIVE,
                "signing_address": key.signing_address,
                "signing_algo": key.signing_algo,
                "measurement_name": key.measurement_name,
                "provisioned_at": key.provisioned_at,
            },
        )

    def revoke(self, key_id: str) -> None:
        record = self._get(key_id)
        if record is None:
            raise KeyNotUsable(f"cannot revoke unknown enclave key {key_id!r}")
        record["state"] = self.REVOKED
        self._put(key_id, record)

    def rotate(self, old_key_id: str, new_key: ProvisionedKey) -> None:
        """Retire ``old_key_id`` and activate ``new_key`` atomically in intent."""
        if old_key_id == new_key.key_id:
            raise KeyNotUsable("rotation must move to a different key id")
        self.register(new_key)
        record = self._get(old_key_id)
        if record is not None:
            record["state"] = self.ROTATED
            record["rotated_to"] = new_key.key_id
            self._put(old_key_id, record)

    def state(self, key_id: str) -> str:
        record = self._get(key_id)
        return str(record["state"]) if record else "UNKNOWN"

    def is_usable(self, key_id: str) -> bool:
        return self.state(key_id) == self.ACTIVE

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


# ---------------------------------------------------------------------------
# The signing boundary
# ---------------------------------------------------------------------------


def _extract_quote(report: dict[str, Any]) -> dict[str, Any]:
    """The gateway attestation sub-object, or the report itself."""
    gateway = report.get("gateway_attestation")
    if isinstance(gateway, dict):
        return gateway
    return report


class EnclaveSigningBoundary:
    """Provision and use an enclave signing key behind a verified attestation.

    ``verifier`` is the function that verifies the raw quote; it defaults to the
    real :func:`tracesettle.near.tdx.verify_tdx_quote` with Intel PCS collateral.
    It is injectable so a test can exercise the boundary logic with a
    deterministic quote while the *genuineness* of quote verification is covered
    separately (``tee_attestation_verification_is_genuine``).
    """

    def __init__(
        self,
        *,
        transport: EnclaveTransport,
        measurements: MeasurementPolicy,
        registry: EnclaveKeyRegistry | None = None,
        verifier: Callable[..., Any] | None = None,
        collateral_client: Any = None,
        now: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.transport = transport
        self.measurements = measurements
        self.registry = registry if registry is not None else EnclaveKeyRegistry()
        self._verifier = verifier
        self._collateral_client = collateral_client
        self._now = now
        self._clock = clock or _utc_now

    # -- availability ------------------------------------------------------

    def available(self) -> bool:
        """Whether a genuine signing path is configured.

        Unavailable is the default: with no configured signing endpoint the
        boundary reports itself unavailable and refuses to sign, so hardware
        execution is disabled until it is genuinely set up.
        """
        sign_url = getattr(self.transport, "sign_url", None)
        if sign_url is None and isinstance(self.transport, HttpEnclaveTransport):
            return False
        return True

    # -- provisioning ------------------------------------------------------

    def provision(
        self, request: ProvisioningRequest, *, salt: bytes | None = None
    ) -> ProvisionedKey:
        """Fetch a genuine attestation, verify it, pin the measurement, bind it.

        Refuses (raising, producing no key) unless the quote verifies, its
        measurement is an approved identity, and its nonce is the one derived
        from this exact request.
        """
        nonce = derive_provisioning_nonce(request, salt=salt)
        report = self.transport.attestation_report(nonce.hex())
        gateway = _extract_quote(report)

        quote_hex = gateway.get("intel_quote")
        if not isinstance(quote_hex, str):
            raise EnclaveError("the attestation report carries no intel_quote")
        try:
            quote = bytes.fromhex(quote_hex)
        except ValueError as exc:
            raise EnclaveError("the intel_quote is not valid hex") from exc

        signing_address = _hex_or_none(gateway.get("signing_address"))
        signing_algo = str(gateway.get("signing_algo") or "ed25519")
        tls_fingerprint = _hex_or_none(gateway.get("tls_cert_fingerprint"))
        event_log = _event_log(gateway)

        verification = self._verify(
            quote,
            nonce=nonce,
            signing_address=signing_address,
            tls_cert_fingerprint=tls_fingerprint,
            event_log=event_log,
        )
        if not getattr(verification, "verified", False):
            failures = "; ".join(getattr(verification, "failures", []) or ["unknown"])
            raise EnclaveError(f"the enclave attestation did not verify: {failures}")

        # The verified quote must carry the exact nonce derived from this
        # request, or the attestation is not bound to this transaction.
        if not self._nonce_matches(verification, nonce):
            raise EnclaveError(
                "the verified quote's nonce does not match the provisioning request; "
                "refusing to trust an attestation bound to a different operation"
            )

        measurement = dict(getattr(verification, "measurement", {}) or {})
        approved = self.measurements.evaluate(measurement)

        if signing_address is None:
            raise EnclaveError("the verified attestation carries no signing address to provision")
        if signing_algo != "ed25519":
            raise EnclaveError(
                f"unsupported enclave signing algorithm {signing_algo!r}; refusing to provision"
            )

        key = ProvisionedKey(
            key_id=request.key_id,
            signing_algo=signing_algo,
            signing_address=signing_address.hex(),
            measurement_name=approved.name,
            measurement=measurement,
            nonce=nonce.hex(),
            provisioning_digest=request.digest(),
            provisioned_at=_iso(self._clock()),
            verification=getattr(verification, "to_dict", lambda: {})(),
        )
        self.registry.register(key)
        return key

    # -- signing -----------------------------------------------------------

    def sign(
        self, key: ProvisionedKey, request: ProvisioningRequest, message: bytes
    ) -> EnclaveSignature:
        """Sign ``message`` inside the enclave, accepting only a verified signature.

        The message digest and the transaction binding are sent to the enclave;
        the returned signature is verified **over the exact message** with the
        provisioned public key. A signature that does not verify, comes from a
        different key, or echoes a different message is refused — never returned
        as valid.
        """
        if not self.registry.is_usable(key.key_id):
            raise KeyNotUsable(
                f"enclave key {key.key_id!r} is {self.registry.state(key.key_id)}; refusing to sign"
            )
        if request.key_id != key.key_id:
            raise EnclaveError(
                "the provisioning request does not match the key; refusing to sign"
            )
        digest = hashlib.sha256(message).hexdigest()
        payload = {
            "key_id": key.key_id,
            "signing_algo": key.signing_algo,
            "message": base64.b64encode(message).decode("ascii"),
            "message_digest": digest,
            "transaction_digest": request.transaction_digest,
            "execution_id": request.execution_id,
            "decision_nonce": request.decision_nonce,
            "policy_version": request.policy_version,
        }
        response = self.transport.sign(payload)

        returned_algo = str(response.get("signing_algo") or "")
        returned_address = str(response.get("signing_address") or "").lower()
        if returned_algo != key.signing_algo:
            raise EnclaveError("the enclave returned a different signing algorithm; refusing")
        if returned_address and returned_address != key.signing_address.lower():
            raise EnclaveError("the enclave returned a signature from a different key; refusing")
        if str(response.get("message_digest") or "").lower() not in ("", digest):
            raise EnclaveError("the enclave echoed a different message digest; refusing")

        signature_b64 = response.get("signature")
        if not isinstance(signature_b64, str):
            raise EnclaveError("the enclave response carried no signature")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise EnclaveError("the enclave signature is not valid base64") from exc

        if key.signing_algo != "ed25519":
            raise EnclaveError(f"unsupported enclave signing algorithm {key.signing_algo!r}")

        try:
            public = bytes.fromhex(key.signing_address)
        except ValueError as exc:
            raise EnclaveError("the provisioned signing address is not valid hex") from exc
        if not ed25519.verify(signature, message, public):
            raise EnclaveError(
                "the enclave signature does not verify over the exact bytes; refusing"
            )

        return EnclaveSignature(
            key_id=key.key_id,
            signing_algo=key.signing_algo,
            signing_address=key.signing_address,
            signature=signature,
            signed_digest=digest,
            verified=True,
            detail="signature verified over the exact message with the provisioned enclave key",
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _nonce_matches(verification: Any, nonce: bytes) -> bool:
        """Whether the verified quote carries exactly the expected nonce."""
        verified_nonce = str(getattr(verification, "nonce", "") or "").lower()
        return bool(verified_nonce) and verified_nonce == nonce.hex()

    def _verify(
        self,
        quote: bytes,
        *,
        nonce: bytes,
        signing_address: bytes | None,
        tls_cert_fingerprint: bytes | None,
        event_log: list[dict[str, Any]] | None,
    ) -> Any:
        if self._verifier is not None:
            return self._verifier(
                quote,
                nonce=nonce,
                signing_address=signing_address,
                tls_cert_fingerprint=tls_cert_fingerprint,
                event_log=event_log,
                now=self._now,
                collateral_client=self._collateral_client,
            )
        return tdx.verify_tdx_quote(
            quote,
            nonce=nonce,
            signing_address=signing_address,
            tls_cert_fingerprint=tls_cert_fingerprint,
            event_log=event_log,
            now=self._now,
            collateral_client=self._collateral_client,
        )


class EnclaveTransactionSigner:
    """Adapt the enclave boundary to the pipeline's ``TransactionSigner``.

    This is the genuine connection between enclave signing and the NEAR executor:
    the pipeline calls :meth:`sign` with the exact transaction-hash bytes, and
    this adapter refuses unless the enclave boundary provisions a key against a
    verified, measurement-pinned, transaction-bound attestation and returns a
    signature that verifies over those exact bytes. It is testnet-only, exactly
    like the software signer it replaces, so it can never be pointed at mainnet.
    """

    def __init__(
        self,
        *,
        boundary: EnclaveSigningBoundary,
        key: ProvisionedKey,
        request: ProvisioningRequest,
        account_id: str,
        network: Any,
    ) -> None:
        from .networks import NearNetwork

        if network is NearNetwork.MAINNET:
            raise EnclaveError("the enclave signer is testnet-only; refusing to sign for mainnet")
        self.boundary = boundary
        self.key = key
        self.request = request
        self._account_id = account_id
        self._network = network

    @property
    def public_key(self) -> str:
        return "ed25519:" + _b58(bytes.fromhex(self.key.signing_address))

    @property
    def account_id(self) -> str:
        return self._account_id

    def sign(self, message: bytes) -> bytes:
        result = self.boundary.sign(self.key, self.request, message)
        if not result.verified:
            raise EnclaveError("the enclave signature did not verify; refusing to return it")
        return result.signature


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def _hex_or_none(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value.removeprefix("0x"))
    except ValueError:
        return None


def _event_log(gateway: dict[str, Any]) -> list[dict[str, Any]] | None:
    info = gateway.get("info")
    if isinstance(info, dict):
        tcb = info.get("tcb_info")
        if isinstance(tcb, dict) and isinstance(tcb.get("event_log"), list):
            return tcb["event_log"]
    return None
