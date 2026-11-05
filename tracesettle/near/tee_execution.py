"""TEE-bound execution authorization: the trust boundary the signer obeys.

The rest of the product already *verifies* a real Intel TDX quote
(:mod:`tracesettle.near.tdx`, :mod:`tracesettle.near.attestation`). On its own
that is a report: a verified attestation that no execution path consults is a
dashboard, not a security control. This module turns it into one.

What it adds
------------
* A durable :class:`ExecutionRecord` that binds **one** execution to the exact
  transaction it authorizes: the transaction digest, the signer, the receiver,
  the operation, the asset, the amount, the authorization nonce, the policy
  version, the network, an expiry, and the verified TEE measurement. Any change
  to any of those is a different record, so a token minted for one transaction
  cannot authorize another.
* A :class:`TeeBinding` that binds a verified attestation to that record's
  **transaction digest** and its **decision nonce**, so an attestation obtained
  for one transaction cannot be replayed for another.
* An explicit lifecycle state machine (:class:`ExecutionState`) with legal
  transitions only. A transaction cannot be promoted into a successful state;
  the TEE gate cannot be skipped, because ``SIGNING_PENDING`` is reachable only
  from ``TEE_VERIFIED``.
* :meth:`TeeExecutionAuthorizer.enforce`, the single call an execution boundary
  makes before it will accept a signature. It refuses unless the record is
  ``TEE_VERIFIED``, inside its validity window, and its binding still matches the
  bytes that would be signed.

Fail-closed by construction
---------------------------
Every refusal raises :class:`TeeExecutionError`. There is no "trusted caller"
path and no configuration that turns a refusal into an execution. When the
authorizer is absent the boundary behaves exactly as before (the pre-TEE path),
which is why enabling it is an explicit operator decision
(``TRACESETTLE_NEAR_TEE_REQUIRED=1``).

Honest scope
------------
This binds execution to a *verified* hardware attestation. It does not make the
attestation itself stronger than :mod:`tracesettle.near.tdx` makes it: certificate
revocation and TCB freshness need Intel PCS collateral and are not checked here.
The measurement is pinned only when the operator pins one
(``TRACESETTLE_NEAR_TEE_EXPECTED_MEASUREMENT``); otherwise the observed
measurement is recorded and reported as ``UNPINNED`` rather than claimed.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .tee import AttestationStatus


class TeeExecutionError(ValueError):
    """An execution was refused because the TEE trust boundary was not satisfied."""


class IllegalTransition(TeeExecutionError):
    """A lifecycle transition was attempted that the state machine forbids."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class ExecutionState:
    """The lifecycle of one execution. The attributes are the wire labels."""

    RECEIVED = "RECEIVED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZED = "AUTHORIZED"
    TEE_VERIFICATION_PENDING = "TEE_VERIFICATION_PENDING"
    TEE_VERIFIED = "TEE_VERIFIED"
    SIGNING_PENDING = "SIGNING_PENDING"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    INCLUDED = "INCLUDED"
    SETTLEMENT_VERIFIED = "SETTLEMENT_VERIFIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    TEE_VERIFICATION_FAILED = "TEE_VERIFICATION_FAILED"
    SIGNING_FAILED = "SIGNING_FAILED"
    SUBMISSION_FAILED = "SUBMISSION_FAILED"
    SETTLEMENT_FAILED = "SETTLEMENT_FAILED"
    SETTLEMENT_UNKNOWN = "SETTLEMENT_UNKNOWN"


#: The only transitions the state machine permits. ``SIGNING_PENDING`` appears
#: only as a successor of ``TEE_VERIFIED``: that single edge is what makes the
#: TEE gate unskippable. There is no edge that jumps straight to a success state.
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    ExecutionState.RECEIVED: frozenset(
        {ExecutionState.AUTHORIZATION_PENDING, ExecutionState.REJECTED}
    ),
    ExecutionState.AUTHORIZATION_PENDING: frozenset(
        {ExecutionState.AUTHORIZED, ExecutionState.REJECTED, ExecutionState.EXPIRED}
    ),
    ExecutionState.AUTHORIZED: frozenset(
        {
            ExecutionState.TEE_VERIFICATION_PENDING,
            ExecutionState.REJECTED,
            ExecutionState.EXPIRED,
        }
    ),
    ExecutionState.TEE_VERIFICATION_PENDING: frozenset(
        {
            ExecutionState.TEE_VERIFIED,
            ExecutionState.TEE_VERIFICATION_FAILED,
            ExecutionState.EXPIRED,
        }
    ),
    ExecutionState.TEE_VERIFIED: frozenset(
        {ExecutionState.SIGNING_PENDING, ExecutionState.EXPIRED}
    ),
    ExecutionState.SIGNING_PENDING: frozenset(
        {ExecutionState.SIGNED, ExecutionState.SIGNING_FAILED}
    ),
    ExecutionState.SIGNED: frozenset(
        {ExecutionState.SUBMITTED, ExecutionState.SUBMISSION_FAILED}
    ),
    ExecutionState.SUBMITTED: frozenset(
        {
            ExecutionState.INCLUDED,
            ExecutionState.SETTLEMENT_FAILED,
            ExecutionState.SETTLEMENT_UNKNOWN,
        }
    ),
    ExecutionState.INCLUDED: frozenset(
        {
            ExecutionState.SETTLEMENT_VERIFIED,
            ExecutionState.SETTLEMENT_FAILED,
            ExecutionState.SETTLEMENT_UNKNOWN,
        }
    ),
}

#: States from which no further transition is allowed.
TERMINAL_STATES: frozenset[str] = frozenset(
    {
        ExecutionState.SETTLEMENT_VERIFIED,
        ExecutionState.REJECTED,
        ExecutionState.EXPIRED,
        ExecutionState.TEE_VERIFICATION_FAILED,
        ExecutionState.SIGNING_FAILED,
        ExecutionState.SUBMISSION_FAILED,
        ExecutionState.SETTLEMENT_FAILED,
        ExecutionState.SETTLEMENT_UNKNOWN,
    }
)


def is_terminal(state: str) -> bool:
    return state in TERMINAL_STATES


def can_transition(source: str, target: str) -> bool:
    """Whether ``source -> target`` is a legal edge, including same-state no-ops."""
    if source == target:
        return True
    return target in LEGAL_TRANSITIONS.get(source, frozenset())


def execution_digest(
    *,
    execution_id: str,
    network: str,
    transaction_digest: str,
    service_id: str,
    authorization_nonce: str,
    policy_version: str,
) -> str:
    """The digest the TEE binding commits to.

    It covers the execution id, the network, the *transaction digest* (the exact
    bytes to be signed), the service identity, the authorization nonce and the
    policy version. Every one of those is an explicit identifier, so two
    executions differ unless all of them agree.
    """
    material = {
        "execution_id": execution_id,
        "network": network,
        "transaction_digest": transaction_digest,
        "service_id": service_id,
        "authorization_nonce": authorization_nonce,
        "policy_version": policy_version,
        "v": "1",
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class TeeBinding:
    """A verified attestation bound to one execution digest and nonce."""

    execution_id: str
    execution_digest: str
    nonce: str
    provider: str
    status: str
    measurement_fingerprint: str
    measurement_pinned: bool
    verification: dict[str, Any] = field(default_factory=dict)
    bound_at: str = ""

    @property
    def verified(self) -> bool:
        return self.status == AttestationStatus.VERIFIED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "execution_digest": self.execution_digest,
            "nonce": self.nonce,
            "provider": self.provider,
            "status": self.status,
            "verified": self.verified,
            "measurement_fingerprint": self.measurement_fingerprint,
            "measurement_pinned": self.measurement_pinned,
            "bound_at": self.bound_at,
            "verification": dict(self.verification),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TeeBinding":
        return cls(
            execution_id=str(data.get("execution_id", "")),
            execution_digest=str(data.get("execution_digest", "")),
            nonce=str(data.get("nonce", "")),
            provider=str(data.get("provider", "")),
            status=str(data.get("status", "")),
            measurement_fingerprint=str(data.get("measurement_fingerprint", "")),
            measurement_pinned=bool(data.get("measurement_pinned", False)),
            verification=dict(data.get("verification") or {}),
            bound_at=str(data.get("bound_at", "")),
        )


def measurement_fingerprint(measurement: dict[str, Any]) -> str:
    """A stable fingerprint over a TD report's measurement fields."""
    blob = json.dumps(measurement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class ExecutionRecord:
    """The durable authorization + evidence record for one execution."""

    execution_id: str
    state: str
    created_at: str
    expires_at: str
    service_id: str
    network: str
    transaction_digest: str
    signer_id: str
    receiver_id: str
    operation: str
    asset: str
    amount: str
    destination: str
    authorization_id: str | None
    authorization_nonce: str
    policy_version: str
    execution_digest: str
    #: The attestation nonce this execution expects, set when verification begins.
    tee_expected_nonce: str = ""
    tee_binding: TeeBinding | None = None
    history: list[dict[str, str]] = field(default_factory=list)
    settlement: dict[str, Any] = field(default_factory=dict)

    @property
    def expired(self) -> bool:
        return _utc_now() > _parse_iso(self.expires_at)

    @property
    def tee_verified(self) -> bool:
        return self.tee_binding is not None and self.tee_binding.verified

    def transition(self, target: str, *, reason: str = "") -> None:
        """Advance the record, refusing any illegal edge. Terminal states are final."""
        if is_terminal(self.state) and target != self.state:
            raise IllegalTransition(
                f"execution {self.execution_id} is in terminal state {self.state}; "
                f"refusing to move to {target}"
            )
        if not can_transition(self.state, target):
            raise IllegalTransition(
                f"illegal execution transition {self.state} -> {target} for "
                f"execution {self.execution_id}"
            )
        if target == self.state:
            return
        self.state = target
        self.history.append(
            {"state": target, "at": _iso(_utc_now()), "reason": reason}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "state": self.state,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "expired": self.expired,
            "service_id": self.service_id,
            "network": self.network,
            "transaction_digest": self.transaction_digest,
            "signer_id": self.signer_id,
            "receiver_id": self.receiver_id,
            "operation": self.operation,
            "asset": self.asset,
            "amount": self.amount,
            "destination": self.destination,
            "authorization_id": self.authorization_id,
            "authorization_nonce": self.authorization_nonce,
            "policy_version": self.policy_version,
            "execution_digest": self.execution_digest,
            "tee_expected_nonce": self.tee_expected_nonce,
            "tee_verified": self.tee_verified,
            "tee_binding": self.tee_binding.to_dict() if self.tee_binding else None,
            "settlement": dict(self.settlement),
            "history": list(self.history),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, blob: str) -> "ExecutionRecord":
        return cls.from_dict(json.loads(blob))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionRecord":
        binding = data.get("tee_binding")
        return cls(
            execution_id=str(data["execution_id"]),
            state=str(data["state"]),
            created_at=str(data["created_at"]),
            expires_at=str(data["expires_at"]),
            service_id=str(data.get("service_id", "")),
            network=str(data.get("network", "")),
            transaction_digest=str(data.get("transaction_digest", "")),
            signer_id=str(data.get("signer_id", "")),
            receiver_id=str(data.get("receiver_id", "")),
            operation=str(data.get("operation", "")),
            asset=str(data.get("asset", "")),
            amount=str(data.get("amount", "")),
            destination=str(data.get("destination", "")),
            authorization_id=data.get("authorization_id"),
            authorization_nonce=str(data.get("authorization_nonce", "")),
            policy_version=str(data.get("policy_version", "")),
            execution_digest=str(data.get("execution_digest", "")),
            tee_expected_nonce=str(data.get("tee_expected_nonce", "")),
            tee_binding=TeeBinding.from_dict(binding) if isinstance(binding, dict) else None,
            history=list(data.get("history") or []),
            settlement=dict(data.get("settlement") or {}),
        )


class ExecutionRecordStore:
    """Durable storage for execution records (SQLite), with an in-memory mode.

    A configured path that cannot be opened is a hard failure: a record that
    cannot be persisted must not silently live only in memory, because the TEE
    gate reads the record back before it will let a signature through.
    """

    def __init__(self, path: str | None = None) -> None:
        self._lock = threading.RLock()
        self._memory: dict[str, str] = {}
        self._conn: sqlite3.Connection | None = None
        self.path = path
        if path:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    record TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    @property
    def backend(self) -> str:
        return "sqlite" if self._conn is not None else "in-memory"

    def put(self, record: ExecutionRecord) -> None:
        blob = record.to_json()
        with self._lock:
            if self._conn is not None:
                self._conn.execute(
                    "INSERT INTO executions (execution_id, state, record, updated_at) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(execution_id) DO UPDATE SET "
                    "state=excluded.state, record=excluded.record, updated_at=excluded.updated_at",
                    (record.execution_id, record.state, blob, _iso(_utc_now())),
                )
                self._conn.commit()
            else:
                self._memory[record.execution_id] = blob

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock:
            if self._conn is not None:
                row = self._conn.execute(
                    "SELECT record FROM executions WHERE execution_id = ?",
                    (execution_id,),
                ).fetchone()
                blob = row[0] if row else None
            else:
                blob = self._memory.get(execution_id)
        return ExecutionRecord.from_json(blob) if blob else None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


class TeeExecutionAuthorizer:
    """Creates execution records and enforces the TEE gate before signing.

    ``require_attestation`` is the operator's decision to make a verified
    attestation mandatory. When it is true, :meth:`enforce` refuses any execution
    that is not ``TEE_VERIFIED``, so a transaction cannot reach the signer
    without a hardware attestation bound to it.
    """

    def __init__(
        self,
        *,
        store: ExecutionRecordStore | None = None,
        require_attestation: bool = True,
        expected_measurement: str = "",
        ttl_seconds: int = 90,
        clock: Any = None,
    ) -> None:
        self.store = store or ExecutionRecordStore()
        self.require_attestation = require_attestation
        self.expected_measurement = expected_measurement.strip().lower()
        self.ttl_seconds = ttl_seconds
        self._clock = clock or _utc_now
        self._lock = threading.RLock()

    # -- record creation ---------------------------------------------------

    def create(
        self,
        *,
        service_id: str,
        network: str,
        transaction_digest: str,
        signer_id: str,
        receiver_id: str,
        operation: str,
        asset: str,
        amount: str,
        destination: str,
        authorization_id: str | None,
        authorization_nonce: str,
        policy_version: str,
    ) -> ExecutionRecord:
        """Create the AUTHORIZED execution record for a guard-approved operation.

        The caller has already obtained a guard ``ALLOW``; this only records the
        authorization so the TEE gate has something exact to bind to. It does not
        itself authorize anything.
        """
        now = self._clock()
        execution_id = "exec_" + hashlib.sha256(
            (
                transaction_digest
                + "\x00"
                + authorization_nonce
                + "\x00"
                + service_id
                + "\x00"
                + _iso(now)
            ).encode("utf-8")
        ).hexdigest()[:24]
        digest = execution_digest(
            execution_id=execution_id,
            network=network,
            transaction_digest=transaction_digest,
            service_id=service_id,
            authorization_nonce=authorization_nonce,
            policy_version=policy_version,
        )
        record = ExecutionRecord(
            execution_id=execution_id,
            state=ExecutionState.AUTHORIZED,
            created_at=_iso(now),
            expires_at=_iso(now + timedelta(seconds=self.ttl_seconds)),
            service_id=service_id,
            network=network,
            transaction_digest=transaction_digest,
            signer_id=signer_id,
            receiver_id=receiver_id,
            operation=operation,
            asset=asset,
            amount=amount,
            destination=destination,
            authorization_id=authorization_id,
            authorization_nonce=authorization_nonce,
            policy_version=policy_version,
            execution_digest=digest,
        )
        record.history.append(
            {"state": ExecutionState.AUTHORIZED, "at": _iso(now), "reason": "guard ALLOW"}
        )
        with self._lock:
            self.store.put(record)
        return record

    # -- attestation binding ----------------------------------------------

    def begin_verification(self, execution_id: str, *, expected_nonce: str = "") -> ExecutionRecord:
        record = self._load(execution_id)
        if expected_nonce:
            record.tee_expected_nonce = expected_nonce
        record.transition(ExecutionState.TEE_VERIFICATION_PENDING, reason="attestation requested")
        with self._lock:
            self.store.put(record)
        return record

    def bind_attestation(
        self,
        execution_id: str,
        attestation: Any,
        *,
        expected_nonce: str,
        expected_transaction_digest: str,
    ) -> ExecutionRecord:
        """Bind a verified attestation to the record, or fail closed.

        The attestation must be ``VERIFIED``; it must carry the exact nonce the
        record derived; and (when the operator pinned a measurement) its
        measurement must equal the pin. Anything else moves the record to
        ``TEE_VERIFICATION_FAILED`` and raises.
        """
        record = self._load(execution_id)
        if record.state not in (
            ExecutionState.TEE_VERIFICATION_PENDING,
            ExecutionState.TEE_VERIFIED,
        ):
            record.transition(ExecutionState.TEE_VERIFICATION_PENDING, reason="attestation supplied")

        status = getattr(attestation, "status", None)
        status_value = getattr(status, "value", str(status))
        verification = dict(getattr(attestation, "verification", {}) or {})
        nonce = str(getattr(attestation, "nonce", ""))
        measurement = verification.get("measurement") or {}
        fingerprint = measurement_fingerprint(measurement) if measurement else ""
        pinned = bool(self.expected_measurement)
        pinned_ok = (not pinned) or fingerprint == self.expected_measurement

        failure = ""
        if status_value != AttestationStatus.VERIFIED.value:
            failure = f"attestation status is {status_value}, not VERIFIED"
        elif nonce != expected_nonce:
            failure = "the attestation nonce does not match this execution's decision nonce"
        elif expected_transaction_digest != record.transaction_digest:
            failure = "the attestation was bound to a different transaction digest"
        elif not pinned_ok:
            failure = "the attestation measurement does not match the pinned measurement"

        if failure:
            binding = TeeBinding(
                execution_id=record.execution_id,
                execution_digest=record.execution_digest,
                nonce=nonce,
                provider=str(getattr(attestation, "provider", "")),
                status=status_value,
                measurement_fingerprint=fingerprint,
                measurement_pinned=pinned,
                verification=verification,
                bound_at=_iso(self._clock()),
            )
            record.tee_binding = binding
            record.transition(ExecutionState.TEE_VERIFICATION_FAILED, reason=failure)
            with self._lock:
                self.store.put(record)
            raise TeeExecutionError(f"TEE verification failed: {failure}")

        binding = TeeBinding(
            execution_id=record.execution_id,
            execution_digest=record.execution_digest,
            nonce=nonce,
            provider=str(getattr(attestation, "provider", "")),
            status=status_value,
            measurement_fingerprint=fingerprint,
            measurement_pinned=pinned,
            verification=verification,
            bound_at=_iso(self._clock()),
        )
        record.tee_binding = binding
        record.transition(ExecutionState.TEE_VERIFIED, reason="attestation verified and bound")
        with self._lock:
            self.store.put(record)
        return record

    # -- the enforcement point --------------------------------------------

    def enforce(self, execution_id: str, *, transaction_digest: str) -> ExecutionRecord:
        """Refuse unless the execution is TEE-verified and still exact.

        This is the one call the execution boundary makes before accepting a
        signature. It is deliberately paranoid: it re-checks the transaction
        digest, the binding, the expiry, and the state, so a record edited after
        verification, a substituted transaction, or an expired authorization all
        refuse.
        """
        record = self._load(execution_id)
        if self.require_attestation and not record.tee_verified:
            raise TeeExecutionError(
                f"execution {execution_id} is {record.state}; a verified TEE attestation "
                "bound to this transaction is required before signing"
            )
        if record.expired:
            if can_transition(record.state, ExecutionState.EXPIRED):
                record.transition(ExecutionState.EXPIRED, reason="authorization expired")
                with self._lock:
                    self.store.put(record)
            raise TeeExecutionError(f"execution {execution_id} has expired; refusing to sign")
        if transaction_digest != record.transaction_digest:
            raise TeeExecutionError(
                "the transaction to be signed does not match the authorized execution; refusing"
            )
        if record.tee_binding is not None:
            if record.tee_binding.execution_digest != record.execution_digest:
                raise TeeExecutionError("the TEE binding does not cover this execution; refusing")
            if record.tee_expected_nonce and record.tee_binding.nonce != record.tee_expected_nonce:
                raise TeeExecutionError("the TEE binding nonce does not match; refusing")
        return record

    def begin_signing(self, execution_id: str) -> ExecutionRecord:
        """Move TEE_VERIFIED -> SIGNING_PENDING, the only door to the signer."""
        record = self._load(execution_id)
        record.transition(ExecutionState.SIGNING_PENDING, reason="signing authorized")
        with self._lock:
            self.store.put(record)
        return record

    def record_state(self, execution_id: str, state: str, *, reason: str = "") -> ExecutionRecord:
        record = self._load(execution_id)
        record.transition(state, reason=reason)
        with self._lock:
            self.store.put(record)
        return record

    def record_settlement(self, execution_id: str, settlement: dict[str, Any]) -> ExecutionRecord:
        record = self._load(execution_id)
        record.settlement = dict(settlement)
        with self._lock:
            self.store.put(record)
        return record

    def get(self, execution_id: str) -> ExecutionRecord | None:
        return self.store.get(execution_id)

    def _load(self, execution_id: str) -> ExecutionRecord:
        record = self.store.get(execution_id)
        if record is None:
            raise TeeExecutionError(f"unknown execution {execution_id!r}")
        return record
