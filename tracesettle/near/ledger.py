"""A durable submission ledger, so an interrupted execution is never guessed at.

The hard problem in submitting a transaction is the *unknown outcome*: the node
accepted the bytes but the response was lost, or the process died between sending
and recording the result. The one thing an honest system must never do is assume
"no response" means "not applied" and submit again blindly.

This module makes that decision explicit and durable. Before anything is sent,
the exact signed bytes and their hash are recorded. The hash of a NEAR
transaction covers its nonce, so the *same* bytes can only ever be applied once by
the network - re-broadcasting identical bytes is therefore idempotent and safe,
while broadcasting *different* bytes is never done here. A submission whose
outcome is unknown is marked ``UNKNOWN`` and resolved by asking the chain what
happened, never by assuming failure.

The exact signed bytes are persisted (not merely held in memory) because they are
the only artifact from which the signing event can be independently re-verified
after a process restart: the NEAR digest is recomputed from those bytes and the
ed25519 signature is checked over it. Once recorded they are immutable - a later
write that would substitute different bytes for the same transaction hash is
refused.

Storage is SQLite when a path is configured and in memory otherwise. A store
error is raised, never swallowed: a ledger that cannot persist is a ledger that
cannot be trusted to prevent a double submission.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SubmissionLedgerError(RuntimeError):
    """A submission record could not be stored without corrupting its evidence."""


class SubmissionState:
    """Where one submission is in its life. The attributes are the wire labels."""

    #: The transaction was built and authorized; nothing has been signed.
    PREPARED = "PREPARED"
    #: The signed bytes exist and are recorded, but nothing has been sent.
    SIGNED = "SIGNED"
    #: A send is in flight. A crash here leaves an unknown outcome.
    SUBMITTING = "SUBMITTING"
    #: The node returned a result; the transaction is on-chain (or failed).
    SUBMITTED = "SUBMITTED"
    #: The send was attempted but the outcome could not be established.
    UNKNOWN = "UNKNOWN"
    #: Settlement was independently verified against the chain.
    SETTLED = "SETTLED"
    #: The transaction is known not to have been applied (definitive refusal).
    FAILED = "FAILED"


#: States that still need resolution after a restart.
PENDING_STATES = frozenset(
    {SubmissionState.SIGNED, SubmissionState.SUBMITTING, SubmissionState.UNKNOWN}
)

#: States from which no further progress is expected without new evidence.
TERMINAL_STATES = frozenset({SubmissionState.SETTLED, SubmissionState.FAILED})


@dataclass
class SubmissionRecord:
    """The durable record of one attempted transaction submission."""

    tx_hash: str
    state: str
    network: str
    signer_id: str
    receiver_id: str
    amount_base: str
    destination: str
    #: The exact base64 ``SignedTransaction`` that was (or will be) broadcast.
    #: Recording it is what makes a safe re-broadcast possible: identical bytes,
    #: identical hash, at most one application. It is also the only artifact from
    #: which the signing event can be *independently re-verified* after a restart:
    #: the digest is recomputed from these bytes and the signature is checked over
    #: it, so this field must survive persistence (see :meth:`to_dict`).
    signed_b64: str = ""
    #: The signature algorithm the signed bytes carry. NEAR ``SignedTransaction``
    #: is a Borsh ``Signature`` with a one-byte tag; only ed25519 (tag 0) is
    #: emitted here. Recorded explicitly so a re-verifier never has to guess, and
    #: so a future non-ed25519 signature cannot be verified with the wrong rule.
    signature_algorithm: str = "ed25519"
    #: The caller's idempotency key, if any, so a duplicate request is recognised.
    idempotency_key: str = ""
    attempts: int = 0
    last_error: str = ""
    settlement: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    history: list[dict[str, str]] = field(default_factory=list)

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def pending(self) -> bool:
        return self.state in PENDING_STATES

    def transition(self, target: str, *, reason: str = "") -> None:
        """Move to ``target``, recording the reason. Never refuses a retry of the
        same state, so a recovery pass can re-assert ``UNKNOWN``."""
        if target == self.state:
            return
        self.state = target
        self.updated_at = _utc_now()
        self.history.append({"state": target, "at": self.updated_at, "reason": reason})

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "state": self.state,
            "network": self.network,
            "signer_id": self.signer_id,
            "receiver_id": self.receiver_id,
            "amount_base": self.amount_base,
            "destination": self.destination,
            # The exact signed bytes and their algorithm are persisted so the
            # signing event can be independently re-verified after a restart: the
            # digest is recomputed from these bytes and the signature is checked
            # over it. Omitting them silently degrades recovery and the durable
            # evidence chain, which is why they are part of the record, not a
            # process-local convenience.
            "signed_b64": self.signed_b64,
            "signature_algorithm": self.signature_algorithm,
            "idempotency_key": self.idempotency_key,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "settlement": dict(self.settlement),
            "terminal": self.terminal,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "history": list(self.history),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, blob: str) -> "SubmissionRecord":
        data = json.loads(blob)
        return cls(
            tx_hash=str(data["tx_hash"]),
            state=str(data["state"]),
            network=str(data.get("network", "")),
            signer_id=str(data.get("signer_id", "")),
            receiver_id=str(data.get("receiver_id", "")),
            amount_base=str(data.get("amount_base", "")),
            destination=str(data.get("destination", "")),
            signed_b64=str(data.get("signed_b64", "")),
            signature_algorithm=str(data.get("signature_algorithm", "ed25519")),
            idempotency_key=str(data.get("idempotency_key", "")),
            attempts=int(data.get("attempts", 0)),
            last_error=str(data.get("last_error", "")),
            settlement=dict(data.get("settlement") or {}),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
            history=list(data.get("history") or []),
        )


class SubmissionLedger:
    """Durable storage for submission records (SQLite), with an in-memory mode.

    A configured path that cannot be opened is a hard failure: a submission that
    cannot be persisted must not silently live only in memory, because the
    ledger is what prevents a blind re-submission after a restart.
    """

    def __init__(self, path: str | None = None) -> None:
        self._lock = threading.RLock()
        self._memory: dict[str, SubmissionRecord] = {}
        self._conn: sqlite3.Connection | None = None
        self.path = path
        if path:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                    tx_hash TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL DEFAULT '',
                    record TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS submissions_idem ON submissions(idempotency_key)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS submissions_state ON submissions(state)"
            )
            self._conn.commit()

    @property
    def backend(self) -> str:
        return "sqlite" if self._conn is not None else "in-memory"

    def put(self, record: SubmissionRecord) -> None:
        record.updated_at = _utc_now()
        blob = record.to_json()
        with self._lock:
            if self._conn is not None:
                # The signed bytes are the evidence of *what was signed*; once
                # recorded they must never be silently replaced by different bytes
                # (a substitution) or cleared (which would erase the only artifact
                # a restart can re-verify). A state/settlement update carries the
                # same bytes, so this refuses only a real change.
                existing = self._existing_signed(record.tx_hash)
                if existing and record.signed_b64 != existing:
                    raise SubmissionLedgerError(
                        "refusing to overwrite the recorded signed transaction for "
                        f"{record.tx_hash[:16]}…; the original signed bytes are immutable"
                    )
                self._conn.execute(
                    "INSERT INTO submissions (tx_hash, state, idempotency_key, record, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(tx_hash) DO UPDATE SET "
                    "state=excluded.state, idempotency_key=excluded.idempotency_key, "
                    "record=excluded.record, updated_at=excluded.updated_at",
                    (record.tx_hash, record.state, record.idempotency_key, blob, record.updated_at),
                )
                self._conn.commit()
            else:
                previous = self._memory.get(record.tx_hash)
                if previous is not None and previous.signed_b64 and record.signed_b64 != previous.signed_b64:
                    raise SubmissionLedgerError(
                        "refusing to overwrite the recorded signed transaction for "
                        f"{record.tx_hash[:16]}…; the original signed bytes are immutable"
                    )
                # Store a copy (JSON round-trip) so the in-memory backend has the
                # same value semantics as SQLite: a caller mutating a record it
                # read cannot silently change what is stored.
                self._memory[record.tx_hash] = SubmissionRecord.from_json(record.to_json())

    def _existing_signed(self, tx_hash: str) -> str:
        row = self._conn.execute(
            "SELECT record FROM submissions WHERE tx_hash = ?", (tx_hash,)
        ).fetchone()
        if not row:
            return ""
        return str(json.loads(row[0]).get("signed_b64", ""))

    def get(self, tx_hash: str) -> SubmissionRecord | None:
        with self._lock:
            if self._conn is not None:
                row = self._conn.execute(
                    "SELECT record FROM submissions WHERE tx_hash = ?", (tx_hash,)
                ).fetchone()
                return SubmissionRecord.from_json(row[0]) if row else None
            return self._memory.get(tx_hash)

    def get_by_idempotency(self, key: str) -> SubmissionRecord | None:
        if not key:
            return None
        with self._lock:
            if self._conn is not None:
                row = self._conn.execute(
                    "SELECT record FROM submissions WHERE idempotency_key = ? "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (key,),
                ).fetchone()
                return SubmissionRecord.from_json(row[0]) if row else None
            for record in self._memory.values():
                if record.idempotency_key == key:
                    return record
            return None

    def pending(self) -> tuple[SubmissionRecord, ...]:
        """Every record whose outcome is not yet resolved, oldest first."""
        with self._lock:
            if self._conn is not None:
                rows = self._conn.execute(
                    "SELECT record FROM submissions WHERE state IN (?, ?, ?) "
                    "ORDER BY updated_at ASC",
                    tuple(PENDING_STATES),
                ).fetchall()
                return tuple(SubmissionRecord.from_json(r[0]) for r in rows)
            return tuple(r for r in self._memory.values() if r.pending)

    def all(self) -> tuple[SubmissionRecord, ...]:
        with self._lock:
            if self._conn is not None:
                rows = self._conn.execute("SELECT record FROM submissions").fetchall()
                return tuple(SubmissionRecord.from_json(r[0]) for r in rows)
            return tuple(self._memory.values())

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
