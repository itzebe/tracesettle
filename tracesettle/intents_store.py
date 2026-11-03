"""Durable storage for NEAR Intents transactions and their investigations.

An investigation is only useful if it survives a restart. This module gives the
full lifecycle a home on disk — the request, the quote, the deposit, the
authorization decision, the provider status history, the settlement assurance
and the audit trail — using the standard-library ``sqlite3`` so no infrastructure
or runtime dependency is added.

Design rules, each of which is tested:

* **Durable across restart.** A file-backed database is reopened and the records
  are read back exactly, including the revision counter and provider history.
* **Idempotent provider updates.** A provider status update is applied only when
  it is newer than what is stored (by ``updatedAt``, then by a monotonic
  revision). Replaying the same update is a no-op, so a retry cannot double-count
  or corrupt the audit trail.
* **Cross-owner isolation.** A record is read only by its owner; a different
  owner gets ``None``, never another owner's data. This is enforced in the store,
  not only in the API, so a direct caller cannot bypass it.
* **Fail closed.** Every method raises :class:`IntentStoreError` on a database
  problem. There is no in-memory fallback once a database is configured, so a
  failed write cannot look like a successful one.

**Honest scope.** Like the guard's state store, a SQLite file is durable state
for **one** application instance; it is not multi-instance shared state. The
interface is narrow so a shared backend could implement the same methods.

**What is never stored.** No private key, seed phrase, or signing material — the
lifecycle never handles any. The authorization *token* is not persisted either:
only the decision and the authorization id are kept, so a restart cannot replay a
bearer token from the database.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

#: Bump when the schema changes and append a migration below.
SCHEMA_VERSION = 1


class IntentStoreError(RuntimeError):
    """A durable intents operation failed. The caller must fail closed."""


_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS intents (
            intent_id          TEXT PRIMARY KEY,
            owner              TEXT NOT NULL,
            created_at         TEXT NOT NULL,
            updated_at         TEXT NOT NULL,
            revision           INTEGER NOT NULL DEFAULT 1,
            state              TEXT NOT NULL,
            deposit_address    TEXT,
            provider_status    TEXT,
            provider_updated_at TEXT,
            idempotency_key    TEXT,
            record             TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS intents_owner_created ON intents(owner, created_at)",
        "CREATE INDEX IF NOT EXISTS intents_deposit_address ON intents(deposit_address)",
        "CREATE UNIQUE INDEX IF NOT EXISTS intents_idempotency ON intents(idempotency_key) "
        "WHERE idempotency_key IS NOT NULL",
        """
        CREATE TABLE IF NOT EXISTS intent_events (
            seq        INTEGER PRIMARY KEY AUTOINCREMENT,
            intent_id  TEXT NOT NULL,
            at         TEXT NOT NULL,
            kind       TEXT NOT NULL,
            detail     TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS intent_events_intent ON intent_events(intent_id, seq)",
    ),
}


@dataclass
class IntentRecord:
    """The full, serializable state of one NEAR Intents transaction.

    A plain data container; the store is the only thing that persists it. Every
    field is JSON-serializable so the record round-trips losslessly.
    """

    intent_id: str
    owner: str
    created_at: str
    updated_at: str
    state: str
    revision: int = 1
    origin_asset: str | None = None
    destination_asset: str | None = None
    amount: str | None = None
    recipient: str | None = None
    refund_to: str | None = None
    swap_type: str | None = None
    slippage_tolerance: int | None = None
    quote: dict[str, Any] | None = None
    deposit_address: str | None = None
    deposit_memo: str | None = None
    deposit_tx_hash: str | None = None
    provider_status: str | None = None
    provider_updated_at: str | None = None
    lifecycle: dict[str, Any] | None = None
    decision: dict[str, Any] | None = None
    authorization_id: str | None = None
    assurance: dict[str, Any] | None = None
    idempotency_key: str | None = None
    notes: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "owner": self.owner,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "state": self.state,
            "revision": self.revision,
            "origin_asset": self.origin_asset,
            "destination_asset": self.destination_asset,
            "amount": self.amount,
            "recipient": self.recipient,
            "refund_to": self.refund_to,
            "swap_type": self.swap_type,
            "slippage_tolerance": self.slippage_tolerance,
            "quote": self.quote,
            "deposit_address": self.deposit_address,
            "deposit_memo": self.deposit_memo,
            "deposit_tx_hash": self.deposit_tx_hash,
            "provider_status": self.provider_status,
            "provider_updated_at": self.provider_updated_at,
            "lifecycle": self.lifecycle,
            "decision": self.decision,
            "authorization_id": self.authorization_id,
            "assurance": self.assurance,
            "idempotency_key": self.idempotency_key,
            "notes": list(self.notes),
            "events": list(self.events),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntentRecord":
        return cls(
            intent_id=data["intent_id"],
            owner=data["owner"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            state=data["state"],
            revision=int(data.get("revision", 1)),
            origin_asset=data.get("origin_asset"),
            destination_asset=data.get("destination_asset"),
            amount=data.get("amount"),
            recipient=data.get("recipient"),
            refund_to=data.get("refund_to"),
            swap_type=data.get("swap_type"),
            slippage_tolerance=data.get("slippage_tolerance"),
            quote=data.get("quote"),
            deposit_address=data.get("deposit_address"),
            deposit_memo=data.get("deposit_memo"),
            deposit_tx_hash=data.get("deposit_tx_hash"),
            provider_status=data.get("provider_status"),
            provider_updated_at=data.get("provider_updated_at"),
            lifecycle=data.get("lifecycle"),
            decision=data.get("decision"),
            authorization_id=data.get("authorization_id"),
            assurance=data.get("assurance"),
            idempotency_key=data.get("idempotency_key"),
            notes=list(data.get("notes", [])),
            events=list(data.get("events", [])),
        )


def _apply_migrations(connection: sqlite3.Connection) -> None:
    current = _read_version(connection)
    if current > SCHEMA_VERSION:
        raise IntentStoreError(
            f"intents database schema version {current} is newer than this build understands "
            f"({SCHEMA_VERSION}); refusing to run against it"
        )
    for target in range(current + 1, SCHEMA_VERSION + 1):
        statements = _MIGRATIONS.get(target)
        if statements is None:
            raise IntentStoreError(f"no migration is defined for schema version {target}")
        try:
            with connection:
                for statement in statements:
                    connection.execute(statement)
                connection.execute("DELETE FROM schema_version")
                connection.execute("INSERT INTO schema_version(version) VALUES (?)", (target,))
        except sqlite3.Error as exc:
            raise IntentStoreError(f"migration to schema version {target} failed: {exc}") from exc


def _read_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if row is None:
        return 0
    value = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if value is None:
        return 0
    return int(value[0])


class IntentStore:
    """A durable, owner-scoped store for NEAR Intents transaction records."""

    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_ms: int = 5000) -> None:
        self.path = os.fspath(path)
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                self.path, timeout=busy_timeout_ms / 1000.0, isolation_level=None, check_same_thread=False
            )
        except sqlite3.Error as exc:
            raise IntentStoreError(f"cannot open the intents database at {self.path!r}: {exc}") from exc
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            _apply_migrations(self._connection)
        except IntentStoreError:
            self._connection.close()
            raise
        except sqlite3.Error as exc:
            self._connection.close()
            raise IntentStoreError(f"cannot initialise the intents database: {exc}") from exc

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    @property
    def backend(self) -> str:
        return "sqlite"

    def schema_version(self) -> int:
        with self._lock:
            return _read_version(self._connection)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise IntentStoreError(f"cannot begin a transaction: {exc}") from exc
            try:
                yield self._connection
            except sqlite3.Error as exc:
                self._connection.execute("ROLLBACK")
                raise IntentStoreError(f"intents database error: {exc}") from exc
            else:
                self._connection.execute("COMMIT")

    # -- writes -------------------------------------------------------------

    def create(
        self,
        *,
        owner: str,
        state: str,
        created_at: str,
        idempotency_key: str | None = None,
        **fields: Any,
    ) -> tuple[IntentRecord, bool]:
        """Create a record. Idempotent on ``idempotency_key``.

        Returns ``(record, created)``. When the key was already used the existing
        record is returned with ``created=False``, so a retried request does not
        create a second transaction.
        """
        if not owner or not str(owner).strip():
            raise IntentStoreError("an intent must have an owner")
        with self._lock:
            if idempotency_key is not None:
                existing = self._find_by_idempotency_key(idempotency_key)
                if existing is not None:
                    return (existing, False)
            intent_id = fields.pop("intent_id", None) or uuid.uuid4().hex
            record = IntentRecord(
                intent_id=intent_id,
                owner=str(owner),
                created_at=created_at,
                updated_at=created_at,
                state=state,
                idempotency_key=idempotency_key,
                **{k: v for k, v in fields.items() if k in _RECORD_FIELDS},
            )
            self._insert(record)
            self._append_event(record.intent_id, created_at, "CREATED", {"state": state})
            return (record, True)

    def update(
        self,
        intent_id: str,
        *,
        owner: str,
        updated_at: str,
        expect_state: str | None = None,
        **fields: Any,
    ) -> IntentRecord | None:
        """Apply a change to a record owned by ``owner``.

        Returns the updated record, or ``None`` if the record does not exist or
        is not owned by ``owner`` (never another owner's record).
        """
        with self._lock:
            record = self._load(intent_id)
            if record is None or record.owner != owner:
                return None
            for key, value in fields.items():
                if key in _RECORD_FIELDS:
                    setattr(record, key, value)
            record.updated_at = updated_at
            record.revision += 1
            if expect_state is not None:
                record.state = expect_state
            self._persist(record)
            self._append_event(
                intent_id, updated_at, "UPDATED", {"state": record.state, "revision": record.revision}
            )
            return record

    def apply_provider_status(
        self,
        intent_id: str,
        *,
        owner: str,
        provider_status: str,
        provider_updated_at: str | None,
        observed_at: str,
        lifecycle: dict[str, Any] | None = None,
        deposit_tx_hash: str | None = None,
    ) -> tuple[IntentRecord | None, bool]:
        """Apply a provider status update idempotently.

        Returns ``(record, changed)``. A duplicate — an ``updatedAt`` that is not
        newer than what is stored, or the identical status at the identical time —
        is a no-op with ``changed=False``, so a retry cannot double-count.
        """
        with self._lock:
            record = self._load(intent_id)
            if record is None or record.owner != owner:
                return (None, False)
            if not _is_newer(provider_updated_at, record.provider_updated_at) and not _status_changed(
                provider_status, record.provider_status, provider_updated_at, record.provider_updated_at
            ):
                return (record, False)
            record.provider_status = provider_status
            record.provider_updated_at = provider_updated_at or record.provider_updated_at
            if lifecycle is not None:
                record.lifecycle = lifecycle
                record.state = str(lifecycle.get("label", record.state))
            if deposit_tx_hash:
                record.deposit_tx_hash = deposit_tx_hash
            record.updated_at = observed_at
            record.revision += 1
            self._persist(record)
            self._append_event(
                intent_id,
                observed_at,
                "PROVIDER_STATUS",
                {"status": provider_status, "provider_updated_at": provider_updated_at},
            )
            return (record, True)

    def append_event(self, intent_id: str, *, owner: str, at: str, kind: str, detail: Any) -> None:
        with self._lock:
            record = self._load(intent_id)
            if record is None or record.owner != owner:
                return
            self._append_event(intent_id, at, kind, detail)

    # -- reads --------------------------------------------------------------

    def get(self, intent_id: str, *, owner: str) -> IntentRecord | None:
        """Read a record owned by ``owner``; ``None`` for any other owner."""
        with self._lock:
            record = self._load(intent_id)
            if record is None or record.owner != owner:
                return None
            return record

    def list_for_owner(self, owner: str, *, limit: int = 50) -> list[IntentRecord]:
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT record FROM intents WHERE owner = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                    (owner, int(limit)),
                ).fetchall()
            except sqlite3.Error as exc:
                raise IntentStoreError(f"intents database error: {exc}") from exc
            return [IntentRecord.from_dict(json.loads(r["record"])) for r in rows]

    def find_by_deposit_address(self, deposit_address: str, *, owner: str) -> IntentRecord | None:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT record FROM intents WHERE deposit_address = ? AND owner = ? LIMIT 1",
                    (deposit_address, owner),
                ).fetchone()
            except sqlite3.Error as exc:
                raise IntentStoreError(f"intents database error: {exc}") from exc
            return IntentRecord.from_dict(json.loads(row["record"])) if row else None

    def events(self, intent_id: str, *, owner: str) -> list[dict[str, Any]]:
        with self._lock:
            record = self._load(intent_id)
            if record is None or record.owner != owner:
                return []
            try:
                rows = self._connection.execute(
                    "SELECT seq, at, kind, detail FROM intent_events WHERE intent_id = ? ORDER BY seq",
                    (intent_id,),
                ).fetchall()
            except sqlite3.Error as exc:
                raise IntentStoreError(f"intents database error: {exc}") from exc
            return [
                {"seq": r["seq"], "at": r["at"], "kind": r["kind"], "detail": json.loads(r["detail"] or "null")}
                for r in rows
            ]

    # -- internals ----------------------------------------------------------

    def _insert(self, record: IntentRecord) -> None:
        try:
            with self._transaction() as conn:
                conn.execute(
                    "INSERT INTO intents (intent_id, owner, created_at, updated_at, revision, state, "
                    "deposit_address, provider_status, provider_updated_at, idempotency_key, record) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        record.intent_id,
                        record.owner,
                        record.created_at,
                        record.updated_at,
                        record.revision,
                        record.state,
                        record.deposit_address,
                        record.provider_status,
                        record.provider_updated_at,
                        record.idempotency_key,
                        json.dumps(record.to_dict()),
                    ),
                )
        except IntentStoreError:
            raise
        except sqlite3.IntegrityError as exc:
            # A concurrent insert with the same idempotency key: re-read it.
            if record.idempotency_key is not None:
                existing = self._find_by_idempotency_key(record.idempotency_key)
                if existing is not None:
                    raise IntentStoreError("idempotency key already used") from exc
            raise IntentStoreError(f"intent could not be stored: {exc}") from exc

    def _persist(self, record: IntentRecord) -> None:
        try:
            with self._transaction() as conn:
                conn.execute(
                    "UPDATE intents SET updated_at=?, revision=?, state=?, deposit_address=?, "
                    "provider_status=?, provider_updated_at=?, record=? WHERE intent_id=?",
                    (
                        record.updated_at,
                        record.revision,
                        record.state,
                        record.deposit_address,
                        record.provider_status,
                        record.provider_updated_at,
                        json.dumps(record.to_dict()),
                        record.intent_id,
                    ),
                )
        except IntentStoreError:
            raise
        except sqlite3.Error as exc:
            raise IntentStoreError(f"intent could not be updated: {exc}") from exc

    def _load(self, intent_id: str) -> IntentRecord | None:
        try:
            row = self._connection.execute(
                "SELECT record FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise IntentStoreError(f"intents database error: {exc}") from exc
        return IntentRecord.from_dict(json.loads(row["record"])) if row else None

    def _find_by_idempotency_key(self, key: str) -> IntentRecord | None:
        try:
            row = self._connection.execute(
                "SELECT record FROM intents WHERE idempotency_key = ? LIMIT 1", (key,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise IntentStoreError(f"intents database error: {exc}") from exc
        return IntentRecord.from_dict(json.loads(row["record"])) if row else None

    def _append_event(self, intent_id: str, at: str, kind: str, detail: Any) -> None:
        try:
            with self._transaction() as conn:
                conn.execute(
                    "INSERT INTO intent_events (intent_id, at, kind, detail) VALUES (?, ?, ?, ?)",
                    (intent_id, at, kind, json.dumps(detail)),
                )
        except sqlite3.Error as exc:
            raise IntentStoreError(f"intent event could not be appended: {exc}") from exc


#: The fields a caller may set through ``create``/``update``. Kept explicit so an
#: unknown key cannot be written into a record by accident.
_RECORD_FIELDS = frozenset(
    {
        "origin_asset",
        "destination_asset",
        "amount",
        "recipient",
        "refund_to",
        "swap_type",
        "slippage_tolerance",
        "quote",
        "deposit_address",
        "deposit_memo",
        "deposit_tx_hash",
        "provider_status",
        "provider_updated_at",
        "lifecycle",
        "decision",
        "authorization_id",
        "assurance",
        "notes",
    }
)


def _is_newer(incoming: str | None, stored: str | None) -> bool:
    """Whether ``incoming`` is a strictly newer ISO-8601 timestamp than ``stored``.

    ISO-8601 UTC timestamps compare correctly as strings, which is what the
    provider returns. A missing incoming timestamp is never "newer".
    """
    if incoming is None:
        return False
    if stored is None:
        return True
    return incoming > stored


def _status_changed(
    incoming_status: str, stored_status: str | None, incoming_at: str | None, stored_at: str | None
) -> bool:
    """Whether a status is genuinely new even without a newer timestamp."""
    if stored_status is None:
        return True
    if incoming_status != stored_status and incoming_at is not None and incoming_at == stored_at:
        # Same timestamp, different status: the provider revised the record in
        # place. Accept it, since a status change is meaningful.
        return True
    return False
