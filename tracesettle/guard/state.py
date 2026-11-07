"""Durable authorization state for the transaction guard.

The guard's security-critical state — spent nonces, revoked authorizations, and
the velocity / volume / rejection counters — must survive a process restart. A
restart that forgets a spent nonce re-enables a replay; a restart that clears a
spending window resets a limit. This module gives that state a home on disk.

Backend
-------
SQLite (standard library ``sqlite3``): no infrastructure, no new runtime
dependency, real transactions, and a ``PRIMARY KEY`` that makes single-use nonce
consumption atomic.

**Honest scope.** A SQLite file on a local volume is durable state for **one**
application instance. It is *not* multi-instance shared state: two hosts cannot
share the file, and network filesystems are unsupported. Two processes on one
host may share the file safely (SQLite serialises writers). The interface is kept
narrow so a future shared backend (PostgreSQL) can implement the same methods;
this repository has no PostgreSQL dependency, so none is introduced.

Fail-closed
-----------
Every method raises :class:`StateStoreError` on a database problem. Callers treat
that as a refusal, never as "assume the nonce was unused" or "assume the limit
was not reached". There is no in-memory fallback once a database is configured.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterator, Protocol, runtime_checkable

#: Bump when the schema changes and add a migration below.
SCHEMA_VERSION = 3

DEFAULT_BUSY_TIMEOUT_MS = 5000

#: Counter-event kinds. Stable strings: they are persisted.
EVENT_DECISION = "DECISION"
EVENT_AUTHORIZATION_ISSUED = "AUTHORIZATION_ISSUED"
EVENT_SIGNER = "SIGNER"

#: What a decision event's ``outcome`` holds when the decision was a block.
OUTCOME_BLOCK = "BLOCK"
OUTCOME_EXECUTED = "EXECUTED"


class StateStoreError(RuntimeError):
    """A durable-state operation failed. The caller must fail closed.

    The message is safe to log: it never contains a nonce, a secret, or a key.
    """


class StateStoreConflict(StateStoreError):
    """A transient conflict that a caller may safely retry.

    Raised when the database aborts a decision because it serialised against a
    concurrent one (for example a PostgreSQL ``SERIALIZABLE`` serialization
    failure). The store is *not* degraded and the transaction was rolled back, so
    retrying the whole decision is safe. A caller that exhausts its retries must
    still fail closed — never fall back to weaker state.
    """


@dataclass(frozen=True)
class CounterEvent:
    """One durable counter event, read back for the velocity context."""

    at: float
    kind: str
    service_id: str
    outcome: str | None = None
    asset: str | None = None
    amount: Decimal | None = None


@runtime_checkable
class StateStore(Protocol):
    """The durable-state contract both backends satisfy.

    ``GuardStateStore`` (SQLite) and ``PostgresGuardStateStore`` (PostgreSQL)
    implement this identical surface, so the guard's authorization and enforcement
    logic is backend-agnostic and unchanged. Every method raises
    :class:`StateStoreError` on failure; callers fail closed.
    """

    @property
    def degraded(self) -> bool: ...

    @property
    def backend(self) -> str: ...

    def close(self) -> None: ...

    def schema_version(self) -> int: ...

    def decision_cycle(self) -> Iterator[None]: ...

    def consume_nonce(self, nonce: str, expires_at: float) -> bool: ...

    def is_nonce_consumed(self, nonce: str) -> bool: ...

    def prune_nonces(self, *, now: float | None = None) -> int: ...

    def revoke_authorization(self, authorization_id: str, until: float) -> None: ...

    def is_authorization_revoked(self, authorization_id: str, *, now: float | None = None) -> bool: ...

    def record_event(
        self,
        *,
        kind: str,
        service_id: str,
        outcome: str | None = None,
        asset: str | None = None,
        amount: object | None = None,
        at: float | None = None,
    ) -> None: ...

    def events_since(
        self, *, since: float, service_id: str | None = None, kind: str | None = None
    ) -> list[CounterEvent]: ...

    def prune_events(self, *, before: float) -> int: ...

    def prune_idempotency(self, *, before: float) -> int: ...

    def remember_decision(
        self, request_key: str, decision_id: str, *, at: float | None = None
    ) -> bool: ...

    def decision_for(self, request_key: str) -> str | None: ...

    # -- sandbox integration credentials ------------------------------------

    def add_sandbox_credential(
        self,
        *,
        credential_id: str,
        label: str,
        scope: str,
        secret_hash: str,
        approval_hash: str | None,
        service_id: str,
        expires_at: float,
        at: float | None = None,
    ) -> None: ...

    def sandbox_credentials(self, *, include_inactive: bool = False) -> list[dict[str, Any]]: ...

    def sandbox_credential_secrets(self) -> list[dict[str, Any]]: ...

    def revoke_sandbox_credential(self, credential_id: str) -> bool: ...

    def touch_sandbox_credential(self, credential_id: str) -> None: ...


def _decimal_or_none(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
#
# Each migration is a list of statements that moves the database from version
# N-1 to N. They run inside one transaction per step, so a failure leaves the
# database at its previous version rather than half-migrated. Never edit a
# shipped migration; append a new one.

_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS consumed_nonces (
            nonce       TEXT PRIMARY KEY,
            expires_at  REAL NOT NULL,
            consumed_at REAL NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS consumed_nonces_expires_at ON consumed_nonces(expires_at)",
        """
        CREATE TABLE IF NOT EXISTS revoked_authorizations (
            authorization_id TEXT PRIMARY KEY,
            until            REAL NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS revoked_authorizations_until ON revoked_authorizations(until)",
        """
        CREATE TABLE IF NOT EXISTS counter_events (
            seq        INTEGER PRIMARY KEY AUTOINCREMENT,
            at         REAL NOT NULL,
            kind       TEXT NOT NULL,
            service_id TEXT NOT NULL,
            outcome    TEXT,
            asset      TEXT,
            amount     TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS counter_events_service_at ON counter_events(service_id, at)",
        "CREATE INDEX IF NOT EXISTS counter_events_kind_at ON counter_events(kind, at)",
        """
        CREATE TABLE IF NOT EXISTS idempotency (
            request_key TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            at          REAL NOT NULL
        )
        """,
    ),
    # The window read is ``WHERE at >= ?``, so it needs a *leading* ``at`` index.
    # The composite indexes above lead with ``service_id``/``kind`` and so cannot
    # serve that predicate; without this the read is a full scan of a table that
    # grows with every decision. ``counter_events_at`` is the fix.
    2: (
        "CREATE INDEX IF NOT EXISTS counter_events_at ON counter_events(at)",
        "CREATE INDEX IF NOT EXISTS idempotency_at ON idempotency(at)",
    ),
    # Short-lived, narrowly scoped *sandbox* integration credentials, so an
    # independent judge can connect an agent without the operator minting a
    # durable service credential. Kept in the same store as the nonce/limit state
    # because it is security-critical: a credential must survive a restart and be
    # honoured by every instance. Only the SHA-256 hash is stored; the secret is
    # shown once at issue time. ``scope`` and ``expires_at`` bound it, and
    # ``revoked`` lets an operator cut it off early.
    3: (
        """
        CREATE TABLE IF NOT EXISTS sandbox_credentials (
            credential_id TEXT PRIMARY KEY,
            label         TEXT NOT NULL,
            scope         TEXT NOT NULL,
            secret_hash   TEXT NOT NULL,
            approval_hash TEXT,
            service_id    TEXT NOT NULL,
            created_at    REAL NOT NULL,
            expires_at    REAL NOT NULL,
            revoked       INTEGER NOT NULL DEFAULT 0,
            request_count INTEGER NOT NULL DEFAULT 0
        )
        """,
        "CREATE INDEX IF NOT EXISTS sandbox_credentials_expires_at "
        "ON sandbox_credentials(expires_at)",
    ),
}


def _apply_migrations(connection: sqlite3.Connection) -> None:
    """Bring ``connection`` up to :data:`SCHEMA_VERSION`, one step per transaction."""
    current = _read_version(connection)
    if current > SCHEMA_VERSION:
        raise StateStoreError(
            f"state database schema version {current} is newer than this build "
            f"understands ({SCHEMA_VERSION}); refusing to run against it"
        )
    for target in range(current + 1, SCHEMA_VERSION + 1):
        statements = _MIGRATIONS.get(target)
        if statements is None:
            raise StateStoreError(f"no migration is defined for schema version {target}")
        try:
            with connection:  # one transaction for the whole step
                for statement in statements:
                    connection.execute(statement)
                connection.execute("DELETE FROM schema_version")
                connection.execute("INSERT INTO schema_version(version) VALUES (?)", (target,))
        except sqlite3.Error as exc:
            raise StateStoreError(f"migration to schema version {target} failed: {exc}") from exc


def _read_version(connection: sqlite3.Connection) -> int:
    """Return the stored schema version, or 0 for a fresh database."""
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if row is None:
        return 0
    value = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if value is None:
        return 0
    return int(value[0])


class GuardStateStore:
    """A durable store for the guard's security-critical state.

    Thread-safe: one SQLite connection guarded by a lock. SQLite connections are
    not shareable across threads by default, and the guard is threaded, so every
    access is serialised through :attr:`_lock`. Cross-*process* safety comes from
    SQLite's own file locking plus ``busy_timeout``.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        synchronous: str = "FULL",
        check_integrity: bool = True,
    ) -> None:
        self.path = os.fspath(path)
        self._lock = threading.RLock()
        self._closed = False
        #: Latched when a durable write fails. Once set, every read and write
        #: raises, so a failed counter write cannot silently disable a limit for
        #: the rest of the process lifetime.
        self._degraded = False
        try:
            # ``isolation_level=None`` puts the connection in autocommit mode so we
            # control transactions explicitly with BEGIN IMMEDIATE where a write
            # lock must be taken up front (atomic consume).
            self._connection = sqlite3.connect(
                self.path, timeout=busy_timeout_ms / 1000.0, isolation_level=None, check_same_thread=False
            )
        except sqlite3.Error as exc:
            raise StateStoreError(f"cannot open the state database at {self.path!r}: {exc}") from exc
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(f"PRAGMA synchronous={synchronous}")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            if check_integrity:
                self._check_integrity()
            _apply_migrations(self._connection)
        except StateStoreError:
            self._connection.close()
            raise
        except sqlite3.Error as exc:
            self._connection.close()
            raise StateStoreError(f"cannot initialise the state database: {exc}") from exc

    # -- lifecycle ----------------------------------------------------------

    def _check_integrity(self) -> None:
        row = self._connection.execute("PRAGMA quick_check").fetchone()
        if row is None or str(row[0]).lower() != "ok":
            raise StateStoreError(
                "state database failed its integrity check; refusing to run with "
                "possibly corrupt security state"
            )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    @property
    def degraded(self) -> bool:
        """True once a durable write failed. All later operations raise."""
        return self._degraded

    @property
    def backend(self) -> str:
        """A short, stable label for the durable backend (``sqlite``, ``postgresql``)."""
        return "sqlite"

    def _mark_degraded(self) -> None:
        # Called with the lock held.
        self._degraded = True

    def _guard_usable(self) -> None:
        # Called with the lock held. Order matters: closed first, then degraded.
        if self._closed:
            raise StateStoreError("the state database has been closed")
        if self._degraded:
            raise StateStoreError(
                "the state database is degraded after a failed write; refusing to "
                "use possibly-inconsistent security state"
            )

    def __enter__(self) -> "GuardStateStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            self._guard_usable()
            cursor = self._connection.cursor()
            try:
                yield cursor
            finally:
                cursor.close()

    def schema_version(self) -> int:
        with self._lock:
            return _read_version(self._connection)

    @contextmanager
    def decision_cycle(self) -> Iterator[None]:
        """Run a whole decision — read counters, decide, record — atomically.

        Without this, two concurrent evaluations can both read a window as empty
        and both authorize, exceeding the limit. ``BEGIN IMMEDIATE`` takes the
        write lock up front, so a second cycle (thread *or* process) waits and
        then sees the first cycle's events. Every read and write inside the cycle
        runs on the same transaction and commits as one unit.

        A caller that raises inside the cycle rolls the whole thing back, so a
        partial decision never becomes durable state.
        """
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise StateStoreError(f"could not begin a decision transaction: {exc}") from exc
            try:
                yield
            except BaseException:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            try:
                self._connection.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                self._mark_degraded()
                raise StateStoreError(f"could not commit a decision transaction: {exc}") from exc

    # -- replay: atomic nonce consumption ----------------------------------

    def consume_nonce(self, nonce: str, expires_at: float) -> bool:
        """Atomically consume ``nonce``. True exactly once, for any number of callers.

        The ``PRIMARY KEY`` on ``consumed_nonces`` is the guarantee: a concurrent
        second insert raises ``IntegrityError`` and this returns False. The whole
        thing is one ``INSERT``, so it is atomic across threads and processes.
        """
        now = time.time()
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute(
                    "INSERT INTO consumed_nonces(nonce, expires_at, consumed_at) VALUES (?, ?, ?)",
                    (nonce, float(expires_at), now),
                )
                return True
            except sqlite3.IntegrityError:
                return False
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"nonce consumption failed: {exc}") from exc

    def is_nonce_consumed(self, nonce: str) -> bool:
        with self._cursor() as cursor:
            try:
                row = cursor.execute(
                    "SELECT 1 FROM consumed_nonces WHERE nonce = ?", (nonce,)
                ).fetchone()
            except sqlite3.Error as exc:
                raise StateStoreError(f"nonce lookup failed: {exc}") from exc
            return row is not None

    def prune_nonces(self, *, now: float | None = None) -> int:
        """Delete consumed nonces whose authorization has expired. Returns the count."""
        cutoff = time.time() if now is None else now
        with self._lock:
            self._guard_usable()
            try:
                cursor = self._connection.execute(
                    "DELETE FROM consumed_nonces WHERE expires_at < ?", (cutoff,)
                )
                return cursor.rowcount
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"nonce prune failed: {exc}") from exc

    # -- authorization revocation ------------------------------------------

    def revoke_authorization(self, authorization_id: str, until: float) -> None:
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute(
                    "INSERT INTO revoked_authorizations(authorization_id, until) VALUES (?, ?) "
                    "ON CONFLICT(authorization_id) DO UPDATE SET until = excluded.until",
                    (authorization_id, float(until)),
                )
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"authorization revocation failed: {exc}") from exc

    def is_authorization_revoked(self, authorization_id: str, *, now: float | None = None) -> bool:
        cutoff = time.time() if now is None else now
        with self._cursor() as cursor:
            try:
                row = cursor.execute(
                    "SELECT until FROM revoked_authorizations WHERE authorization_id = ?",
                    (authorization_id,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise StateStoreError(f"revocation lookup failed: {exc}") from exc
        if row is None:
            return False
        return float(row["until"]) >= cutoff

    # -- counters -----------------------------------------------------------

    def record_event(
        self,
        *,
        kind: str,
        service_id: str,
        outcome: str | None = None,
        asset: str | None = None,
        amount: Decimal | str | None = None,
        at: float | None = None,
    ) -> None:
        """Append one durable counter event."""
        moment = time.time() if at is None else at
        amount_text = None if amount is None else (amount if isinstance(amount, str) else str(amount))
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute(
                    "INSERT INTO counter_events(at, kind, service_id, outcome, asset, amount) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (moment, kind, service_id, outcome, asset, amount_text),
                )
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"recording a counter event failed: {exc}") from exc

    def events_since(
        self, *, since: float, service_id: str | None = None, kind: str | None = None
    ) -> list[CounterEvent]:
        """Read counter events at or after ``since``, newest last."""
        clauses = ["at >= ?"]
        params: list[Any] = [since]
        if service_id is not None:
            clauses.append("service_id = ?")
            params.append(service_id)
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        sql = (
            "SELECT at, kind, service_id, outcome, asset, amount FROM counter_events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY at ASC"
        )
        with self._cursor() as cursor:
            try:
                rows = cursor.execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                raise StateStoreError(f"reading counter events failed: {exc}") from exc
        return [
            CounterEvent(
                at=float(r["at"]),
                kind=str(r["kind"]),
                service_id=str(r["service_id"]),
                outcome=r["outcome"],
                asset=r["asset"],
                amount=_decimal_or_none(r["amount"]),
            )
            for r in rows
        ]

    def prune_events(self, *, before: float) -> int:
        """Delete counter events older than ``before``. Returns the count.

        Events this old cannot affect any window, so dropping them keeps the table
        bounded and the window read fast. Deleting a row is a durable write, so it
        is deliberately *not* wrapped in the decision transaction: it runs on its
        own and cannot roll back a decision in progress.
        """
        with self._lock:
            self._guard_usable()
            try:
                cursor = self._connection.execute("DELETE FROM counter_events WHERE at < ?", (before,))
                return cursor.rowcount
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"pruning counter events failed: {exc}") from exc

    def prune_idempotency(self, *, before: float) -> int:
        """Delete idempotency keys older than ``before``. Returns the count.

        A key only needs to outlive a plausible retry, so dropping old ones keeps
        the table bounded without weakening duplicate detection for recent
        requests.
        """
        with self._lock:
            self._guard_usable()
            try:
                cursor = self._connection.execute("DELETE FROM idempotency WHERE at < ?", (before,))
                return cursor.rowcount
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"pruning idempotency keys failed: {exc}") from exc

    # -- idempotency --------------------------------------------------------

    def remember_decision(self, request_key: str, decision_id: str, *, at: float | None = None) -> bool:
        """Record that ``request_key`` was decided. True if newly recorded.

        False means the same key was already decided; the caller must not account
        for the transaction a second time.
        """
        moment = time.time() if at is None else at
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute(
                    "INSERT INTO idempotency(request_key, decision_id, at) VALUES (?, ?, ?)",
                    (request_key, decision_id, moment),
                )
                return True
            except sqlite3.IntegrityError:
                return False
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"idempotency record failed: {exc}") from exc

    def decision_for(self, request_key: str) -> str | None:
        with self._cursor() as cursor:
            try:
                row = cursor.execute(
                    "SELECT decision_id FROM idempotency WHERE request_key = ?", (request_key,)
                ).fetchone()
            except sqlite3.Error as exc:
                raise StateStoreError(f"idempotency lookup failed: {exc}") from exc
            return None if row is None else str(row["decision_id"])

    # -- sandbox integration credentials ------------------------------------

    def add_sandbox_credential(
        self,
        *,
        credential_id: str,
        label: str,
        scope: str,
        secret_hash: str,
        approval_hash: str | None,
        service_id: str,
        expires_at: float,
        at: float | None = None,
    ) -> None:
        """Persist one sandbox credential (hashes only; never the secrets)."""
        moment = time.time() if at is None else at
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute(
                    "INSERT INTO sandbox_credentials("
                    "credential_id, label, scope, secret_hash, approval_hash, service_id, "
                    "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        credential_id,
                        label,
                        scope,
                        secret_hash,
                        approval_hash,
                        service_id,
                        moment,
                        float(expires_at),
                    ),
                )
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"recording a sandbox credential failed: {exc}") from exc

    def sandbox_credentials(self, *, include_inactive: bool = False) -> list[dict[str, Any]]:
        """Return sandbox credentials (metadata only; never the secret or its hash).

        ``include_inactive`` includes expired and revoked rows for an operator
        audit; the default is the active set only.
        """
        now = time.time()
        with self._cursor() as cursor:
            try:
                rows = cursor.execute(
                    "SELECT credential_id, label, scope, service_id, created_at, expires_at, "
                    "revoked, request_count, approval_hash FROM sandbox_credentials "
                    "ORDER BY created_at DESC"
                ).fetchall()
            except sqlite3.Error as exc:
                raise StateStoreError(f"sandbox credential lookup failed: {exc}") from exc
        out: list[dict[str, Any]] = []
        for row in rows:
            record = {
                "credential_id": str(row["credential_id"]),
                "label": str(row["label"]),
                "scope": str(row["scope"]),
                "service_id": str(row["service_id"]),
                "created_at": float(row["created_at"]),
                "expires_at": float(row["expires_at"]),
                "revoked": bool(row["revoked"]),
                "request_count": int(row["request_count"]),
                "has_approval_secret": row["approval_hash"] is not None,
            }
            record["expired"] = record["expires_at"] <= now
            record["active"] = not record["revoked"] and not record["expired"]
            if include_inactive or record["active"]:
                out.append(record)
        return out

    def sandbox_credential_secrets(self) -> list[dict[str, Any]]:
        """Return the *hash material* for credential resolution.

        Internal to the sandbox authority: it needs the stored hashes to verify a
        presented secret. This never includes a plaintext secret (none is stored)
        and is not part of any API response.
        """
        with self._cursor() as cursor:
            try:
                rows = cursor.execute(
                    "SELECT credential_id, secret_hash, approval_hash, revoked, expires_at, "
                    "request_count FROM sandbox_credentials"
                ).fetchall()
            except sqlite3.Error as exc:
                raise StateStoreError(f"sandbox credential secret lookup failed: {exc}") from exc
        return [
            {
                "credential_id": str(row["credential_id"]),
                "secret_hash": row["secret_hash"],
                "approval_hash": row["approval_hash"],
                "revoked": bool(row["revoked"]),
                "expires_at": float(row["expires_at"]),
                "request_count": int(row["request_count"]),
            }
            for row in rows
        ]

    def revoke_sandbox_credential(self, credential_id: str) -> bool:
        with self._lock:
            self._guard_usable()
            try:
                cursor = self._connection.execute(
                    "UPDATE sandbox_credentials SET revoked = 1 WHERE credential_id = ?",
                    (credential_id,),
                )
                return cursor.rowcount > 0
            except sqlite3.Error as exc:
                self._mark_degraded()
                raise StateStoreError(f"revoking a sandbox credential failed: {exc}") from exc

    def touch_sandbox_credential(self, credential_id: str) -> None:
        """Increment a credential's use counter. Best-effort, never fatal."""
        with self._lock:
            self._guard_usable()
            try:
                self._connection.execute(
                    "UPDATE sandbox_credentials SET request_count = request_count + 1 "
                    "WHERE credential_id = ?",
                    (credential_id,),
                )
            except sqlite3.Error:
                # A counter is diagnostic, not a security control: a failure here
                # must not fail an otherwise valid request, and must not latch the
                # store degraded.
                return


class DurableReplayStore:
    """A :class:`~tracesettle.guard.authorization.ReplayStore` backed by SQLite.

    Structurally matches the in-memory store, so
    :class:`~tracesettle.guard.authorization.AuthorizationAuthority` accepts it
    unchanged. A database error raises :class:`StateStoreError`; the authority
    turns that into a refusal, never a silent "unused".

    The store also owns retention for the durable tables. ``consume`` is the one
    call made on every signing attempt, so it is the natural place to prune: it
    is called from the enforcement path and cannot be forgotten by a caller.
    """

    def __init__(
        self,
        store: GuardStateStore,
        *,
        prune_interval_seconds: float = 300.0,
        counter_retention_seconds: float = 86400.0,
        idempotency_retention_seconds: float = 86400.0,
    ) -> None:
        self._store = store
        self._prune_interval = prune_interval_seconds
        #: Counter events older than this cannot affect any window (the window is
        #: at most a few hours), so they are safe to drop. Without this the table
        #: grows without bound and the window read slows down forever.
        self._counter_retention = counter_retention_seconds
        #: An idempotency key only needs to be remembered for as long as a retry
        #: is plausible; a day is generous and keeps the table bounded too.
        self._idempotency_retention = idempotency_retention_seconds
        self._last_prune = 0.0

    def consume(self, nonce: str, expires_at: float) -> bool:
        self._maybe_prune()
        return self._store.consume_nonce(nonce, expires_at)

    def is_consumed(self, nonce: str) -> bool:
        return self._store.is_nonce_consumed(nonce)

    def _maybe_prune(self) -> None:
        now = time.time()
        if now - self._last_prune < self._prune_interval:
            return
        self._last_prune = now
        self._store.prune_nonces(now=now)
        self._store.prune_events(before=now - self._counter_retention)
        self._store.prune_idempotency(before=now - self._idempotency_retention)


class DurableRevocationStore:
    """A revocation store backed by SQLite (survives a restart)."""

    def __init__(self, store: GuardStateStore) -> None:
        self._store = store

    def revoke(self, authorization_id: str, until: float) -> None:
        self._store.revoke_authorization(authorization_id, until)

    def is_revoked(self, authorization_id: str) -> bool:
        return self._store.is_authorization_revoked(authorization_id)


def open_state_store(
    path: str | os.PathLike[str] | None,
    *,
    backend: str = "auto",
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    pg_dsn: str | None = None,
    pg_connect_timeout_s: int = 10,
    pg_statement_timeout_ms: int = 5000,
    require_postgres: bool = False,
) -> GuardStateStore | None:
    """Open the configured durable state store, or ``None`` for in-memory.

    Backend selection is explicit and fails closed:

    * ``auto`` (default) — PostgreSQL when a DSN is configured, else SQLite when a
      path is configured, else the in-memory stores. This keeps the loopback
      development workflow unchanged.
    * ``sqlite`` — a path is required; a missing one raises rather than silently
      running without durable state.
    * ``postgresql`` — a DSN is required; a missing one, or a server that cannot be
      reached, raises. ``psycopg`` must be installed.
    * ``memory`` — no durable store; spent nonces and counters are process-local.

    ``require_postgres`` is a production guard: when set, any selection other than
    PostgreSQL (including a missing DSN) raises. There is no override, so a
    deployment cannot silently lose shared authorization state.

    A configured backend that cannot be opened raises :class:`StateStoreError`: a
    durable-state control that silently degrades is worse than one that refuses to
    start. The DSN is never included in an error message.
    """
    choice = (backend or "auto").strip().lower()
    if choice not in {"auto", "memory", "sqlite", "postgresql"}:
        raise StateStoreError(
            f"unknown guard-state backend {backend!r}; expected one of "
            "auto, memory, sqlite, postgresql"
        )

    if require_postgres and choice != "postgresql":
        raise StateStoreError(
            "TRACESETTLE_GUARD_REQUIRE_POSTGRES is set, so the PostgreSQL backend is "
            f"required, but the configured backend is {choice!r}; set "
            "TRACESETTLE_GUARD_STATE_BACKEND=postgresql and "
            "TRACESETTLE_GUARD_STATE_PG_DSN, or unset the requirement"
        )

    if choice == "memory":
        return None

    if choice == "postgresql" or (choice == "auto" and pg_dsn):
        # Imported lazily so the SQLite default never pulls in the driver.
        from .state_pg import open_postgres_state_store

        return open_postgres_state_store(
            pg_dsn or "",
            connect_timeout_s=pg_connect_timeout_s,
            statement_timeout_ms=pg_statement_timeout_ms,
        )

    if choice == "sqlite" or (choice == "auto" and path):
        if not path:
            raise StateStoreError(
                "the sqlite guard-state backend was selected but "
                "TRACESETTLE_GUARD_STATE_DB is unset"
            )
        return GuardStateStore(path, busy_timeout_ms=busy_timeout_ms)

    return None
