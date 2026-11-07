"""PostgreSQL backend for the guard's durable authorization state.

Why this exists
---------------
A SQLite file is durable state for **one** application instance: two hosts cannot
share it. When several TraceSettle replicas must agree on which authorization
nonces are spent, which are revoked, and how much a service has spent in the
current window, that state has to live in one shared database. This module is
that shared backend.

It is an *optional* dependency. The package imports nothing third-party at
module load; :mod:`psycopg` is imported lazily inside :func:`open_postgres_state_store`
and the store constructor, so the SQLite default and the settlement engine keep
running on a standard-library-only interpreter. Selecting the PostgreSQL backend
without ``psycopg`` installed is a hard startup error, never a silent downgrade.

Correctness model
-----------------
Distributed correctness is placed in the *database*, not in process-local locks
(which are meaningless across hosts):

* **Single-use nonce** — ``consumed_nonces`` has a ``PRIMARY KEY`` on ``nonce``;
  the consumption is one ``INSERT`` that returns its row. A concurrent second
  insert raises ``UniqueViolation`` and the attempt is refused. Exactly one
  caller can ever win, on any host.
* **Limits** — the whole decision (read the window counters, run the controls,
  claim the idempotency key, append the counter events) runs in one transaction
  that first takes a transaction-scoped advisory lock
  (``pg_advisory_xact_lock``), the PostgreSQL analogue of SQLite's
  ``BEGIN IMMEDIATE``. A second instance's decision waits at the lock until the
  first commits, then reads the winner's committed counters, so two concurrent
  decisions cannot both read an empty window and both authorize. This is
  deterministic and needs no retry loop; a bounded ``lock_timeout`` means a stuck
  holder surfaces as a fail-closed :class:`~tracesettle.guard.state.StateStoreConflict`
  rather than hanging.
* **Idempotency and revocation** are ``PRIMARY KEY`` upserts, so they are
  single-valued across every instance.
* **Migrations** are serialised by a session-scoped advisory lock
  (``pg_advisory_lock``) held across the inspect-and-migrate sequence. PostgreSQL
  ``CREATE TABLE IF NOT EXISTS`` is not atomic, so without this lock several
  instances starting against the same empty database would race the catalog and
  all but one would fail on a first deployment.

Every method raises :class:`~tracesettle.guard.state.StateStoreError` on a
database problem and never falls back to in-memory state, so an outage fails
closed. A transient serialization failure is the one exception: it is a
:class:`StateStoreConflict` (a ``StateStoreError`` subclass) that a caller may
retry, but exhausting the retries is still a failure, never an allow.

The connection string is a secret. It is stored, never logged, and never
included in an exception message; errors name the host/port at most, never the
password.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator

from .state import (
    SCHEMA_VERSION,
    CounterEvent,
    StateStoreConflict,
    StateStoreError,
    _decimal_or_none,
)

#: Postgres SQLSTATEs that mean "a concurrent transaction conflicted; retry".
_RETRYABLE_SQLSTATES = frozenset(
    {
        "40001",  # serialization_failure
        "40P01",  # deadlock_detected
        "55P03",  # lock_not_available (our bounded advisory-lock wait elapsed)
    }
)

DEFAULT_CONNECT_TIMEOUT_S = 10
DEFAULT_STATEMENT_TIMEOUT_MS = 5000
DEFAULT_APPLICATION_NAME = "tracesettle"

#: Fixed 64-bit key for the transaction-scoped advisory lock that serialises
#: decisions across every instance. Any constant works as long as it is stable;
#: this one is arbitrary but unique to the guard's decision cycle.
_DECISION_LOCK_KEY = 0x54524143_45535431  # "TRACEST1"

#: Fixed 64-bit key for the session-scoped advisory lock that serialises schema
#: migration across every instance. Distinct from the decision lock so the two
#: never contend. See :func:`_apply_pg_migrations`.
_MIGRATION_LOCK_KEY = 0x54524143_4553544D  # "TRACESTM"

#: How long a start-up waits for the migration lock before failing closed. A
#: migration is a handful of DDL statements (milliseconds), so this only ever
#: elapses if another instance is wedged mid-migration; failing the start-up is
#: better than hanging forever.
_MIGRATION_LOCK_TIMEOUT_MS = 30_000


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
#
# Mirrors the SQLite schema. Each step runs in one transaction, so a failure
# leaves the database at its previous version rather than half-migrated. Never
# edit a shipped migration; append a new one.
#
# ``at``/``expires_at``/``until`` are double precision epoch seconds, matching
# the SQLite backend so a decision behaves identically on either. ``amount`` is
# TEXT because money is carried as an exact decimal string, never a float.

_PG_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS consumed_nonces (
            nonce       TEXT PRIMARY KEY,
            expires_at  DOUBLE PRECISION NOT NULL,
            consumed_at DOUBLE PRECISION NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS consumed_nonces_expires_at ON consumed_nonces(expires_at)",
        """
        CREATE TABLE IF NOT EXISTS revoked_authorizations (
            authorization_id TEXT PRIMARY KEY,
            until            DOUBLE PRECISION NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS revoked_authorizations_until ON revoked_authorizations(until)",
        """
        CREATE TABLE IF NOT EXISTS counter_events (
            seq        BIGSERIAL PRIMARY KEY,
            at         DOUBLE PRECISION NOT NULL,
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
            at          DOUBLE PRECISION NOT NULL
        )
        """,
    ),
    # The window read is ``WHERE at >= $1``; it needs a leading ``at`` index so it
    # is an index scan, not a sequential scan of a table that grows per decision.
    2: (
        "CREATE INDEX IF NOT EXISTS counter_events_at ON counter_events(at)",
        "CREATE INDEX IF NOT EXISTS idempotency_at ON idempotency(at)",
    ),
    # Short-lived sandbox integration credentials (see the SQLite store). The
    # shape matches so both backends satisfy the same ``StateStore`` contract.
    3: (
        """
        CREATE TABLE IF NOT EXISTS sandbox_credentials (
            credential_id TEXT PRIMARY KEY,
            label         TEXT NOT NULL,
            scope         TEXT NOT NULL,
            secret_hash   TEXT NOT NULL,
            approval_hash TEXT,
            service_id    TEXT NOT NULL,
            created_at    DOUBLE PRECISION NOT NULL,
            expires_at    DOUBLE PRECISION NOT NULL,
            revoked       INTEGER NOT NULL DEFAULT 0,
            request_count INTEGER NOT NULL DEFAULT 0
        )
        """,
        "CREATE INDEX IF NOT EXISTS sandbox_credentials_expires_at "
        "ON sandbox_credentials(expires_at)",
    ),
}


class PostgresGuardStateStore:
    """A durable guard-state store backed by PostgreSQL, shared across instances.

    Thread-safe: one connection guarded by a re-entrant lock. The guard is
    threaded, and a psycopg connection is not shareable across threads without
    care, so every access is serialised. Cross-*instance* safety comes from the
    database — a unique key for nonces and a transaction-scoped advisory lock for
    the decision critical section — not from this lock, which only orders threads
    inside one process.

    The interface matches :class:`~tracesettle.guard.state.GuardStateStore`, so
    :class:`~tracesettle.guard.state.DurableReplayStore` and
    :class:`~tracesettle.guard.state.DurableRevocationStore` accept it unchanged
    and the guard's authorization logic is untouched.
    """

    def __init__(
        self,
        dsn: str,
        *,
        connect_timeout_s: int = DEFAULT_CONNECT_TIMEOUT_S,
        statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
        application_name: str = DEFAULT_APPLICATION_NAME,
        decision_lock_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
        check_connection: bool = True,
    ) -> None:
        try:
            import psycopg  # noqa: F401  (imported for availability; used via self._psycopg)
            import psycopg.errors  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise StateStoreError(
                "the PostgreSQL guard-state backend requires the 'psycopg' package "
                "(pip install 'psycopg[binary]'); it is not part of the standard library"
            ) from exc

        import psycopg

        self._psycopg = psycopg
        self._lock = threading.RLock()
        self._closed = False
        #: Latched when a durable write fails in a way that is not a retryable
        #: conflict. Once set, every read and write raises, so a counter that
        #: failed to persist cannot leave a limit silently unenforced.
        self._degraded = False
        #: True while a decision transaction is open on this store. A dropped
        #: connection must then fail closed rather than reconnect: reconnecting
        #: would run the rest of the decision on a *new* transaction (and without
        #: the advisory lock), splitting one atomic decision into two and
        #: committing a partial result. See :meth:`_prepare`.
        self._in_decision = False
        self._decision_lock_timeout_ms = max(0, int(decision_lock_timeout_ms))
        # The DSN is a secret: keep it, never log it. Only host/port may appear in
        # an error, and even that is optional.
        self._dsn = dsn
        self._connect_kwargs: dict[str, Any] = {
            "connect_timeout": int(connect_timeout_s),
            "application_name": application_name,
            # Bound every statement so a lock wait cannot hang a decision forever.
            "options": f"-c statement_timeout={int(statement_timeout_ms)}",
        }
        try:
            self._connection = self._connect()
        except StateStoreError:
            raise
        except Exception as exc:  # psycopg.OperationalError and friends
            raise StateStoreError(
                f"cannot connect to the PostgreSQL state database: {_safe_pg_message(exc)}"
            ) from exc
        try:
            if check_connection:
                self._check_connection()
            _apply_pg_migrations(self._connection)
        except StateStoreError:
            self._safe_close()
            raise
        except Exception as exc:
            self._safe_close()
            raise StateStoreError(
                f"cannot initialise the PostgreSQL state database: {_safe_pg_message(exc)}"
            ) from exc

    # -- lifecycle ----------------------------------------------------------

    def _connect(self):  # type: ignore[no-untyped-def]
        # autocommit mode: transactions are opened explicitly, so a bare read does
        # not leave an idle transaction holding locks.
        return self._psycopg.connect(self._dsn, autocommit=True, **self._connect_kwargs)

    def _check_connection(self) -> None:
        try:
            with self._connection.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        except Exception as exc:
            raise StateStoreError(
                f"the PostgreSQL state database did not answer a probe: {_safe_pg_message(exc)}"
            ) from exc

    def _safe_close(self) -> None:
        try:
            self._connection.close()
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._safe_close()
                self._closed = True

    @property
    def degraded(self) -> bool:
        """True once a non-retryable durable write failed. All later operations raise."""
        return self._degraded

    @property
    def backend(self) -> str:
        """The stable backend label reported by metrics."""
        return "postgresql"

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

    def _prepare(self) -> None:
        """Fail closed if the store is unusable, and reconnect if the link dropped.

        A lost connection is *not* a reason to latch degraded: every operation
        outside a decision is either a read or an idempotent single-statement
        write, and an interrupted transaction is rolled back by the server, so a
        fresh connection is safe to use. Latching degraded here would take an
        instance out of service for a transient network blip. A non-connection
        write failure still latches.

        The one exception is a connection lost *inside* a decision transaction.
        Reconnecting then would silently run the rest of the decision on a new
        transaction — and without the advisory lock — so the decision's writes
        (the idempotency claim, the counter events) would be split across two
        transactions and a partial result could be committed while the caller
        still sees ``ALLOW``. So a drop mid-decision fails closed instead: the
        decision is abandoned and the caller treats it as a state-store failure.
        """
        self._guard_usable()
        if self._connection is None or self._connection.closed:
            if self._in_decision:
                raise StateStoreError(
                    "the database connection was lost inside a decision transaction; "
                    "refusing to reconnect mid-decision so a partial decision cannot "
                    "be committed"
                )
            try:
                self._connection = self._connect()
            except Exception as exc:
                raise StateStoreError(
                    f"cannot reconnect to the PostgreSQL state database: {_safe_pg_message(exc)}"
                ) from exc

    def __enter__(self) -> "PostgresGuardStateStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- error translation --------------------------------------------------

    def _raise_for(self, exc: Exception, action: str) -> None:
        """Translate a psycopg error into the store's fail-closed exception.

        A serialization/deadlock failure is retryable and does not degrade the
        store. A *connection* error does not latch degraded either: the next call
        reconnects, so a transient blip does not take the instance out of service
        permanently (the failing call still raises, so it fails closed). Any other
        error — a syntax error, a constraint surprise, a server-side fault — latches
        degraded, because state may be inconsistent and it will not fix itself.
        """
        sqlstate = getattr(exc, "sqlstate", None)
        if sqlstate in _RETRYABLE_SQLSTATES:
            raise StateStoreConflict(
                f"{action} conflicted with a concurrent transaction ({sqlstate}); retry"
            ) from exc
        if isinstance(exc, self._psycopg.OperationalError) or isinstance(
            exc, self._psycopg.InterfaceError
        ):
            raise StateStoreError(f"{action} failed: the database connection was lost") from exc
        self._mark_degraded()
        raise StateStoreError(f"{action} failed: {_safe_pg_message(exc)}") from exc

    # -- transactions -------------------------------------------------------

    @contextmanager
    def _read_cursor(self) -> Iterator[Any]:
        with self._lock:
            self._prepare()
            try:
                cursor = self._connection.cursor()
            except Exception as exc:
                # A dead connection fails here, before the caller's own try/except,
                # so it must be translated here too: fail closed, never leak a
                # driver exception.
                self._raise_for(exc, "opening a read cursor")
                raise  # unreachable
            try:
                yield cursor
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass

    def schema_version(self) -> int:
        with self._lock:
            self._prepare()
            try:
                return _read_pg_version(self._connection)
            except Exception as exc:
                self._raise_for(exc, "reading the schema version")
                raise  # unreachable; keeps type checkers happy

    @contextmanager
    def decision_cycle(self) -> Iterator[None]:
        """Run a whole decision atomically across every instance.

        The counter read, the controls, the idempotency claim, and the counter
        append all run inside one transaction that first takes a transaction-scoped
        advisory lock (``pg_advisory_xact_lock``). The lock is the PostgreSQL
        analogue of SQLite's ``BEGIN IMMEDIATE``: a second instance's decision
        waits at the lock until the first commits, then reads the winner's
        committed counters. That makes the concurrent-limit guarantee deterministic
        — no reliance on a serialization failure being raised, so the body never
        has to be re-run.

        The lock is released automatically at commit or rollback. It is taken with
        a bounded ``lock_timeout`` so a stuck holder cannot hang a decision
        forever; exceeding it is a fail-closed :class:`StateStoreConflict`. A
        caller that raises inside the cycle rolls the whole thing back, so a
        partial decision never becomes durable state.
        """
        with self._lock:
            self._prepare()
            previous_in_decision = self._in_decision
            self._in_decision = True
            try:
                try:
                    with self._connection.transaction():
                        with self._connection.cursor() as cur:
                            # Serialise decisions across instances, with a bounded wait.
                            cur.execute(f"SET LOCAL lock_timeout = {int(self._decision_lock_timeout_ms)}")
                            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_DECISION_LOCK_KEY,))
                        yield
                except StateStoreConflict:
                    raise
                except Exception as exc:
                    # Only a real database error is translated. An exception raised by
                    # the caller's own decision body (an application error) is left to
                    # propagate unchanged: the transaction still rolls back, but the
                    # store is not degraded, exactly as the SQLite backend behaves.
                    if isinstance(exc, self._psycopg.Error):
                        # A connection lost mid-decision is *not* retryable: the
                        # transaction is gone, so re-running the body here would be
                        # unsafe, and _prepare already refuses to reconnect. Treat it
                        # as a plain fail-closed store error.
                        connection_lost = isinstance(
                            exc, (self._psycopg.OperationalError, self._psycopg.InterfaceError)
                        )
                        if (
                            not connection_lost
                            and getattr(exc, "sqlstate", None) in _RETRYABLE_SQLSTATES
                        ):
                            # The advisory-lock wait timed out: transient, retryable,
                            # and fail-closed if the caller gives up.
                            raise StateStoreConflict(
                                "the decision could not acquire the shared decision lock in "
                                "time; the request was not evaluated"
                            ) from exc
                        self._raise_for(exc, "running a decision transaction")
                    raise
            finally:
                self._in_decision = previous_in_decision

    # -- replay: atomic nonce consumption ----------------------------------

    def consume_nonce(self, nonce: str, expires_at: float) -> bool:
        """Atomically consume ``nonce``. True exactly once, for any number of callers.

        One ``INSERT`` with a ``PRIMARY KEY`` conflict: a concurrent second insert
        raises ``UniqueViolation`` and this returns False. The savepoint means a
        duplicate does not poison an enclosing decision transaction (PostgreSQL
        aborts a transaction on any error until a rollback or savepoint rollback).
        """
        now = time.time()
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "INSERT INTO consumed_nonces(nonce, expires_at, consumed_at) "
                            "VALUES (%s, %s, %s)",
                            (nonce, float(expires_at), now),
                        )
                return True
            except self._psycopg.errors.UniqueViolation:
                return False
            except Exception as exc:
                self._raise_for(exc, "nonce consumption")
                raise  # unreachable

    def is_nonce_consumed(self, nonce: str) -> bool:
        with self._read_cursor() as cursor:
            try:
                cursor.execute("SELECT 1 FROM consumed_nonces WHERE nonce = %s", (nonce,))
                return cursor.fetchone() is not None
            except Exception as exc:
                self._raise_for(exc, "nonce lookup")
                raise  # unreachable

    def prune_nonces(self, *, now: float | None = None) -> int:
        """Delete consumed nonces whose authorization has expired. Returns the count."""
        cutoff = time.time() if now is None else now
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute("DELETE FROM consumed_nonces WHERE expires_at < %s", (cutoff,))
                        return cur.rowcount
            except Exception as exc:
                self._raise_for(exc, "nonce prune")
                raise  # unreachable

    # -- authorization revocation ------------------------------------------

    def revoke_authorization(self, authorization_id: str, until: float) -> None:
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "INSERT INTO revoked_authorizations(authorization_id, until) "
                            "VALUES (%s, %s) ON CONFLICT (authorization_id) "
                            "DO UPDATE SET until = EXCLUDED.until",
                            (authorization_id, float(until)),
                        )
            except Exception as exc:
                self._raise_for(exc, "authorization revocation")
                raise  # unreachable

    def is_authorization_revoked(self, authorization_id: str, *, now: float | None = None) -> bool:
        cutoff = time.time() if now is None else now
        with self._read_cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT until FROM revoked_authorizations WHERE authorization_id = %s",
                    (authorization_id,),
                )
                row = cursor.fetchone()
            except Exception as exc:
                self._raise_for(exc, "revocation lookup")
                raise  # unreachable
        if row is None:
            return False
        return float(row[0]) >= cutoff

    # -- counters -----------------------------------------------------------

    def record_event(
        self,
        *,
        kind: str,
        service_id: str,
        outcome: str | None = None,
        asset: str | None = None,
        amount: object | None = None,
        at: float | None = None,
    ) -> None:
        """Append one durable counter event.

        Called inside a decision transaction, so it joins that transaction and
        commits with it; called on its own it auto-commits. The amount is stored
        as its exact decimal string, never a float.
        """
        moment = time.time() if at is None else at
        amount_text = None if amount is None else (amount if isinstance(amount, str) else str(amount))
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "INSERT INTO counter_events(at, kind, service_id, outcome, asset, amount) "
                            "VALUES (%s, %s, %s, %s, %s, %s)",
                            (moment, kind, service_id, outcome, asset, amount_text),
                        )
            except Exception as exc:
                self._raise_for(exc, "recording a counter event")
                raise  # unreachable

    def events_since(
        self, *, since: float, service_id: str | None = None, kind: str | None = None
    ) -> list[CounterEvent]:
        """Read counter events at or after ``since``, newest last."""
        clauses = ["at >= %s"]
        params: list[Any] = [since]
        if service_id is not None:
            clauses.append("service_id = %s")
            params.append(service_id)
        if kind is not None:
            clauses.append("kind = %s")
            params.append(kind)
        sql = (
            "SELECT at, kind, service_id, outcome, asset, amount FROM counter_events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY at ASC"
        )
        with self._read_cursor() as cursor:
            try:
                cursor.execute(sql, params)
                rows = cursor.fetchall()
            except Exception as exc:
                self._raise_for(exc, "reading counter events")
                raise  # unreachable
        return [
            CounterEvent(
                at=float(r[0]),
                kind=str(r[1]),
                service_id=str(r[2]),
                outcome=r[3],
                asset=r[4],
                amount=_decimal_or_none(r[5]),
            )
            for r in rows
        ]

    def prune_events(self, *, before: float) -> int:
        """Delete counter events older than ``before``. Returns the count.

        Events this old cannot affect any window, so dropping them keeps the table
        bounded and the window read fast. Runs on its own transaction so it cannot
        roll back a decision in progress.
        """
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute("DELETE FROM counter_events WHERE at < %s", (before,))
                        return cur.rowcount
            except Exception as exc:
                self._raise_for(exc, "pruning counter events")
                raise  # unreachable

    def prune_idempotency(self, *, before: float) -> int:
        """Delete idempotency keys older than ``before``. Returns the count."""
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute("DELETE FROM idempotency WHERE at < %s", (before,))
                        return cur.rowcount
            except Exception as exc:
                self._raise_for(exc, "pruning idempotency keys")
                raise  # unreachable

    # -- idempotency --------------------------------------------------------

    def remember_decision(self, request_key: str, decision_id: str, *, at: float | None = None) -> bool:
        """Record that ``request_key`` was decided. True if newly recorded.

        False means the same key was already decided; the caller must not account
        for the transaction a second time. The savepoint keeps a duplicate from
        aborting an enclosing decision transaction.
        """
        moment = time.time() if at is None else at
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "INSERT INTO idempotency(request_key, decision_id, at) "
                            "VALUES (%s, %s, %s)",
                            (request_key, decision_id, moment),
                        )
                return True
            except self._psycopg.errors.UniqueViolation:
                return False
            except Exception as exc:
                self._raise_for(exc, "idempotency record")
                raise  # unreachable

    def decision_for(self, request_key: str) -> str | None:
        with self._read_cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT decision_id FROM idempotency WHERE request_key = %s", (request_key,)
                )
                row = cursor.fetchone()
            except Exception as exc:
                self._raise_for(exc, "idempotency lookup")
                raise  # unreachable
            return None if row is None else str(row[0])

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
        moment = time.time() if at is None else at
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "INSERT INTO sandbox_credentials("
                            "credential_id, label, scope, secret_hash, approval_hash, service_id, "
                            "created_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
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
            except Exception as exc:
                self._raise_for(exc, "recording a sandbox credential")
                raise  # unreachable

    def sandbox_credentials(self, *, include_inactive: bool = False) -> list[dict[str, Any]]:
        now = time.time()
        with self._read_cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT credential_id, label, scope, service_id, created_at, expires_at, "
                    "revoked, request_count, approval_hash FROM sandbox_credentials "
                    "ORDER BY created_at DESC"
                )
                rows = cursor.fetchall()
            except Exception as exc:
                self._raise_for(exc, "sandbox credential lookup")
                raise  # unreachable
        out: list[dict[str, Any]] = []
        for row in rows:
            record = {
                "credential_id": str(row[0]),
                "label": str(row[1]),
                "scope": str(row[2]),
                "service_id": str(row[3]),
                "created_at": float(row[4]),
                "expires_at": float(row[5]),
                "revoked": bool(row[6]),
                "request_count": int(row[7]),
                "has_approval_secret": row[8] is not None,
            }
            record["expired"] = record["expires_at"] <= now
            record["active"] = not record["revoked"] and not record["expired"]
            if include_inactive or record["active"]:
                out.append(record)
        return out

    def sandbox_credential_secrets(self) -> list[dict[str, Any]]:
        """Return the hash material for credential resolution (never a plaintext)."""
        with self._read_cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT credential_id, secret_hash, approval_hash, revoked, expires_at, "
                    "request_count FROM sandbox_credentials"
                )
                rows = cursor.fetchall()
            except Exception as exc:
                self._raise_for(exc, "sandbox credential secret lookup")
                raise  # unreachable
        return [
            {
                "credential_id": str(row[0]),
                "secret_hash": row[1],
                "approval_hash": row[2],
                "revoked": bool(row[3]),
                "expires_at": float(row[4]),
                "request_count": int(row[5]),
            }
            for row in rows
        ]

    def revoke_sandbox_credential(self, credential_id: str) -> bool:
        with self._lock:
            self._prepare()
            try:
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "UPDATE sandbox_credentials SET revoked = 1 WHERE credential_id = %s",
                            (credential_id,),
                        )
                        return cur.rowcount > 0
            except Exception as exc:
                self._raise_for(exc, "revoking a sandbox credential")
                raise  # unreachable

    def touch_sandbox_credential(self, credential_id: str) -> None:
        """Increment a credential's use counter. Best-effort, never fatal."""
        try:
            with self._lock:
                self._prepare()
                with self._connection.transaction():
                    with self._connection.cursor() as cur:
                        cur.execute(
                            "UPDATE sandbox_credentials SET request_count = request_count + 1 "
                            "WHERE credential_id = %s",
                            (credential_id,),
                        )
        except Exception:
            return


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------


def _apply_pg_migrations(connection: Any) -> None:
    """Bring ``connection`` up to :data:`SCHEMA_VERSION`, one step per transaction.

    The inspect-and-migrate sequence is serialised across every starting instance
    by a session-scoped advisory lock. ``CREATE TABLE IF NOT EXISTS`` — and every
    other ``IF NOT EXISTS`` statement here — is **not** atomic: two instances
    starting against the same *empty* database can both observe the object missing
    and both attempt to create it, and PostgreSQL rejects the loser with a
    ``UniqueViolation`` on the internal ``pg_type`` catalog
    (``pg_type_typname_nsp_index``). Without serialisation, every instance but one
    fails to start on a first deployment.

    The lock is held for the whole inspect-and-migrate sequence and released on the
    same connection in a ``finally``, so a later instance waits, then re-reads the
    *committed* version and finds nothing to do. The wait is bounded
    (:data:`_MIGRATION_LOCK_TIMEOUT_MS`), so a wedged migration fails a start-up
    closed instead of hanging it forever. A migration failure still propagates as
    :class:`StateStoreError` with each step's transaction rolled back, so a
    half-migrated database is never reported as successfully initialised.
    """
    # Capture the session's current lock_timeout so it can be restored exactly;
    # ``set_config`` takes a bound parameter, unlike ``SET``.
    with connection.cursor() as cur:
        cur.execute("SELECT current_setting('lock_timeout')")
        previous_lock_timeout = cur.fetchone()[0]
        cur.execute(
            "SELECT set_config('lock_timeout', %s, false)",
            (str(int(_MIGRATION_LOCK_TIMEOUT_MS)),),
        )
    acquired = False
    try:
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_KEY,))
            acquired = True
        except Exception as exc:
            raise StateStoreError(
                "could not acquire the schema-migration lock within "
                f"{_MIGRATION_LOCK_TIMEOUT_MS} ms; another instance may be migrating"
            ) from exc
        _run_pg_migrations(connection)
    finally:
        # Best effort: never let cleanup mask a migration failure. If the
        # connection is already dead the server releases the session lock when it
        # closes, so a failed unlock here cannot leak the lock past this session.
        if acquired:
            try:
                with connection.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_KEY,))
            except Exception:
                pass
        try:
            with connection.cursor() as cur:
                cur.execute(
                    "SELECT set_config('lock_timeout', %s, false)", (previous_lock_timeout,)
                )
        except Exception:
            pass


def _run_pg_migrations(connection: Any) -> None:
    """Apply each pending migration step, one transaction per step."""
    current = _read_pg_version(connection)
    if current > SCHEMA_VERSION:
        raise StateStoreError(
            f"state database schema version {current} is newer than this build "
            f"understands ({SCHEMA_VERSION}); refusing to run against it"
        )
    for target in range(current + 1, SCHEMA_VERSION + 1):
        statements = _PG_MIGRATIONS.get(target)
        if statements is None:
            raise StateStoreError(f"no migration is defined for schema version {target}")
        try:
            with connection.transaction():
                with connection.cursor() as cur:
                    for statement in statements:
                        cur.execute(statement)
                    cur.execute("DELETE FROM schema_version")
                    cur.execute("INSERT INTO schema_version(version) VALUES (%s)", (target,))
        except StateStoreError:
            raise
        except Exception as exc:
            raise StateStoreError(
                f"migration to schema version {target} failed: {_safe_pg_message(exc)}"
            ) from exc


def _read_pg_version(connection: Any) -> int:
    """Return the stored schema version, or 0 for a fresh database."""
    with connection.cursor() as cur:
        cur.execute("SELECT to_regclass('public.schema_version')")
        row = cur.fetchone()
        if row is None or row[0] is None:
            return 0
        cur.execute("SELECT version FROM schema_version LIMIT 1")
        value = cur.fetchone()
        if value is None:
            return 0
        return int(value[0])


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def open_postgres_state_store(
    dsn: str,
    *,
    connect_timeout_s: int = DEFAULT_CONNECT_TIMEOUT_S,
    statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
    application_name: str = DEFAULT_APPLICATION_NAME,
    decision_lock_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
) -> PostgresGuardStateStore:
    """Open a PostgreSQL state store.

    A missing ``psycopg``, a bad DSN, or an unreachable server raises
    :class:`StateStoreError`, so a misconfigured deployment fails to start rather
    than running with an unenforced control. There is no in-memory fallback.
    """
    if not dsn or not str(dsn).strip():
        raise StateStoreError(
            "the PostgreSQL guard-state backend was selected but no connection string "
            "is configured (set TRACESETTLE_GUARD_STATE_PG_DSN)"
        )
    return PostgresGuardStateStore(
        dsn,
        connect_timeout_s=connect_timeout_s,
        statement_timeout_ms=statement_timeout_ms,
        application_name=application_name,
        decision_lock_timeout_ms=decision_lock_timeout_ms,
    )


def _safe_pg_message(exc: Exception) -> str:
    """A message safe to log: the exception text, with any DSN scrubbed.

    psycopg does not normally put the password in an exception, but this is
    defence in depth: a ``key=value`` DSN echoed inside a driver message would
    otherwise leak a credential into a log.
    """
    text = str(exc)
    for marker in ("password=", "postgresql://", "postgres://"):
        if marker in text:
            return f"{type(exc).__name__}: connection error (details withheld)"
    return f"{type(exc).__name__}: {text}"
