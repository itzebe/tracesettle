"""Durable storage for settlement investigations.

A settlement investigation is only useful if it can be retrieved later. The
settlement engine itself stays pure and read-only; this module gives its output
a home on disk so a report produced before a restart can be read back, with its
evidence and its conclusion intact, using the standard-library ``sqlite3`` so no
infrastructure or runtime dependency is added.

Design rules, each tested:

* **Durable across restart.** A file-backed database is reopened and the report
  is read back byte-for-byte, so a conclusion is reproducible from what was
  recorded rather than re-derived from live sources.
* **Reproducible conclusions.** The stored report is the *same* structure the
  engine emitted; the conclusion is never recomputed from the stored summary, so
  the recorded evidence and the conclusion cannot drift apart.
* **Cross-owner isolation.** A report is read only by its owner; a different
  owner gets ``None``, never another owner's data.
* **Fail closed.** Every method raises :class:`InvestigationStoreError` on a
  database problem; there is no in-memory fallback once a database is configured.

**Honest scope.** Like the other stores, a SQLite file is durable state for one
application instance. The interface is narrow so a shared backend could implement
the same methods. Nothing sensitive is stored: an investigation holds only public
on-chain identifiers and the evidence already published by public sources.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

#: Bump when the schema changes and append a migration below.
SCHEMA_VERSION = 1


class InvestigationStoreError(RuntimeError):
    """A durable investigations operation failed. The caller must fail closed."""


_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            owner            TEXT NOT NULL,
            identifier       TEXT NOT NULL,
            outcome          TEXT NOT NULL,
            created_at       TEXT NOT NULL,
            report           TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS investigations_owner_created "
        "ON investigations(owner, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS investigations_identifier "
        "ON investigations(identifier)",
    ),
}


class InvestigationStore:
    """A durable, owner-scoped store of settlement investigation reports."""

    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_ms: int = 5000) -> None:
        self.path = os.fspath(path)
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(self.path, check_same_thread=False)
        except sqlite3.Error as exc:
            raise InvestigationStoreError(
                f"cannot open the investigations database at {self.path!r}: {exc}"
            ) from exc
        self._connection.row_factory = sqlite3.Row
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            _apply_migrations(self._connection)
        except InvestigationStoreError:
            raise
        except sqlite3.Error as exc:
            raise InvestigationStoreError(f"cannot initialise the investigations database: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @property
    def backend(self) -> str:
        return "sqlite"

    @property
    def schema_version(self) -> int:
        with self._lock:
            return _read_version(self._connection)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise InvestigationStoreError(f"cannot begin a transaction: {exc}") from exc
            try:
                yield self._connection
            except sqlite3.Error as exc:
                self._connection.rollback()
                raise InvestigationStoreError(f"investigations database error: {exc}") from exc
            else:
                self._connection.commit()

    def save(self, report: dict[str, Any], *, owner: str = "local") -> dict[str, Any]:
        """Persist a report (an ``InvestigationReport.to_dict()``).

        A re-run of the same identifier replaces the stored report for the same
        ``investigation_id`` — the newest evidence wins — while a different
        investigation is a new row. This keeps the history bounded without
        silently dropping a distinct conclusion.
        """
        if not isinstance(report, dict):
            raise InvestigationStoreError("a report must be a mapping")
        investigation_id = report.get("investigation_id")
        if not isinstance(investigation_id, str) or not investigation_id.strip():
            raise InvestigationStoreError("a report must carry an investigation_id")
        identifier = ""
        raw_input = report.get("input")
        if isinstance(raw_input, dict):
            identifier = str(raw_input.get("identifier") or "")
        outcome = str(report.get("outcome") or "")
        created_at = str(report.get("created_at") or "")
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO investigations "
                "(investigation_id, owner, identifier, outcome, created_at, report) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(investigation_id) DO UPDATE SET "
                "owner=excluded.owner, identifier=excluded.identifier, outcome=excluded.outcome, "
                "created_at=excluded.created_at, report=excluded.report",
                (investigation_id, owner, identifier, outcome, created_at, json.dumps(report)),
            )
        return {
            "investigation_id": investigation_id,
            "owner": owner,
            "identifier": identifier,
            "outcome": outcome,
            "created_at": created_at,
        }

    def get(self, investigation_id: str, *, owner: str = "local") -> dict[str, Any] | None:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT report FROM investigations WHERE investigation_id = ? AND owner = ?",
                    (investigation_id, owner),
                ).fetchone()
            except sqlite3.Error as exc:
                raise InvestigationStoreError(f"investigations database error: {exc}") from exc
        return json.loads(row["report"]) if row else None

    def list_for_owner(self, owner: str = "local", *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT investigation_id, identifier, outcome, created_at FROM investigations "
                    "WHERE owner = ? ORDER BY created_at DESC, investigation_id DESC LIMIT ?",
                    (owner, int(limit)),
                ).fetchall()
            except sqlite3.Error as exc:
                raise InvestigationStoreError(f"investigations database error: {exc}") from exc
        return [dict(r) for r in rows]


def _apply_migrations(connection: sqlite3.Connection) -> None:
    current = _read_version(connection)
    if current > SCHEMA_VERSION:
        raise InvestigationStoreError(
            f"investigations database schema version {current} is newer than this build understands "
            f"({SCHEMA_VERSION}); refusing to run against it"
        )
    for target in range(current + 1, SCHEMA_VERSION + 1):
        statements = _MIGRATIONS.get(target)
        if statements is None:
            raise InvestigationStoreError(f"no migration is defined for schema version {target}")
        try:
            for statement in statements:
                connection.execute(statement)
            connection.execute("DELETE FROM schema_version")
            connection.execute("INSERT INTO schema_version (version) VALUES (?)", (target,))
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise InvestigationStoreError(f"migration to schema version {target} failed: {exc}") from exc


def _read_version(connection: sqlite3.Connection) -> int:
    try:
        row = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    except sqlite3.Error:
        return 0
    return int(row["version"]) if row else 0
