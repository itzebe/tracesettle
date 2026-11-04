"""Persistent security safeguards: the learning loop's memory.

The original mission is *identify, authorize, protect, execute, verify,
investigate, learn*. The first six steps existed; this module supplies the last
one. When a decision surfaces a security failure or an unverified condition, the
lesson is recorded as a **safeguard** and applied to later decisions, so a
repeated request is treated more strictly than the first one.

What a safeguard is
-------------------
A safeguard is a durable, evidence-backed tightening of one policy dimension,
scoped to a service identity and (optionally) an asset:

* ``require_approval_above`` — above this amount a human must approve.
* ``require_verification`` — the operation needs independent verification before
  it may sign.

Safeguards only ever make a decision **stricter**. Nothing here can grant a
permission, relax a limit, or edit the operator's policy: a safeguard is applied
*on top of* the configured policy, never instead of it. The operator's policy
remains authoritative, and an operator can clear a safeguard explicitly.

Determinism
-----------
The store is plain data. The same request plus the same safeguards always yields
the same decision, so ``reconcile.py``-style determinism holds for the guard too.

Durability
----------
SQLite (standard library), like the rest of the guard's durable state. A
configured database that cannot be opened is a hard failure, never a silent
fallback to a weaker (unsafeguarded) default.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

#: Bump when the schema changes and add a migration below.
SAFEGUARD_SCHEMA_VERSION = 1

DEFAULT_BUSY_TIMEOUT_MS = 5000

#: The dimensions a safeguard can tighten. Each is a *restriction*.
DIM_REQUIRE_APPROVAL_ABOVE = "require_approval_above"
DIM_REQUIRE_VERIFICATION = "require_verification"

KNOWN_DIMENSIONS = frozenset({DIM_REQUIRE_APPROVAL_ABOVE, DIM_REQUIRE_VERIFICATION})

#: How a safeguard is matched. A service-wide safeguard has no asset.
SCOPE_SERVICE = "service"
SCOPE_ASSET = "asset"


class SafeguardError(RuntimeError):
    """A durable-safeguard operation failed. Callers fail closed."""


@dataclass(frozen=True)
class Safeguard:
    """One durable tightening, with the evidence that justified it."""

    safeguard_id: str
    service_id: str
    #: ``None`` means the safeguard applies to every asset of the service.
    asset: str | None
    dimension: str
    #: For ``require_approval_above``: the amount above which approval is needed.
    #: For ``require_verification``: unused (None).
    threshold: Decimal | None
    reason_code: str
    reason: str
    created_at: float
    #: The decision that created it, for traceability.
    source_decision_id: str | None = None
    #: How many times this safeguard has changed a later decision.
    applied_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def scope(self) -> str:
        return SCOPE_ASSET if self.asset else SCOPE_SERVICE

    def to_dict(self) -> dict[str, Any]:
        return {
            "safeguard_id": self.safeguard_id,
            "service_id": self.service_id,
            "asset": self.asset,
            "scope": self.scope,
            "dimension": self.dimension,
            "threshold": None if self.threshold is None else _canonical(self.threshold),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "created_at": self.created_at,
            "source_decision_id": self.source_decision_id,
            "applied_count": self.applied_count,
            "metadata": dict(self.metadata),
        }


def _canonical(value: Decimal) -> str:
    """A decimal as a plain, non-exponential string (no float round-trip)."""
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _decimal_or_none(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


#: A service-wide safeguard sorts before an asset-specific one so an operator
#: reading the list sees the broadest rule first.
def _sort_key(s: Safeguard) -> tuple[Any, ...]:
    return (s.service_id, s.asset or "", s.dimension, s.created_at)


class SafeguardStore:
    """A durable store of security safeguards (SQLite, standard library only)."""

    def __init__(self, path: str, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._degraded = False
        try:
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            self._connection = sqlite3.connect(
                path, timeout=busy_timeout_ms / 1000, check_same_thread=False
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._migrate()
        except sqlite3.Error as exc:
            raise SafeguardError(f"could not open the safeguard store at '{path}': {exc}") from exc

    # -- lifecycle ----------------------------------------------------------

    @property
    def backend(self) -> str:
        return "sqlite"

    @property
    def degraded(self) -> bool:
        return self._degraded

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.close()
            except sqlite3.Error:
                pass

    def _migrate(self) -> None:
        with self._lock:
            try:
                with self._connection:
                    self._connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS safeguards (
                            safeguard_id       TEXT PRIMARY KEY,
                            service_id         TEXT NOT NULL,
                            asset              TEXT,
                            dimension          TEXT NOT NULL,
                            threshold          TEXT,
                            reason_code        TEXT NOT NULL,
                            reason             TEXT NOT NULL,
                            created_at         REAL NOT NULL,
                            source_decision_id TEXT,
                            applied_count      INTEGER NOT NULL DEFAULT 0,
                            metadata           TEXT NOT NULL DEFAULT '{}'
                        )
                        """
                    )
                    self._connection.execute(
                        "CREATE INDEX IF NOT EXISTS safeguards_scope "
                        "ON safeguards(service_id, asset, dimension)"
                    )
                    self._connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS safeguard_schema (
                            version INTEGER NOT NULL
                        )
                        """
                    )
                    row = self._connection.execute(
                        "SELECT version FROM safeguard_schema LIMIT 1"
                    ).fetchone()
                    if row is None:
                        self._connection.execute(
                            "INSERT INTO safeguard_schema(version) VALUES (?)",
                            (SAFEGUARD_SCHEMA_VERSION,),
                        )
                    elif int(row[0]) > SAFEGUARD_SCHEMA_VERSION:
                        raise SafeguardError(
                            f"safeguard store schema version {int(row[0])} is newer than this "
                            f"build understands ({SAFEGUARD_SCHEMA_VERSION}); refusing to run"
                        )
            except sqlite3.Error as exc:
                raise SafeguardError(f"could not migrate the safeguard store: {exc}") from exc

    # -- writes -------------------------------------------------------------

    def record(self, safeguard: Safeguard) -> Safeguard:
        """Persist a safeguard. Re-recording the same dimension+scope is idempotent.

        A safeguard is a *restriction*, so recording one twice must not weaken it:
        the stricter threshold wins, and the evidence from the first occurrence is
        kept (it is the one that triggered the lesson).
        """
        with self._lock:
            try:
                with self._connection:
                    existing = self._connection.execute(
                        "SELECT * FROM safeguards WHERE service_id=? AND "
                        "((asset IS NULL AND ? IS NULL) OR asset=?) AND dimension=?",
                        (safeguard.service_id, safeguard.asset, safeguard.asset, safeguard.dimension),
                    ).fetchone()
                    if existing is not None:
                        merged = _merge(existing, safeguard)
                        if merged is None:
                            return _row_to_safeguard(existing)
                        self._connection.execute(
                            "UPDATE safeguards SET threshold=?, reason_code=?, reason=?, "
                            "created_at=?, source_decision_id=?, metadata=? WHERE safeguard_id=?",
                            (
                                None if merged.threshold is None else _canonical(merged.threshold),
                                merged.reason_code,
                                merged.reason,
                                merged.created_at,
                                merged.source_decision_id,
                                json.dumps(merged.metadata),
                                existing["safeguard_id"],
                            ),
                        )
                        return merged
                    self._connection.execute(
                        "INSERT INTO safeguards (safeguard_id, service_id, asset, dimension, "
                        "threshold, reason_code, reason, created_at, source_decision_id, "
                        "applied_count, metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            safeguard.safeguard_id,
                            safeguard.service_id,
                            safeguard.asset,
                            safeguard.dimension,
                            None if safeguard.threshold is None else _canonical(safeguard.threshold),
                            safeguard.reason_code,
                            safeguard.reason,
                            safeguard.created_at,
                            safeguard.source_decision_id,
                            safeguard.applied_count,
                            json.dumps(safeguard.metadata),
                        ),
                    )
                return safeguard
            except sqlite3.Error as exc:
                self._degraded = True
                raise SafeguardError(f"could not persist a safeguard: {exc}") from exc

    def note_applied(self, safeguard_ids: list[str]) -> None:
        """Increment the applied counter for safeguards that changed a decision."""
        if not safeguard_ids:
            return
        with self._lock:
            try:
                with self._connection:
                    for sid in safeguard_ids:
                        self._connection.execute(
                            "UPDATE safeguards SET applied_count = applied_count + 1 "
                            "WHERE safeguard_id = ?",
                            (sid,),
                        )
            except sqlite3.Error as exc:
                self._degraded = True
                raise SafeguardError(f"could not update a safeguard counter: {exc}") from exc

    def clear(self, safeguard_id: str) -> bool:
        """Remove a safeguard. This is an operator action, not an automatic one."""
        with self._lock:
            try:
                with self._connection:
                    cur = self._connection.execute(
                        "DELETE FROM safeguards WHERE safeguard_id = ?", (safeguard_id,)
                    )
                return cur.rowcount > 0
            except sqlite3.Error as exc:
                self._degraded = True
                raise SafeguardError(f"could not clear a safeguard: {exc}") from exc

    # -- reads --------------------------------------------------------------

    def for_request(self, service_id: str, asset: str | None) -> tuple[Safeguard, ...]:
        """Every safeguard that applies to a request: service-wide, then asset."""
        asset_key = (asset or "").strip().upper() or None
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT * FROM safeguards WHERE service_id=? AND (asset IS NULL OR asset=?)",
                    (service_id, asset_key),
                ).fetchall()
            except sqlite3.Error as exc:
                raise SafeguardError(f"could not read safeguards: {exc}") from exc
        return tuple(sorted((_row_to_safeguard(r) for r in rows), key=_sort_key))

    def all(self) -> tuple[Safeguard, ...]:
        with self._lock:
            try:
                rows = self._connection.execute("SELECT * FROM safeguards").fetchall()
            except sqlite3.Error as exc:
                raise SafeguardError(f"could not list safeguards: {exc}") from exc
        return tuple(sorted((_row_to_safeguard(r) for r in rows), key=_sort_key))

    def count(self) -> int:
        with self._lock:
            try:
                row = self._connection.execute("SELECT COUNT(*) FROM safeguards").fetchone()
            except sqlite3.Error as exc:
                raise SafeguardError(f"could not count safeguards: {exc}") from exc
        return int(row[0]) if row else 0


def _merge(existing_row: sqlite3.Row, new: Safeguard) -> Safeguard | None:
    """Merge a newly observed safeguard into an existing one, keeping the stricter.

    Returns ``None`` when the existing safeguard is already at least as strict, so
    a repeated observation does not rewrite the record.
    """
    existing = _row_to_safeguard(existing_row)
    if existing.dimension == DIM_REQUIRE_APPROVAL_ABOVE:
        old_t = existing.threshold
        new_t = new.threshold
        if old_t is not None and (new_t is None or new_t >= old_t):
            return None
        threshold = new_t
    else:
        # require_verification is boolean; once set it stays set.
        return None
    return Safeguard(
        safeguard_id=existing.safeguard_id,
        service_id=existing.service_id,
        asset=existing.asset,
        dimension=existing.dimension,
        threshold=threshold,
        reason_code=existing.reason_code,
        reason=existing.reason,
        created_at=existing.created_at,
        source_decision_id=existing.source_decision_id,
        applied_count=existing.applied_count,
        metadata=dict(existing.metadata),
    )


def _row_to_safeguard(row: sqlite3.Row) -> Safeguard:
    return Safeguard(
        safeguard_id=row["safeguard_id"],
        service_id=row["service_id"],
        asset=row["asset"],
        dimension=row["dimension"],
        threshold=_decimal_or_none(row["threshold"]),
        reason_code=row["reason_code"],
        reason=row["reason"],
        created_at=float(row["created_at"]),
        source_decision_id=row["source_decision_id"],
        applied_count=int(row["applied_count"]),
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
    )


def open_safeguard_store(path: str | None, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS):
    """Open the configured safeguard store, or return ``None`` when unset.

    ``None`` is the in-memory default: no learning loop, and the guard behaves
    exactly as before. A configured path that cannot be opened raises, because a
    security record must not silently fall back to a weaker default.
    """
    if not path:
        return None
    return SafeguardStore(path, busy_timeout_ms=busy_timeout_ms)


def now_epoch() -> float:
    return time.time()
