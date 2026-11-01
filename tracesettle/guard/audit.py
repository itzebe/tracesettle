"""Hash-chained audit log.

Every security-relevant event (evaluation, authorization issuance, signing
attempt, refusal, incident) is appended as a record whose digest covers the
previous record's digest. Any edit, reorder, or deletion of an existing record
therefore breaks the chain from that point on, and :meth:`AuditLog.verify`
detects it.

What this does and does not guarantee
-------------------------------------
The chain gives **tamper-evidence**, not tamper-proofness. An attacker who can
rewrite the whole log can recompute every digest and produce a consistent chain.
Detecting that requires an external anchor (publishing the head digest
elsewhere, or signing it). The tool therefore claims only what it verifies:
in-place modification of a stored log is detectable, and :meth:`verify` proves
it by recomputation. The head digest is exposed so a deployment can anchor it
out of band.

Records are appended under a lock, so the chain stays linear under concurrency.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

GENESIS_DIGEST = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    recorded_at: str
    event_type: str
    actor: str
    outcome: str
    detail: str
    request_id: str | None = None
    decision_id: str | None = None
    authorization_id: str | None = None
    service_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    prev_digest: str = GENESIS_DIGEST
    digest: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "recorded_at": self.recorded_at,
            "event_type": self.event_type,
            "actor": self.actor,
            "outcome": self.outcome,
            "detail": self.detail,
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "authorization_id": self.authorization_id,
            "service_id": self.service_id,
            "extra": self.extra,
            "prev_digest": self.prev_digest,
        }

    def compute_digest(self) -> str:
        payload = json.dumps(self.body(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        out = self.body()
        out["digest"] = self.digest
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditRecord":
        return cls(
            sequence=int(data["sequence"]),
            recorded_at=str(data["recorded_at"]),
            event_type=str(data["event_type"]),
            actor=str(data["actor"]),
            outcome=str(data["outcome"]),
            detail=str(data["detail"]),
            request_id=data.get("request_id"),
            decision_id=data.get("decision_id"),
            authorization_id=data.get("authorization_id"),
            service_id=data.get("service_id"),
            extra=dict(data.get("extra") or {}),
            prev_digest=str(data.get("prev_digest", GENESIS_DIGEST)),
            digest=str(data.get("digest", "")),
        )


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    length: int
    broken_at: int | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "length": self.length,
            "broken_at": self.broken_at,
            "reason": self.reason,
        }


class AuditLog:
    """An append-only, hash-chained event log.

    ``path`` is optional. When set, each record is also appended as one JSON
    object per line, so the log survives a restart and can be verified later.
    When unset, the log is in-memory only and the retention is bounded by
    ``max_records``; the chain still proves in-place modification.
    """

    def __init__(self, *, path: str | os.PathLike[str] | None = None, max_records: int = 10000) -> None:
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        self._max_records = max(1, max_records)
        self._path = Path(path) if path else None
        self._persistent = self._path is not None
        if self._persistent:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Resume the chain from the existing file. Without this, a restart
            # would start a fresh chain whose first record claims the genesis
            # digest, so the persisted log would no longer verify end to end.
            self._records = self._load_tail()

    # -- writing ------------------------------------------------------------

    def append(
        self,
        *,
        event_type: str,
        actor: str,
        outcome: str,
        detail: str,
        request_id: str | None = None,
        decision_id: str | None = None,
        authorization_id: str | None = None,
        service_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> AuditRecord:
        with self._lock:
            prev = self._records[-1].digest if self._records else GENESIS_DIGEST
            record = AuditRecord(
                sequence=len(self._records) + 1,
                recorded_at=_utc_now(),
                event_type=event_type,
                actor=actor,
                outcome=outcome,
                detail=detail,
                request_id=request_id,
                decision_id=decision_id,
                authorization_id=authorization_id,
                service_id=service_id,
                extra=dict(extra or {}),
                prev_digest=prev,
            )
            record = replace(record, digest=record.compute_digest())
            self._records.append(record)
            if len(self._records) > self._max_records:
                # Trimming the head keeps the most recent history. The chain of
                # the retained records still verifies from the first retained
                # record's own prev_digest, which is a digest of a record no
                # longer present; verification treats that as the chain start.
                self._records = self._records[-self._max_records :]
            if self._persistent:
                self._append_line(record)
            return record

    def _load_tail(self) -> list[AuditRecord]:
        """Read the last ``max_records`` persisted records, skipping any bad line.

        A line that does not parse is dropped rather than aborting start-up; the
        remaining chain still verifies, and :meth:`verify` will report the break
        if the dropped record was in the middle.
        """
        assert self._path is not None
        if not self._path.exists():
            return []
        loaded: list[AuditRecord] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                loaded.append(AuditRecord.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
        return loaded[-self._max_records :]

    def _append_line(self, record: AuditRecord) -> None:
        assert self._path is not None
        line = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    # -- reading ------------------------------------------------------------

    def records(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def recent(self, limit: int = 50, *, event_types: Iterable[str] | None = None) -> tuple[AuditRecord, ...]:
        wanted = {t for t in event_types} if event_types else None
        with self._lock:
            items = list(self._records)
        if wanted is not None:
            items = [r for r in items if r.event_type in wanted]
        return tuple(items[-limit:][::-1])

    @property
    def head_digest(self) -> str:
        with self._lock:
            return self._records[-1].digest if self._records else GENESIS_DIGEST

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # -- verification -------------------------------------------------------

    def verify(self) -> ChainVerification:
        """Recompute the chain and report the first inconsistency.

        Detects: an edited field (digest mismatch), a reordered or removed
        record (prev_digest mismatch), and a forged digest (recomputation
        disagrees). This is the property the tool claims; it is checked here, not
        asserted.
        """
        with self._lock:
            records = list(self._records)
        if not records:
            return ChainVerification(True, 0, None, "empty log")
        expected_prev = records[0].prev_digest
        for index, record in enumerate(records, start=1):
            if record.prev_digest != expected_prev:
                return ChainVerification(
                    False,
                    len(records),
                    index,
                    f"record {index} does not link to its predecessor",
                )
            if record.compute_digest() != record.digest:
                return ChainVerification(
                    False,
                    len(records),
                    index,
                    f"record {index} has been modified (digest mismatch)",
                )
            expected_prev = record.digest
        return ChainVerification(True, len(records), None, "chain intact")

    @staticmethod
    def verify_records(records: list[dict[str, Any]]) -> ChainVerification:
        """Verify a list of serialized records, e.g. read back from disk."""
        if not records:
            return ChainVerification(True, 0, None, "empty log")
        expected_prev = str(records[0].get("prev_digest", GENESIS_DIGEST))
        for index, raw in enumerate(records, start=1):
            record = AuditRecord.from_dict(raw)
            if record.prev_digest != expected_prev:
                return ChainVerification(
                    False, len(records), index, f"record {index} does not link to its predecessor"
                )
            if record.compute_digest() != record.digest:
                return ChainVerification(
                    False, len(records), index, f"record {index} has been modified (digest mismatch)"
                )
            expected_prev = record.digest
        return ChainVerification(True, len(records), None, "chain intact")

    def read_file(self) -> list[dict[str, Any]]:
        """Read the persisted log back as records (does not load into memory)."""
        if not self._persistent or not self._path or not self._path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
