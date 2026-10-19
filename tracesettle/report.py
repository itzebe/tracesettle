"""Structured investigation report generation (JSON + Markdown).

The report is derived entirely from the investigation's evidence and the engine's
result. It never invents data, never includes credentials, and always states the
read-only limitation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from . import DISCLAIMER, __version__
from .investigation import Investigation
from .model import (
    EvidenceItem,
    ReconciliationResult,
    StageState,
    Verification,
)

SUPPORTED_PATH = "NEAR Intents 1Click swap, ORIGIN_CHAIN deposit, EVM origin -> EVM destination"


@dataclass(frozen=True)
class Report:
    investigation_id: str
    created_at: str
    identifier: str
    identifier_type: str
    supported_path: str
    result: ReconciliationResult
    evidence: tuple[EvidenceItem, ...]
    source_reports: tuple[dict[str, Any], ...]
    notes: tuple[str, ...]
    known_limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "TRACESETTLE", "version": __version__, "read_only": True},
            "disclaimer": DISCLAIMER,
            "investigation_id": self.investigation_id,
            "created_at": self.created_at,
            "input": {"identifier": self.identifier, "identifier_type": self.identifier_type},
            "supported_path": self.supported_path,
            "outcome": self.result.outcome.value,
            "summary": self.result.summary,
            "last_confirmed_stage": (
                self.result.last_confirmed_stage.value if self.result.last_confirmed_stage else None
            ),
            "stages": [s.to_dict() for s in self.result.stages],
            "confirmed_stages": [s.stage.value for s in self.result.stages if s.state is StageState.CONFIRMED],
            "reported_unverified_stages": [
                s.stage.value for s in self.result.stages if s.state is StageState.REPORTED
            ],
            "missing_evidence_stages": [
                s.stage.value
                for s in self.result.stages
                if s.state in {StageState.MISSING, StageState.UNAVAILABLE, StageState.UNKNOWN}
            ],
            "contradictions": [c.to_dict() for c in self.result.contradictions],
            "outstanding_questions": list(self.result.unresolved_questions),
            "safety_invariants": self.result.safety,
            "source_statuses": self.result.source_statuses,
            "sources": list(self.source_reports),
            "evidence": [e.to_dict() for e in self.evidence],
            "notes": list(self.notes),
            "known_limitations": list(self.known_limitations),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_markdown(self) -> str:
        d = self.to_dict()
        lines: list[str] = []
        add = lines.append

        add(f"# TRACESETTLE investigation report `{self.investigation_id}`")
        add("")
        add(f"> {DISCLAIMER}")
        add("")
        add("## Input")
        add("")
        add(f"- **Identifier:** `{self.identifier}`")
        add(f"- **Identifier type:** {self.identifier_type}")
        add(f"- **Investigation time:** {self.created_at}")
        add(f"- **Supported path:** {SUPPORTED_PATH}")
        add("")
        add("## Outcome")
        add("")
        add(f"- **Result:** `{d['outcome']}`")
        add(f"- **Last confirmed stage:** `{d['last_confirmed_stage'] or 'none'}`")
        add(f"- **Summary:** {d['summary']}")
        add("")

        add("## Stages")
        add("")
        add("| Stage | State | Explanation |")
        add("| --- | --- | --- |")
        for s in self.result.stages:
            add(f"| {s.stage.value} | {s.state.value} | {s.summary} |")
        add("")

        add("## Contradictions")
        add("")
        if self.result.contradictions:
            for c in self.result.contradictions:
                add(f"- {c.description} (evidence: {', '.join(c.evidence_ids)})")
        else:
            add("- None detected.")
        add("")

        add("## Outstanding questions")
        add("")
        if self.result.unresolved_questions:
            for q in self.result.unresolved_questions:
                add(f"- {q}")
        else:
            add("- None.")
        add("")

        add("## Source availability")
        add("")
        add("| Source | Status | Detail |")
        add("| --- | --- | --- |")
        for report in self.source_reports:
            add(f"| {report['source']} | {report['status']} | {report.get('message') or ''} |")
        add("")

        add("## Evidence")
        add("")
        if self.evidence:
            add("| ID | Stage | Event | Source | Class | Status | Hash | Timestamp | URL |")
            add("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            for e in self.evidence:
                url = e.evidence_url or ""
                if url:
                    url = f"[link]({url})"
                add(
                    f"| `{e.id}` | {e.stage.value} | {e.event_type.value} | {e.source} | "
                    f"{e.verification.value} | {e.reported_status or ''} | "
                    f"`{e.tx_hash or ''}` | {e.timestamp or ''} | {url} |"
                )
        else:
            add("No evidence items were collected.")
        add("")

        limitations = [lim for e in self.evidence for lim in e.limitations]
        if self.notes or limitations:
            add("## Notes and evidence limitations")
            add("")
            for note in self.notes:
                add(f"- {note}")
            seen: set[str] = set()
            for lim in limitations:
                if lim not in seen:
                    seen.add(lim)
                    add(f"- {lim}")
            add("")

        if self.known_limitations:
            add("## Known limitations of this tool")
            add("")
            for lim in self.known_limitations:
                add(f"- {lim}")
            add("")

        add("## Safety invariants honoured by this report")
        add("")
        for name, ok in self.result.safety.items():
            add(f"- {'PASS' if ok else 'VIOLATED'} — `{name}`")
        add("")
        return "\n".join(lines)


#: Limitations that always apply to this tool, stated plainly.
TOOL_LIMITATIONS: tuple[str, ...] = (
    "TRACESETTLE is read-only. It cannot recover, reverse, freeze, or move funds.",
    "It never requests, stores, or uses private keys or seed phrases, and it never signs or submits transactions.",
    "1Click status is a service statement; it is reported, not independently verified.",
    "The 1Click status endpoint is keyed on the deposit address. There is no reverse lookup from an intent hash or transaction hash.",
    "Only chains with a configured public RPC can be independently verified; others are reported as unavailable, never as failed.",
    "A missing record, a 404, or an empty explorer URL is not evidence that a transaction failed.",
    "A reported failure is not proof that funds were lost, and a reported refund of zero is not proof that no refund can occur.",
    "Amount and timestamp similarity are never used to correlate transactions.",
    "Simulated test evidence is always labelled and must not be read as a live finding.",
)


def _investigation_id(identifier: str, evidence: tuple[EvidenceItem, ...]) -> str:
    """Deterministic, non-reversible short id derived from the investigation inputs."""
    digest = hashlib.sha256()
    digest.update(identifier.encode("utf-8"))
    for item in sorted(evidence, key=lambda e: e.id):
        digest.update(item.id.encode("utf-8"))
        if item.tx_hash:
            digest.update(item.tx_hash.encode("utf-8"))
    return "ts-" + digest.hexdigest()[:16]


def build_report(
    inv: Investigation,
    result: ReconciliationResult,
    created_at: str,
) -> Report:
    evidence = tuple(sorted(inv.evidence, key=lambda e: e.id))
    return Report(
        investigation_id=_investigation_id(inv.identifier, evidence),
        created_at=created_at,
        identifier=inv.identifier,
        identifier_type=inv.identifier_type.value,
        supported_path=SUPPORTED_PATH,
        result=result,
        evidence=evidence,
        source_reports=tuple(r.to_dict() for r in inv.source_reports),
        notes=tuple(inv.notes),
        known_limitations=TOOL_LIMITATIONS,
    )


def summarize_evidence(evidence: tuple[EvidenceItem, ...]) -> dict[str, int]:
    """Count evidence by classification — handy for tests and the UI header."""
    counts: dict[str, int] = {v.value: 0 for v in Verification}
    for item in evidence:
        counts[item.verification.value] += 1
    return counts
