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
from .near.settlement import (
    NearSettlementAssurance,
    provider_claims_success_from_evidence,
    settlement_assurance_from_result,
)

SUPPORTED_PATH = (
    "NEAR Intents 1Click swap, ORIGIN_CHAIN deposit, "
    "EVM origin (EVM destination) and Bitcoin origin (BTC refund verification; "
    "confirmed only when the payout is unambiguous)"
)


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
    #: The NEAR settlement assurance view over the same result. This is the
    #: product-level answer to "did the money arrive, and is that independently
    #: proven?" — it never raises the assurance level from a provider claim, so
    #: a provider SUCCESS with no decisive evidence is reported as not VERIFIED.
    settlement_assurance: NearSettlementAssurance | None = None

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
            "settlement_assurance": (
                self.settlement_assurance.to_dict() if self.settlement_assurance else None
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
            "unknown_stages": [
                s.stage.value for s in self.result.stages if s.state is StageState.UNKNOWN
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

        assurance = d.get("settlement_assurance")
        if assurance:
            add("## Settlement assurance")
            add("")
            add(f"- **Assurance level:** `{assurance['level']}`")
            add(
                "- **Independently verified:** "
                f"{'yes' if assurance['independently_verified'] else 'no'}"
            )
            add(
                "- **Provider claimed success:** "
                f"{'yes' if assurance['provider_claimed_success'] else 'no'}"
            )
            if assurance.get("partial_settlement"):
                add("- **Partial settlement:** yes — an earlier stage is confirmed but delivery is not.")
            add(f"- **Reading:** {assurance['summary']}")
            add("")
            add("| Settlement stage | Engine stage | State | Confirmed | Detail |")
            add("| --- | --- | --- | --- | --- |")
            for s in assurance["stages"]:
                add(
                    f"| {s['name']} | {s['stage']} | {s['state']} | "
                    f"{'yes' if s['confirmed'] else 'no'} | {s['detail']} |"
                )
            add("")
            if assurance.get("conflicting_evidence"):
                add("Conflicting evidence:")
                add("")
                for c in assurance["conflicting_evidence"]:
                    add(f"- {c}")
                add("")
            if assurance.get("limitations"):
                add("Assurance limitations:")
                add("")
                for lim in assurance["limitations"]:
                    add(f"- {lim}")
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
        add(
            "Class meanings: `CONFIRMED` = supported by the required authoritative "
            "evidence; `REPORTED` = stated by an upstream service, not independently "
            "checked; `MISSING` = expected evidence not obtained; `UNAVAILABLE` = the "
            "required source could not be queried; `INCOMPLETE` = the source answered "
            "but a required search could not be completed, so the evidence is "
            "insufficient; `CONTRADICTORY` = independently obtained evidence conflicts; "
            "`SIMULATED` = controlled test evidence, not a live finding."
        )
        add("")
        if self.evidence:
            add("| ID | Stage | Event | Source | Class | Method | Status | Hash | Timestamp | URL |")
            add("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            for e in self.evidence:
                url = e.evidence_url or ""
                if url:
                    url = f"[link]({url})"
                add(
                    f"| `{e.id}` | {e.stage.value} | {e.event_type.value} | {e.source} | "
                    f"{e.verification.value} | {e.verification_method or ''} | "
                    f"{e.reported_status or ''} | "
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
    "A source's own report and the raw data it returns are checked against each other: raw transaction bytes that do not hash to the requested txid are recorded as contradictory evidence, never as a confirmation.",
    "Verifying a transaction's identity against its raw bytes proves the bytes match the identifier; it does not prove block inclusion, that the transaction is a refund, or that it belongs to the investigated intent.",
    "An incomplete search (a source answered but could not be searched exhaustively) is reported as insufficient evidence, not as proof that no payout exists.",
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
    # Derive the settlement assurance from the same deterministic result, so the
    # report answers the mission's central question explicitly: did the money
    # arrive, and is that independently proven rather than merely reported? A
    # provider success claim is read from the collected evidence and never raises
    # the level on its own.
    assurance = settlement_assurance_from_result(
        result, provider_reported_success=provider_claims_success_from_evidence(inv.evidence)
    )
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
        settlement_assurance=assurance,
    )


def summarize_evidence(evidence: tuple[EvidenceItem, ...]) -> dict[str, int]:
    """Count evidence by classification — handy for tests and the UI header."""
    counts: dict[str, int] = {v.value: 0 for v in Verification}
    for item in evidence:
        counts[item.verification.value] += 1
    return counts
