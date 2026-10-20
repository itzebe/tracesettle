"""Solver relay adapter — ``get_status``.

Verified in Phase 1:

    POST https://solver-relay-v2.chaindefuser.com/rpc
    {"jsonrpc":"2.0","id":1,"method":"get_status","params":[{"intent_hash":"..."}]}

Returns, e.g.::

    {"result":{"intent_hash":"...","status":"SETTLED",
               "data":{"hash":"<near tx hash>"},
               "filled_amounts":{...}}}

Its status vocabulary is **deliberately kept separate** from 1Click's:

    PENDING, TX_BROADCASTED, SETTLED, NOT_FOUND_OR_NOT_VALID

``NOT_FOUND_OR_NOT_VALID`` is not a failure verdict: the relay simply has no
record. It is reported as such and never mapped onto a 1Click status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import config
from ..httpclient import HttpClient
from ..model import (
    EventType,
    EvidenceItem,
    Provenance,
    SourceReport,
    SourceStatus,
    Stage,
    Verification,
)

SOURCE = "solver_relay"
METHOD = "get_status"

KNOWN_STATUSES = frozenset({"PENDING", "TX_BROADCASTED", "SETTLED", "NOT_FOUND_OR_NOT_VALID"})


@dataclass
class SolverRelayData:
    intent_hash: str
    status: str | None = None
    status_details: str | None = None
    near_tx_hash: str | None = None
    filled_amounts: dict[str, str] = field(default_factory=dict)


def _is_valid_intent_hash(value: Any) -> bool:
    """Validate the returned intent hash before using it for correlation."""
    if not isinstance(value, str) or not value:
        return False
    if len(value) > 128:
        return False
    return all(c.isalnum() or c in "-_" for c in value)


def investigate(
    intent_hash: str, client: HttpClient
) -> tuple[SourceReport, SolverRelayData | None]:
    endpoint = config.SOLVER_RELAY_URL
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": METHOD,
        "params": [{"intent_hash": intent_hash}],
    }
    result = client.post_json(endpoint, payload)

    if not result.ok:
        return (
            SourceReport(
                source=SOURCE,
                status=result.status,
                message=result.message or "Solver relay could not be queried.",
                endpoint=endpoint,
            ),
            None,
        )

    body = result.data
    if not isinstance(body, dict):
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.MALFORMED,
                message="Solver relay returned a non-object response.",
                endpoint=endpoint,
            ),
            None,
        )

    inner = body.get("result")
    if not isinstance(inner, dict):
        # A JSON-RPC error object is a well-formed response, not a transaction state.
        error = body.get("error")
        message = "Solver relay returned an error response."
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            message = f"Solver relay error: {error['message']}"
        return (
            SourceReport(source=SOURCE, status=SourceStatus.MALFORMED, message=message, endpoint=endpoint),
            None,
        )

    returned_hash = inner.get("intent_hash")
    if not _is_valid_intent_hash(returned_hash):
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.MALFORMED,
                message="Solver relay response did not include a valid intent hash; ignored.",
                endpoint=endpoint,
            ),
            None,
        )
    if returned_hash != intent_hash:
        # Correlation must be exact; a mismatched hash is not usable evidence.
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.MALFORMED,
                message=(
                    "Solver relay returned a different intent hash than requested; "
                    "the response was ignored to avoid mis-correlation."
                ),
                endpoint=endpoint,
            ),
            None,
        )

    status = inner.get("status") if isinstance(inner.get("status"), str) else None
    data_obj = inner.get("data") if isinstance(inner.get("data"), dict) else {}
    near_tx_hash = data_obj.get("hash") if isinstance(data_obj.get("hash"), str) else None

    filled_raw = inner.get("filled_amounts")
    filled: dict[str, str] = {}
    if isinstance(filled_raw, dict):
        filled = {k: v for k, v in filled_raw.items() if isinstance(k, str) and isinstance(v, str)}

    parsed = SolverRelayData(
        intent_hash=returned_hash,
        status=status,
        status_details=inner.get("status_details") if isinstance(inner.get("status_details"), str) else None,
        near_tx_hash=near_tx_hash,
        filled_amounts=filled,
    )

    evidence = _build_evidence(parsed, endpoint)
    return (
        SourceReport(
            source=SOURCE,
            status=SourceStatus.OK,
            evidence=tuple(evidence),
            message=f"Solver relay reported '{status}' for intent {returned_hash}.",
            endpoint=endpoint,
        ),
        parsed,
    )


def _build_evidence(data: SolverRelayData, endpoint: str) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    items.append(
        EvidenceItem(
            id="ev-solver-relay-status",
            stage=Stage.NEAR_SETTLEMENT,
            event_type=EventType.SETTLEMENT_CLAIMED,
            source=SOURCE,
            verification=Verification.REPORTED,
            provenance=Provenance.REAL,
            verification_method="solver relay intent-status query",
            source_record_id=data.intent_hash,
            tx_hash=data.near_tx_hash,
            reported_status=data.status,
            evidence_url=endpoint,
            details={
                "intent_hash": data.intent_hash,
                "status_details": data.status_details,
                "filled_amounts": data.filled_amounts,
                "status_vocabulary": "solver_relay",
            },
            limitations=(
                "Solver relay statement; not on-chain proof by itself.",
                "Status vocabulary differs from 1Click and must not be equated without a mapping rule.",
            ),
        )
    )
    if data.status == "NOT_FOUND_OR_NOT_VALID":
        items.append(
            EvidenceItem(
                id="ev-solver-relay-notfound",
                stage=Stage.NEAR_SETTLEMENT,
                event_type=EventType.SOURCE_ISSUE,
                source=SOURCE,
                verification=Verification.REPORTED,
                provenance=Provenance.REAL,
                verification_method="solver relay intent-status query",
                source_record_id=data.intent_hash,
                reported_status=data.status,
                evidence_url=endpoint,
                details={"status_details": data.status_details},
                limitations=(
                    "The relay has no record of this intent. This is not proof that the "
                    "intent failed or that funds were lost.",
                ),
            )
        )
    return items
