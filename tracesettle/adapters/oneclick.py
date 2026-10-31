"""1Click Swap API — swap status adapter.

Verified endpoint (Phase 1):

    GET https://1click.chaindefuser.com/v0/status?depositAddress=<addr>

Key facts that shape this adapter:

* The lookup key is the quote **deposit address**, not an arbitrary hash.
* It answered with no auth header in Phase 1, but the OpenAPI marks it as
  requiring ``X-API-Key`` or ``JWT-auth``. Authentication may therefore become
  mandatory. If it does, we report the source as UNAVAILABLE and explain the
  limitation — we never bypass auth and never substitute fabricated data.
* ``404`` means "no record for this deposit address" and is **not** evidence that
  the swap failed.
* Amount fields may be ``null`` and ``explorerUrl`` may be an empty string even
  on a fully settled swap. Both are handled without crashing and without drawing
  conclusions.

Status vocabulary (1Click only — do not merge with the solver relay's):

    PENDING_DEPOSIT, KNOWN_DEPOSIT_TX, INCOMPLETE_DEPOSIT,
    PROCESSING, SUCCESS, REFUNDED, FAILED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

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

SOURCE = "oneclick_status"

#: Statuses that mean "the swap is still progressing", not "it failed".
IN_FLIGHT_STATUSES = frozenset({"PENDING_DEPOSIT", "KNOWN_DEPOSIT_TX", "PROCESSING"})
KNOWN_STATUSES = frozenset(
    {
        "PENDING_DEPOSIT",
        "KNOWN_DEPOSIT_TX",
        "INCOMPLETE_DEPOSIT",
        "PROCESSING",
        "SUCCESS",
        "REFUNDED",
        "FAILED",
    }
)


@dataclass
class OneClickStatusData:
    """Structured view of a 1Click status record, for orchestration only."""

    found: bool
    status: str | None = None
    deposit_address: str | None = None
    correlation_id: str | None = None
    updated_at: str | None = None
    quote_timestamp: str | None = None
    swap_details: dict[str, Any] = field(default_factory=dict)
    quote_request: dict[str, Any] = field(default_factory=dict)
    quote: dict[str, Any] = field(default_factory=dict)

    @property
    def intent_hashes(self) -> list[str]:
        return _str_list(self.swap_details.get("intentHashes"))

    @property
    def near_tx_hashes(self) -> list[str]:
        return _str_list(self.swap_details.get("nearTxHashes"))

    @property
    def origin_chain_tx_hashes(self) -> list[str]:
        return _hash_list(self.swap_details.get("originChainTxHashes"))

    @property
    def destination_chain_tx_hashes(self) -> list[str]:
        return _hash_list(self.swap_details.get("destinationChainTxHashes"))

    @property
    def origin_asset(self) -> str | None:
        return self.quote_request.get("originAsset")

    @property
    def destination_asset(self) -> str | None:
        return self.quote_request.get("destinationAsset")

    @property
    def recipient(self) -> str | None:
        value = self.quote_request.get("recipient")
        return value if isinstance(value, str) else None

    @property
    def refund_to(self) -> str | None:
        value = self.quote_request.get("refundTo")
        return value if isinstance(value, str) else None

    @property
    def deposit_type(self) -> str | None:
        value = self.quote_request.get("depositType")
        return value if isinstance(value, str) else None

    @property
    def recipient_type(self) -> str | None:
        value = self.quote_request.get("recipientType")
        return value if isinstance(value, str) else None

    @property
    def refunded_amount(self) -> str | None:
        value = self.swap_details.get("refundedAmount")
        return value if isinstance(value, str) else None

    @property
    def refund_reason(self) -> str | None:
        value = self.swap_details.get("refundReason")
        return value if isinstance(value, str) else None

    @property
    def deposited_amount(self) -> str | None:
        value = self.swap_details.get("depositedAmount")
        return value if isinstance(value, str) else None


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _hash_list(value: Any) -> list[str]:
    """Extract hashes from ``[{hash, explorerUrl}]`` without trusting the shape."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for entry in value:
        if isinstance(entry, dict):
            h = entry.get("hash")
            if isinstance(h, str) and h:
                out.append(h)
        elif isinstance(entry, str) and entry:
            out.append(entry)
    return out


def build_status_url(deposit_address: str) -> str:
    """Build the 1Click status URL for a deposit address.

    The address is percent-encoded with :func:`urllib.parse.urlencode` so that
    characters such as ``&``, ``=``, ``?``, spaces, and non-ASCII input stay part
    of the single ``depositAddress`` parameter instead of being interpreted as
    query syntax. The value is not altered; only its transport encoding is.
    """
    query = urlencode({"depositAddress": deposit_address})
    return f"{config.ONECLICK_BASE}{config.ONECLICK_STATUS_PATH}?{query}"


def investigate(
    deposit_address: str, client: HttpClient
) -> tuple[SourceReport, OneClickStatusData | None]:
    """Query 1Click status for a deposit address.

    Returns the source report (health + evidence) and, on success, the parsed
    status data for orchestration.
    """
    endpoint = build_status_url(deposit_address)
    result = client.get_json(
        f"{config.ONECLICK_BASE}{config.ONECLICK_STATUS_PATH}",
        params={"depositAddress": deposit_address},
    )

    if result.status is SourceStatus.NOT_FOUND:
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.NOT_FOUND,
                message=(
                    "No 1Click record exists for this deposit address. This means no record "
                    "was found; it is not evidence that the swap failed."
                ),
                endpoint=endpoint,
            ),
            None,
        )

    if result.status is SourceStatus.UNAUTHORIZED:
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.UNAUTHORIZED,
                message=(
                    "The 1Click status endpoint rejected the request (HTTP 401/403). "
                    "Authentication may have become mandatory. This source is unavailable; "
                    "no conclusion about the transaction can be drawn from it."
                ),
                endpoint=endpoint,
            ),
            None,
        )

    if not result.ok:
        return (
            SourceReport(
                source=SOURCE,
                status=result.status,
                message=result.message or "1Click status could not be retrieved.",
                endpoint=endpoint,
            ),
            None,
        )

    data = result.data
    if not isinstance(data, dict) or not isinstance(data.get("status"), str):
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.MALFORMED,
                message=(
                    "The 1Click status response did not match the expected schema "
                    "(missing 'status'). The response was ignored."
                ),
                endpoint=endpoint,
            ),
            None,
        )

    status = data["status"]
    swap_details = data.get("swapDetails") if isinstance(data.get("swapDetails"), dict) else {}
    quote_response = data.get("quoteResponse") if isinstance(data.get("quoteResponse"), dict) else {}
    quote_request = (
        quote_response.get("quoteRequest") if isinstance(quote_response.get("quoteRequest"), dict) else {}
    )
    quote = quote_response.get("quote") if isinstance(quote_response.get("quote"), dict) else {}

    parsed = OneClickStatusData(
        found=True,
        status=status,
        deposit_address=(
            quote.get("depositAddress")
            if isinstance(quote.get("depositAddress"), str)
            else deposit_address
        ),
        correlation_id=data.get("correlationId") if isinstance(data.get("correlationId"), str) else None,
        updated_at=data.get("updatedAt") if isinstance(data.get("updatedAt"), str) else None,
        quote_timestamp=(
            quote_response.get("timestamp") if isinstance(quote_response.get("timestamp"), str) else None
        ),
        swap_details=swap_details,
        quote_request=quote_request,
        quote=quote,
    )

    evidence = _build_evidence(parsed, endpoint)

    limitations: list[str] = []
    if status not in KNOWN_STATUSES:
        limitations.append(
            f"Unrecognised 1Click status '{status}'; treated as reported and unclassified."
        )
    message = f"1Click reported status '{status}'."
    if limitations:
        message += " " + " ".join(limitations)

    return (
        SourceReport(
            source=SOURCE,
            status=SourceStatus.OK,
            evidence=tuple(evidence),
            message=message,
            endpoint=endpoint,
        ),
        parsed,
    )


def _build_evidence(data: OneClickStatusData, endpoint: str) -> list[EvidenceItem]:
    """All 1Click evidence is REPORTED: an upstream service's own statement."""
    items: list[EvidenceItem] = []
    url = f"{config.EXPLORER_TX_BASE}/{data.deposit_address}" if data.deposit_address else None

    items.append(
        EvidenceItem(
            id="ev-oneclick-status",
            stage=_stage_for_status(data.status),
            event_type=EventType.UPSTREAM_STATUS,
            source=SOURCE,
            verification=Verification.REPORTED,
            provenance=Provenance.REAL,
            verification_method="1Click /v0/status provider report",
            source_record_id=data.correlation_id,
            reported_status=data.status,
            timestamp=data.updated_at,
            evidence_url=url,
            details={
                "deposit_address": data.deposit_address,
                "quote_timestamp": data.quote_timestamp,
                "origin_asset": data.origin_asset,
                "destination_asset": data.destination_asset,
                "deposit_type": data.deposit_type,
                "recipient_type": data.recipient_type,
                "intent_hashes": data.intent_hashes,
                "near_tx_hashes": data.near_tx_hashes,
                "origin_chain_tx_hashes": data.origin_chain_tx_hashes,
                "destination_chain_tx_hashes": data.destination_chain_tx_hashes,
            },
            limitations=("Upstream service statement; not independently verified by TRACESETTLE.",),
        )
    )

    if data.deposited_amount is not None:
        items.append(
            EvidenceItem(
                id="ev-oneclick-deposit",
                stage=Stage.BRIDGE_DEPOSIT_CREDIT,
                event_type=EventType.DEPOSIT_OBSERVED,
                source=SOURCE,
                verification=Verification.REPORTED,
                provenance=Provenance.REAL,
                verification_method="1Click /v0/status provider report",
                source_record_id=data.correlation_id,
                reported_status=data.status,
                timestamp=data.updated_at,
                evidence_url=url,
                details={
                    "deposited_amount": data.deposited_amount,
                    "deposited_amount_formatted": data.swap_details.get("depositedAmountFormatted"),
                    "deposited_amount_usd": data.swap_details.get("depositedAmountUsd"),
                },
                limitations=("Reported by 1Click; not independently verified.",),
            )
        )

    if data.status in {"SUCCESS", "PROCESSING"} and data.intent_hashes:
        items.append(
            EvidenceItem(
                id="ev-oneclick-settlement-claim",
                stage=Stage.NEAR_SETTLEMENT,
                event_type=EventType.SETTLEMENT_CLAIMED,
                source=SOURCE,
                verification=Verification.REPORTED,
                provenance=Provenance.REAL,
                verification_method="1Click /v0/status provider report",
                source_record_id=data.correlation_id,
                tx_hash=data.near_tx_hashes[0] if data.near_tx_hashes else None,
                reported_status=data.status,
                timestamp=data.updated_at,
                evidence_url=url,
                details={
                    "intent_hashes": data.intent_hashes,
                    "near_tx_hashes": data.near_tx_hashes,
                    "amount_out": data.swap_details.get("amountOut"),
                    "amount_out_formatted": data.swap_details.get("amountOutFormatted"),
                },
                limitations=("1Click reports settlement; this is not on-chain proof by itself.",),
            )
        )

    refund_amount = data.refunded_amount
    if data.status == "REFUNDED" or _is_positive_decimal(refund_amount):
        items.append(
            EvidenceItem(
                id="ev-oneclick-refund-claim",
                stage=Stage.REFUND,
                event_type=EventType.REFUND_CLAIMED,
                source=SOURCE,
                verification=Verification.REPORTED,
                provenance=Provenance.REAL,
                verification_method="1Click /v0/status provider report",
                source_record_id=data.correlation_id,
                reported_status=data.status,
                timestamp=data.updated_at,
                evidence_url=url,
                details={
                    "refunded_amount": refund_amount,
                    "refunded_amount_formatted": data.swap_details.get("refundedAmountFormatted"),
                    "refund_reason": data.refund_reason,
                    "refund_to": data.refund_to,
                },
                limitations=(
                    "A reported refund is not independently confirmed without the refund transaction.",
                ),
            )
        )

    if data.status in {"FAILED", "INCOMPLETE_DEPOSIT"}:
        items.append(
            EvidenceItem(
                id="ev-oneclick-failure-claim",
                stage=Stage.NEAR_SETTLEMENT,
                event_type=EventType.UPSTREAM_STATUS,
                source=SOURCE,
                verification=Verification.REPORTED,
                provenance=Provenance.REAL,
                verification_method="1Click /v0/status provider report",
                source_record_id=data.correlation_id,
                reported_status=data.status,
                timestamp=data.updated_at,
                evidence_url=url,
                details={
                    "status": data.status,
                    "status_details": data.swap_details.get("refundReason"),
                },
                limitations=("A reported failure is not proof that funds were lost.",),
            )
        )
    return items


def _stage_for_status(status: str | None) -> Stage:
    if status == "REFUNDED":
        return Stage.REFUND
    if status in {"PENDING_DEPOSIT", "KNOWN_DEPOSIT_TX", "INCOMPLETE_DEPOSIT"}:
        return Stage.SOURCE_CHAIN_DEPOSIT
    return Stage.NEAR_SETTLEMENT


def _is_positive_decimal(value: str | None) -> bool:
    if not value:
        return False
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False
