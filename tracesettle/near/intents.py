"""Live client for the documented 1Click (NEAR Intents) swap lifecycle.

This module implements the *public, unauthenticated* 1Click endpoints that the
official reference documents, and nothing else. It does not invent an endpoint,
a field, or a status value:

* ``GET  /v0/tokens``          — supported assets (``api-reference_oneclick_get-supported-tokens.md``)
* ``POST /v0/quote``           — request a swap quote (``api-reference_oneclick_request-a-swap-quote.md``)
* ``POST /v0/deposit/submit``  — optional deposit-hash notification (``api-reference_oneclick_submit-deposit-transaction-hash.md``)
* ``GET  /v0/status``          — lifecycle status keyed on the deposit address
  (``api-reference_oneclick_check-swap-execution-status.md``); parsed by
  :mod:`tracesettle.adapters.oneclick`, which already owns that schema.

Protocol version recorded: the vendored OpenAPI documents are
``info.version: 0.1.10``. The status lifecycle enum is exactly
``KNOWN_DEPOSIT_TX``, ``PENDING_DEPOSIT``, ``INCOMPLETE_DEPOSIT``,
``PROCESSING``, ``SUCCESS``, ``REFUNDED``, ``FAILED``.

Honest boundaries, repeated because they are the point:

* Nothing here signs, broadcasts, or moves funds. A live (``dry: false``) quote
  returns a **deposit address**; funding it requires the user's own wallet,
  which this module never touches and never asks a key for.
* A request that fails is reported as a failure with its source status; it is
  never silently turned into an empty success. A provider ``SUCCESS`` is a
  *reported* claim and is never treated as independent settlement proof — that
  decision belongs to the deterministic engine in :mod:`tracesettle.reconcile`.
* Validation happens before the call so a malformed request is refused locally,
  rather than sent to the provider.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from decimal import Decimal as _Decimal
from typing import Any

from .. import config
from ..httpclient import HttpClient
from ..model import SourceStatus

#: The documented deposit/recipient/refund type enums.
DEPOSIT_TYPES = ("ORIGIN_CHAIN", "INTENTS", "CONFIDENTIAL_INTENTS")
RECIPIENT_TYPES = ("DESTINATION_CHAIN", "INTENTS", "CONFIDENTIAL_INTENTS")
REFUND_TYPES = ("ORIGIN_CHAIN", "INTENTS", "CONFIDENTIAL_INTENTS")
SWAP_TYPES = ("EXACT_INPUT", "EXACT_OUTPUT", "FLEX_INPUT", "ANY_INPUT")

#: The documented status lifecycle. Used to reject an unrecognised status rather
#: than guess at it. The set is exactly the seven statuses the official status
#: table defines; order is not significant.
LIFECYCLE_STATUSES = (
    "KNOWN_DEPOSIT_TX",
    "PENDING_DEPOSIT",
    "INCOMPLETE_DEPOSIT",
    "PROCESSING",
    "SUCCESS",
    "REFUNDED",
    "FAILED",
)

#: Human-facing lifecycle phrases the mission asks the UI to distinguish. Each
#: maps to one or more provider statuses plus local evidence; the mapping is
#: explicit so the UI cannot show a state the evidence does not support.
LIFECYCLE_LABELS: dict[str, str] = {
    "QUOTE_CREATED": "Quote created",
    "AUTHORIZATION_REQUIRED": "Authorization required",
    "AUTHORIZATION_GRANTED": "Authorization granted",
    "DEPOSIT_ADDRESS_ISSUED": "Deposit address issued",
    "AWAITING_DEPOSIT": "Awaiting your deposit",
    "DEPOSIT_SUBMITTED": "Deposit submitted",
    "DEPOSIT_DETECTED": "Deposit detected",
    "DEPOSIT_INCOMPLETE": "Deposit below required amount",
    "EXECUTION_PENDING": "Execution pending",
    "DESTINATION_OBSERVED": "Destination transaction observed",
    "SETTLEMENT_VERIFIED": "Settlement independently verified",
    "REFUND_DETECTED": "Refund detected",
    "PARTIAL_SETTLEMENT": "Partial settlement",
    "FAILED": "Failed transaction",
    "UNKNOWN_STATUS": "Unknown status",
    "PROVIDER_UNAVAILABLE": "Provider unavailable",
}

_INTEGER_RE = re.compile(r"^[0-9]+$")

#: Decimals for the common assets, used only to convert a provider base-unit
#: amount into the human-unit amount the guard policy is written in. An unknown
#: symbol with no explicit ``asset_decimals`` is a validation error, never a
#: guess: mis-scaling an amount would corrupt every downstream limit check.
ASSET_DECIMALS: dict[str, int] = {
    "USDC": 6,
    "USDT": 6,
    "USDC.E": 6,
    "DAI": 18,
    "ETH": 18,
    "WETH": 18,
    "NEAR": 24,
    "WBTC": 8,
    "BTC": 8,
    "SOL": 9,
}


class QuoteValidationError(ValueError):
    """A quote request was rejected locally, before any network call."""


def _require_choice(value: Any, field_name: str, choices: tuple[str, ...]) -> str:
    text = str(value or "").strip().upper()
    if text not in choices:
        raise QuoteValidationError(
            f"field '{field_name}' must be one of {', '.join(choices)}"
        )
    return text


def _require_text(value: Any, field_name: str, *, max_chars: int = 200) -> str:
    if not isinstance(value, str):
        raise QuoteValidationError(f"field '{field_name}' must be a string")
    text = value.strip()
    if not text:
        raise QuoteValidationError(f"field '{field_name}' must not be empty")
    if len(text) > max_chars:
        raise QuoteValidationError(f"field '{field_name}' exceeds {max_chars} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise QuoteValidationError(f"field '{field_name}' contains control characters")
    return text


@dataclass(frozen=True)
class QuoteRequest:
    """A validated ``POST /v0/quote`` request.

    Field names and semantics follow the official OpenAPI schema exactly. The
    only field this class adds is a convenience default for ``deadline``: when
    omitted, it is set one hour in the future, because the endpoint requires a
    future timestamp that exceeds the deposit's mining time.
    """

    origin_asset: str
    destination_asset: str
    amount: str
    recipient: str
    refund_to: str
    swap_type: str = "EXACT_INPUT"
    slippage_tolerance: int = 100
    deposit_type: str = "ORIGIN_CHAIN"
    recipient_type: str = "DESTINATION_CHAIN"
    refund_type: str = "ORIGIN_CHAIN"
    dry: bool = False
    deadline: str | None = None
    deposit_mode: str | None = None
    referral: str | None = None
    session_id: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any], *, default_dry: bool = False) -> "QuoteRequest":
        """Build a validated request from a client payload.

        ``amount`` must be an integer string in the asset's smallest unit, as the
        reference states ("decimal values like ``0.01`` are invalid — use base
        units"). Refusing it here keeps a mis-scaled amount from reaching the
        provider.
        """
        if not isinstance(payload, dict):
            raise QuoteValidationError("quote request must be a JSON object")
        amount = payload.get("amount")
        if not isinstance(amount, str) or not _INTEGER_RE.match(amount.strip()):
            raise QuoteValidationError(
                "field 'amount' must be an integer string in the asset's smallest unit "
                "(for example '1000000' for 1 USDC at 6 decimals); decimal values are invalid"
            )
        raw_slippage = payload.get("slippage_tolerance", payload.get("slippageTolerance", 100))
        try:
            slippage = int(raw_slippage)
        except (TypeError, ValueError) as exc:
            raise QuoteValidationError("field 'slippage_tolerance' must be an integer") from exc
        if slippage < 0 or slippage > 10000:
            raise QuoteValidationError("field 'slippage_tolerance' must be between 0 and 10000 basis points")

        deadline = payload.get("deadline")
        if deadline is not None:
            deadline = _require_text(deadline, "deadline", max_chars=40)
            if not _is_future_iso(deadline):
                raise QuoteValidationError("field 'deadline' must be an ISO-8601 timestamp in the future")

        return cls(
            origin_asset=_require_text(payload.get("origin_asset"), "origin_asset"),
            destination_asset=_require_text(payload.get("destination_asset"), "destination_asset"),
            amount=amount.strip(),
            recipient=_require_text(payload.get("recipient"), "recipient"),
            refund_to=_require_text(payload.get("refund_to"), "refund_to"),
            swap_type=_require_choice(payload.get("swap_type", "EXACT_INPUT"), "swap_type", SWAP_TYPES),
            slippage_tolerance=slippage,
            deposit_type=_require_choice(payload.get("deposit_type", "ORIGIN_CHAIN"), "deposit_type", DEPOSIT_TYPES),
            recipient_type=_require_choice(
                payload.get("recipient_type", "DESTINATION_CHAIN"), "recipient_type", RECIPIENT_TYPES
            ),
            refund_type=_require_choice(payload.get("refund_type", "ORIGIN_CHAIN"), "refund_type", REFUND_TYPES),
            dry=bool(payload.get("dry", default_dry)),
            deadline=deadline,
            deposit_mode=(
                _require_choice(payload.get("deposit_mode"), "deposit_mode", ("SIMPLE", "MEMO"))
                if payload.get("deposit_mode")
                else None
            ),
            referral=(str(payload["referral"]).strip() if payload.get("referral") else None),
            session_id=(str(payload["session_id"]).strip() if payload.get("session_id") else None),
        )

    def to_body(self) -> dict[str, Any]:
        """The exact JSON body for ``POST /v0/quote``."""
        deadline = self.deadline or (
            _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        body: dict[str, Any] = {
            "dry": self.dry,
            "swapType": self.swap_type,
            "slippageTolerance": self.slippage_tolerance,
            "originAsset": self.origin_asset,
            "depositType": self.deposit_type,
            "destinationAsset": self.destination_asset,
            "amount": self.amount,
            "refundTo": self.refund_to,
            "refundType": self.refund_type,
            "recipient": self.recipient,
            "recipientType": self.recipient_type,
            "deadline": deadline,
        }
        if self.deposit_mode:
            body["depositMode"] = self.deposit_mode
        if self.referral:
            body["referral"] = self.referral
        if self.session_id:
            body["sessionId"] = self.session_id
        return body

    def to_dict(self) -> dict[str, Any]:
        return self.to_body()


def _parse_iso(value: str | None) -> _dt.datetime | None:
    """Parse an ISO-8601 timestamp the provider may return, or ``None``."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def _is_future_iso(value: str) -> bool:
    parsed = _parse_iso(value)
    return parsed is not None and parsed > _dt.datetime.now(_dt.timezone.utc)


def quote_expiry(quote: "QuoteFields | None", *, now: _dt.datetime | None = None) -> dict[str, Any]:
    """Whether a quote is still usable, and why.

    A quote is fundable only while it is unexpired. The provider bounds that with
    ``deadline`` (and ``timeWhenInactive``); whichever it states is enforced. When
    the provider states **no** expiry, the tool does not invent one — it marks the
    quote usable but flags ``expiry_known: False`` and says so, rather than
    silently presenting an unbounded quote as definitely valid.

    Returns ``usable`` (may proceed), ``expiry_known``, ``reason`` (a stable code)
    and ``detail`` (a human sentence). Pure and deterministic for a given ``now``.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if quote is None:
        return {
            "usable": False, "expiry_known": True, "reason": "NO_QUOTE",
            "detail": "there is no quote on this intent",
        }

    stated_raw = quote.deadline or quote.time_when_inactive
    stated = _parse_iso(stated_raw)
    if stated is None:
        return {
            "usable": True, "expiry_known": False, "reason": "NO_EXPIRY_STATED",
            "detail": "the provider stated no expiry for this quote; its validity is not established",
        }
    if stated <= now:
        return {
            "usable": False, "expiry_known": True, "reason": "QUOTE_EXPIRED",
            "detail": f"the quote expired at {stated_raw}",
        }
    return {
        "usable": True, "expiry_known": True, "reason": "VALID",
        "detail": f"the quote is valid until {stated_raw}",
    }




def human_amount(base_amount: str, *, symbol: str | None, decimals: int | None) -> str:
    """Convert a base-unit amount string into a human-unit decimal string.

    ``decimals`` wins when supplied (for example from the provider's token list);
    otherwise the symbol is looked up in :data:`ASSET_DECIMALS`. An unknown
    symbol with no explicit decimals raises, because guessing a scale would
    silently corrupt every limit check downstream. The conversion is exact
    ``Decimal`` arithmetic — never a float.
    """
    if decimals is None:
        key = (symbol or "").strip().upper()
        if key not in ASSET_DECIMALS:
            raise QuoteValidationError(
                f"cannot scale the amount for asset '{symbol}': supply 'asset_decimals' or use a "
                "known symbol"
            )
        decimals = ASSET_DECIMALS[key]
    if not isinstance(base_amount, str) or not _INTEGER_RE.match(base_amount.strip()):
        raise QuoteValidationError("amount must be an integer string in the asset's smallest unit")
    if decimals < 0 or decimals > 36:
        raise QuoteValidationError("asset_decimals must be between 0 and 36")
    value = _Decimal(base_amount.strip()).scaleb(-decimals)
    # Normalize without exponent so the string is a plain decimal (e.g. "1.5").
    normalized = value.normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    blockchain: str
    symbol: str
    decimals: int
    contract_address: str | None = None
    price: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "blockchain": self.blockchain,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "contract_address": self.contract_address,
            "price": self.price,
        }


@dataclass(frozen=True)
class QuoteFields:
    """The ``quote`` object of a ``QuoteResponse``, documented fields only."""

    deposit_address: str | None
    deposit_memo: str | None
    amount_in: str | None
    amount_in_formatted: str | None
    amount_out: str | None
    amount_out_formatted: str | None
    min_amount_out: str | None
    withdraw_fee: str | None
    refund_fee: str | None
    time_estimate: int | None
    deadline: str | None
    time_when_inactive: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "deposit_address": self.deposit_address,
            "deposit_memo": self.deposit_memo,
            "amount_in": self.amount_in,
            "amount_in_formatted": self.amount_in_formatted,
            "amount_out": self.amount_out,
            "amount_out_formatted": self.amount_out_formatted,
            "min_amount_out": self.min_amount_out,
            "withdraw_fee": self.withdraw_fee,
            "refund_fee": self.refund_fee,
            "time_estimate": self.time_estimate,
            "deadline": self.deadline,
            "time_when_inactive": self.time_when_inactive,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "QuoteFields | None":
        """Rebuild the fields from a stored ``to_dict``, or ``None`` if absent."""
        if not isinstance(data, dict):
            return None
        estimate = data.get("time_estimate")
        return cls(
            deposit_address=data.get("deposit_address"),
            deposit_memo=data.get("deposit_memo"),
            amount_in=data.get("amount_in"),
            amount_in_formatted=data.get("amount_in_formatted"),
            amount_out=data.get("amount_out"),
            amount_out_formatted=data.get("amount_out_formatted"),
            min_amount_out=data.get("min_amount_out"),
            withdraw_fee=data.get("withdraw_fee"),
            refund_fee=data.get("refund_fee"),
            time_estimate=int(estimate) if isinstance(estimate, int) else None,
            deadline=data.get("deadline"),
            time_when_inactive=data.get("time_when_inactive"),
        )


@dataclass(frozen=True)
class QuoteOutcome:
    """The result of a quote request: always explicit about success or failure."""

    ok: bool
    source_status: SourceStatus
    http_status: int | None
    request: QuoteRequest | None = None
    quote: QuoteFields | None = None
    correlation_id: str | None = None
    signature: str | None = None
    message: str = ""
    endpoint: str = ""
    limitations: tuple[str, ...] = ()

    @property
    def deposit_address(self) -> str | None:
        return self.quote.deposit_address if self.quote else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "source_status": self.source_status.value,
            "http_status": self.http_status,
            "correlation_id": self.correlation_id,
            "signature_present": bool(self.signature),
            "message": self.message,
            "endpoint": self.endpoint,
            "limitations": list(self.limitations),
            "request": self.request.to_dict() if self.request else None,
            "quote": self.quote.to_dict() if self.quote else None,
        }


def fetch_tokens(client: HttpClient) -> tuple[SourceStatus, tuple[Asset, ...], str]:
    """``GET /v0/tokens`` — the supported asset list.

    Returns ``(source_status, assets, message)``. On any failure the asset tuple
    is empty and the status says why; it is never a silent empty success.
    """
    result = client.get_json(f"{config.ONECLICK_BASE}{config.ONECLICK_TOKENS_PATH}")
    if not result.ok or not isinstance(result.data, list):
        return (
            result.status,
            (),
            result.message or "the supported-token list could not be retrieved",
        )
    assets: list[Asset] = []
    for entry in result.data:
        if not isinstance(entry, dict):
            continue
        asset_id = entry.get("assetId")
        if not isinstance(asset_id, str) or not asset_id:
            continue
        try:
            decimals = int(entry.get("decimals", 0))
        except (TypeError, ValueError):
            decimals = 0
        assets.append(
            Asset(
                asset_id=asset_id,
                blockchain=str(entry.get("blockchain") or ""),
                symbol=str(entry.get("symbol") or ""),
                decimals=decimals,
                contract_address=(
                    entry.get("contractAddress") if isinstance(entry.get("contractAddress"), str) else None
                ),
                price=str(entry["price"]) if entry.get("price") is not None else None,
            )
        )
    if not assets:
        return (SourceStatus.MALFORMED, (), "the token list contained no usable entries")
    return (SourceStatus.OK, tuple(assets), f"{len(assets)} supported assets")


def request_quote(client: HttpClient, request: QuoteRequest) -> QuoteOutcome:
    """``POST /v0/quote`` — request a swap quote (and, when live, a deposit address).

    A live quote (``dry: false``) is the only way the provider issues a deposit
    address. This function never funds it; funding is the user's own wallet step.
    """
    endpoint = f"{config.ONECLICK_BASE}{config.ONECLICK_QUOTE_PATH}"
    result = client.post_json(endpoint, request.to_body())
    if not result.ok:
        return QuoteOutcome(
            ok=False,
            source_status=result.status,
            http_status=result.http_status,
            request=request,
            message=result.message or "the quote request failed",
            endpoint=endpoint,
        )
    data = result.data
    if not isinstance(data, dict) or not isinstance(data.get("quote"), dict):
        return QuoteOutcome(
            ok=False,
            source_status=SourceStatus.MALFORMED,
            http_status=result.http_status,
            request=request,
            message="the quote response did not match the documented schema (no 'quote' object)",
            endpoint=endpoint,
        )
    raw_quote = data["quote"]
    quote = QuoteFields(
        deposit_address=_opt_str(raw_quote.get("depositAddress")),
        deposit_memo=_opt_str(raw_quote.get("depositMemo")),
        amount_in=_opt_str(raw_quote.get("amountIn")),
        amount_in_formatted=_opt_str(raw_quote.get("amountInFormatted")),
        amount_out=_opt_str(raw_quote.get("amountOut")),
        amount_out_formatted=_opt_str(raw_quote.get("amountOutFormatted")),
        min_amount_out=_opt_str(raw_quote.get("minAmountOut")),
        withdraw_fee=_opt_str(raw_quote.get("withdrawFee")),
        refund_fee=_opt_str(raw_quote.get("refundFee")),
        time_estimate=(
            int(raw_quote["timeEstimate"]) if isinstance(raw_quote.get("timeEstimate"), int) else None
        ),
        deadline=_opt_str(raw_quote.get("deadline")),
        time_when_inactive=_opt_str(raw_quote.get("timeWhenInactive")),
    )
    limitations: list[str] = []
    if not request.dry and quote.deposit_address is None:
        # A live quote that returns no deposit address cannot be funded.
        limitations.append(
            "The provider returned a live quote without a deposit address; the swap cannot be "
            "funded from this response."
        )
    return QuoteOutcome(
        ok=True,
        source_status=SourceStatus.OK,
        http_status=result.http_status,
        request=request,
        quote=quote,
        correlation_id=_opt_str(data.get("correlationId")),
        signature=_opt_str(data.get("signature")),
        message=(
            "quote received (dry run: no deposit address is issued)"
            if request.dry
            else "live quote received; a deposit address was issued"
        ),
        endpoint=endpoint,
        limitations=tuple(limitations),
    )


def submit_deposit(
    client: HttpClient, *, deposit_address: str, tx_hash: str, near_sender_account: str | None = None
) -> tuple[SourceStatus, str]:
    """``POST /v0/deposit/submit`` — optional deposit-hash notification.

    Documented as an optional speed-up: it tells the provider a deposit was sent
    so it can pre-emptively verify it. It does not itself move funds. Returns
    ``(source_status, message)``.
    """
    endpoint = f"{config.ONECLICK_BASE}{config.ONECLICK_DEPOSIT_SUBMIT_PATH}"
    body: dict[str, Any] = {"txHash": tx_hash, "depositAddress": deposit_address}
    if near_sender_account:
        body["nearSenderAccount"] = near_sender_account
    result = client.post_json(endpoint, body)
    if not result.ok:
        return (result.status, result.message or "the deposit notification failed")
    return (SourceStatus.OK, "deposit transaction hash submitted")


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


#: Statuses whose name literally contains "deposit" but which do **not** mean a
#: deposit has been observed. The official status table defines
#: ``PENDING_DEPOSIT`` as "Awaiting your token deposit" — the deposit address is
#: issued and no funds have arrived. ``INCOMPLETE_DEPOSIT`` is a *shortfall*: some
#: funds arrived but below the required amount. Neither is a completed deposit.
#: Only ``KNOWN_DEPOSIT_TX`` ("Deposit transaction detected") means a deposit was
#: observed.
AWAITING_DEPOSIT_STATUSES = ("PENDING_DEPOSIT",)
INCOMPLETE_DEPOSIT_STATUSES = ("INCOMPLETE_DEPOSIT",)
#: Statuses that establish a deposit transaction was observed on the origin chain.
DEPOSIT_SEEN_STATUSES = ("KNOWN_DEPOSIT_TX",)


@dataclass(frozen=True)
class LifecycleView:
    """A status-derived lifecycle view for the UI.

    The ``label`` is one of :data:`LIFECYCLE_LABELS`. It is derived from the
    provider status **and** local evidence, so a ``SUCCESS`` provider status
    yields ``EXECUTION_PENDING`` (or ``DESTINATION_OBSERVED``), never
    ``SETTLEMENT_VERIFIED`` — independent verification is a separate, engine-led
    decision.
    """

    provider_status: str | None
    label: str
    deposit_seen: bool
    provider_claims_success: bool
    provider_claims_refund: bool
    provider_claims_failure: bool
    destination_tx_hashes: tuple[str, ...] = ()
    origin_tx_hashes: tuple[str, ...] = ()
    refunded_amount: str | None = None
    amount_out: str | None = None
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_status": self.provider_status,
            "label": self.label,
            "label_text": LIFECYCLE_LABELS.get(self.label, self.label),
            "deposit_seen": self.deposit_seen,
            "provider_claims_success": self.provider_claims_success,
            "provider_claims_refund": self.provider_claims_refund,
            "provider_claims_failure": self.provider_claims_failure,
            "destination_tx_hashes": list(self.destination_tx_hashes),
            "origin_tx_hashes": list(self.origin_tx_hashes),
            "refunded_amount": self.refunded_amount,
            "amount_out": self.amount_out,
            "limitations": list(self.limitations),
        }


def lifecycle_view(
    provider_status: str | None,
    *,
    destination_tx_hashes: tuple[str, ...] = (),
    origin_tx_hashes: tuple[str, ...] = (),
    refunded_amount: str | None = None,
    amount_out: str | None = None,
    source_available: bool = True,
) -> LifecycleView:
    """Map a provider status (+ evidence) onto a lifecycle label.

    Deliberately conservative: a provider ``SUCCESS`` never becomes
    ``SETTLEMENT_VERIFIED`` here. Independent verification is decided by
    :func:`tracesettle.near.settlement.settlement_assurance_from_result` over
    on-chain evidence, and only that can raise the label to
    ``SETTLEMENT_VERIFIED`` (which this function never returns).
    """
    limitations: list[str] = []
    if provider_status is None:
        if not source_available:
            return LifecycleView(
                provider_status=None,
                label="PROVIDER_UNAVAILABLE",
                deposit_seen=False,
                provider_claims_success=False,
                provider_claims_refund=False,
                provider_claims_failure=False,
                limitations=("the status source was unavailable, so the lifecycle is unknown",),
            )
        return LifecycleView(
            provider_status=None,
            label="UNKNOWN_STATUS",
            deposit_seen=False,
            provider_claims_success=False,
            provider_claims_refund=False,
            provider_claims_failure=False,
        )

    status = provider_status.strip().upper()
    if status not in LIFECYCLE_STATUSES:
        limitations.append(
            f"Unrecognised provider status '{provider_status}'; treated as reported and unclassified."
        )
        return LifecycleView(
            provider_status=provider_status,
            label="UNKNOWN_STATUS",
            deposit_seen=False,
            provider_claims_success=False,
            provider_claims_refund=False,
            provider_claims_failure=False,
            limitations=tuple(limitations),
        )

    deposit_seen = status in DEPOSIT_SEEN_STATUSES or status in ("PROCESSING", "SUCCESS", "REFUNDED")
    if status in AWAITING_DEPOSIT_STATUSES:
        # "Awaiting your token deposit": the address is issued, no funds have
        # arrived. This must never read as a submitted or detected deposit.
        label = "AWAITING_DEPOSIT"
        limitations.append(
            "The provider reports PENDING_DEPOSIT, which means it is awaiting your deposit; "
            "no deposit transaction has been observed yet."
        )
    elif status in INCOMPLETE_DEPOSIT_STATUSES:
        label = "DEPOSIT_INCOMPLETE"
        limitations.append(
            "The provider reports INCOMPLETE_DEPOSIT: the deposit received is below the required "
            "amount. A shortfall is not a completed deposit."
        )
    elif status == "KNOWN_DEPOSIT_TX":
        label = "DEPOSIT_DETECTED"
    elif status == "PROCESSING":
        label = "EXECUTION_PENDING"
    elif status == "SUCCESS":
        label = "DESTINATION_OBSERVED" if destination_tx_hashes else "EXECUTION_PENDING"
        limitations.append(
            "The provider reports SUCCESS. That is a reported claim; independent settlement "
            "verification is a separate, evidence-led decision."
        )
    elif status == "REFUNDED":
        label = "REFUND_DETECTED"
        limitations.append("The provider reports a refund; it is reported until the payout is confirmed on-chain.")
    elif status == "FAILED":
        label = "FAILED"
    else:  # pragma: no cover - all statuses handled above
        label = "UNKNOWN_STATUS"

    return LifecycleView(
        provider_status=provider_status,
        label=label,
        deposit_seen=deposit_seen,
        provider_claims_success=status == "SUCCESS",
        provider_claims_refund=status == "REFUNDED",
        provider_claims_failure=status == "FAILED",
        destination_tx_hashes=destination_tx_hashes,
        origin_tx_hashes=origin_tx_hashes,
        refunded_amount=refunded_amount,
        amount_out=amount_out,
        limitations=tuple(limitations),
    )
