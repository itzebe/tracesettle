"""EVM RPC adapter — origin/destination receipt verification.

Verified in Phase 1 (public, no key, requires a normal User-Agent):

    POST https://ethereum-rpc.publicnode.com
    {"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0x..."]}

The adapter distinguishes:

* **inclusion** — the receipt exists (non-null);
* **execution** — ``status == 0x1`` (success) vs ``0x0`` (revert);
* **semantic transfer** — an ERC-20 ``Transfer`` log whose token, recipient and
  amount match the expectation supplied by the orchestrator.

A successful receipt alone proves the transaction executed at chain level. It
does **not** prove the expected asset reached the expected recipient. That is a
separate, explicit check (``DESTINATION_TRANSFER_OBSERVED``), and its absence is
reported as a limitation, never as a failed transfer.

Unsupported chains return UNAVAILABLE — never FAILED.
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

SOURCE = "evm_rpc"

#: keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@dataclass
class EvmReceiptData:
    tx_hash: str
    chain: str
    chain_id: int | None = None
    included: bool = False
    status: str | None = None
    from_address: str | None = None
    to_address: str | None = None
    block_number: int | None = None
    logs: list[dict[str, Any]] = field(default_factory=list)

    @property
    def executed_successfully(self) -> bool:
        return self.status == "0x1"


@dataclass
class ExpectedTransfer:
    """What the orchestrator expects a destination receipt to contain."""

    token_contract: str | None = None
    recipient: str | None = None
    amount_base_units: str | None = None


@dataclass
class TransferMatch:
    matched: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


def _hex_to_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def _normalize_address(value: str | None) -> str | None:
    return value.lower() if isinstance(value, str) else None


def _topic_to_address(topic: str) -> str | None:
    if not isinstance(topic, str) or not topic.startswith("0x") or len(topic) != 66:
        return None
    return "0x" + topic[-40:].lower()


def fetch_receipt(
    tx_hash: str,
    chain: str,
    client: HttpClient,
    expected: ExpectedTransfer | None = None,
) -> tuple[SourceReport, EvmReceiptData | None]:
    rpc = config.rpc_for_chain(chain)
    if rpc is None or rpc.kind != "evm":
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.UNSUPPORTED,
                message=(
                    f"No public RPC is configured for chain '{chain}'. The destination leg "
                    "could not be verified; this is an unverified stage, not a failed transfer."
                ),
                endpoint=None,
            ),
            None,
        )

    # Free public nodes prune history, so an older receipt can come back null from
    # the primary even though the transaction exists. Try every configured
    # endpoint; a fallback answer is validated by the same checks as the primary.
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash],
    }
    last_status = SourceStatus.NOT_FOUND
    last_message: str | None = None
    last_endpoint = rpc.url

    for endpoint in rpc.endpoints():
        last_endpoint = endpoint
        result = client.post_json(endpoint, payload)
        if not result.ok:
            last_status = result.status
            last_message = result.message or f"EVM RPC for {chain} could not be queried."
            # An unhealthy endpoint short-circuits: with the source down we cannot
            # tell "absent" from "unknown", and fanning out to every fallback on an
            # outage only adds load. Only a definitive "not found" tries the next.
            if result.status is not SourceStatus.NOT_FOUND:
                break
            continue

        body = result.data
        if not isinstance(body, dict):
            last_status = SourceStatus.MALFORMED
            last_message = "EVM RPC returned a non-object response."
            break

        receipt = body.get("result")
        if receipt is None:
            last_status = SourceStatus.NOT_FOUND
            last_message = (
                f"No receipt found for {tx_hash} on {rpc.display_name}. A missing receipt "
                "is not proof the transaction failed."
            )
            continue
        if not isinstance(receipt, dict):
            last_status = SourceStatus.MALFORMED
            last_message = "EVM RPC receipt was not an object."
            break

        returned_hash = receipt.get("transactionHash")
        if isinstance(returned_hash, str) and returned_hash.lower() != tx_hash.lower():
            # A receipt for a different hash is a contradiction, not a provider
            # limitation. Do not fall through to another endpoint and do not
            # mis-correlate the response.
            return (
                SourceReport(
                    source=SOURCE,
                    status=SourceStatus.MALFORMED,
                    message=(
                        "EVM RPC returned a receipt for a different transaction hash; "
                        "the response was ignored to avoid mis-correlation."
                    ),
                    endpoint=endpoint,
                ),
                None,
            )

        logs = [entry for entry in (receipt.get("logs") or []) if isinstance(entry, dict)]
        data = EvmReceiptData(
            tx_hash=tx_hash,
            chain=chain,
            chain_id=rpc.chain_id,
            included=True,
            status=receipt.get("status") if isinstance(receipt.get("status"), str) else None,
            from_address=receipt.get("from") if isinstance(receipt.get("from"), str) else None,
            to_address=receipt.get("to") if isinstance(receipt.get("to"), str) else None,
            block_number=_hex_to_int(receipt.get("blockNumber")),
            logs=logs,
        )

        match = match_expected_transfer(data, expected) if expected is not None else None
        evidence = _build_evidence(data, rpc, match, expected)

        message = f"EVM receipt for {tx_hash} on {rpc.display_name} (status {data.status})."
        if endpoint != rpc.url:
            message += f" Retrieved from fallback endpoint {endpoint}."
        if match is not None and not match.matched:
            message += f" Expected transfer not verified: {match.reason}"

        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.OK,
                evidence=tuple(evidence),
                message=message,
                endpoint=endpoint,
            ),
            data,
        )

    return (
        SourceReport(
            source=SOURCE,
            status=last_status,
            message=last_message or f"EVM RPC for {chain} could not be queried.",
            endpoint=last_endpoint,
        ),
        None,
    )


def match_expected_transfer(data: EvmReceiptData, expected: ExpectedTransfer | None) -> TransferMatch:
    """Look for an ERC-20 Transfer matching token/recipient/amount expectations.

    Any expectation we cannot check is reported as not matched, with the reason
    spelled out, so the engine marks the stage unverified rather than confirmed.
    """
    if expected is None:
        return TransferMatch(False, "no expectation supplied")
    if not data.executed_successfully:
        return TransferMatch(False, "receipt status is not success")

    want_contract = _normalize_address(expected.token_contract)
    want_recipient = _normalize_address(expected.recipient)
    want_amount = expected.amount_base_units

    if want_contract is None or want_recipient is None:
        return TransferMatch(
            False,
            "the expected destination token contract and/or recipient is unknown, "
            "so the transfer cannot be checked",
        )

    transfer_logs: list[dict[str, Any]] = []
    for log in data.logs:
        topics = log.get("topics")
        if not isinstance(topics, list) or not topics:
            continue
        if str(topics[0]).lower() != TRANSFER_TOPIC:
            continue
        log_contract = _normalize_address(log.get("address"))
        if log_contract != want_contract:
            continue
        to_addr = _topic_to_address(topics[2]) if len(topics) >= 3 else None
        if to_addr != want_recipient:
            continue
        amount = _hex_to_int(log.get("data"))
        transfer_logs.append(
            {
                "token": log_contract,
                "to": to_addr,
                "amount_base_units": str(amount) if amount is not None else None,
                "log_index": log.get("logIndex"),
            }
        )

    if not transfer_logs:
        return TransferMatch(
            False,
            "no ERC-20 Transfer log matched the expected token contract and recipient",
            {"expected_token": want_contract, "expected_recipient": want_recipient},
        )

    if want_amount is not None:
        exact = [t for t in transfer_logs if t["amount_base_units"] == str(want_amount)]
        if exact:
            return TransferMatch(True, "matched token, recipient and amount", exact[0])
        return TransferMatch(
            True,
            "matched token and recipient; the observed amount differs from the expected amount",
            {"observed": transfer_logs, "expected_amount": str(want_amount)},
        )

    return TransferMatch(
        True,
        "matched token and recipient (no expected amount supplied to check)",
        transfer_logs[0],
    )


def _build_evidence(
    data: EvmReceiptData,
    rpc: config.ChainRpc,
    match: TransferMatch | None,
    expected: ExpectedTransfer | None,
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    url = f"{rpc.explorer_tx_url}{data.tx_hash}"
    stage = Stage.SOURCE_CHAIN_DEPOSIT if expected is None else Stage.DESTINATION_CHAIN_DELIVERY

    # Determine which stage this receipt belongs to via the caller's intent:
    # origin receipts are fetched without an expectation, destination receipts with one.
    # The orchestrator overrides the stage via evidence post-processing when needed.
    items.append(
        EvidenceItem(
            id=f"ev-evm-included-{data.chain}-{data.tx_hash}",
            stage=stage,
            event_type=EventType.DESTINATION_TX_INCLUDED if expected is not None else EventType.SOURCE_TX_INCLUDED,
            source=SOURCE,
            verification=Verification.CONFIRMED,
            provenance=Provenance.REAL,
            tx_hash=data.tx_hash,
            chain=data.chain,
            evidence_url=url,
            verification_method="EVM RPC receipt inclusion",
            details={
                "chain_id": data.chain_id,
                "from": data.from_address,
                "to": data.to_address,
                "block_number": data.block_number,
                "log_count": len(data.logs),
            },
            limitations=("Inclusion proves the transaction is in a block, nothing more.",),
        )
    )

    items.append(
        EvidenceItem(
            id=f"ev-evm-exec-{data.chain}-{data.tx_hash}",
            stage=stage,
            event_type=(
                EventType.DESTINATION_TX_EXECUTED if expected is not None else EventType.SOURCE_TX_EXECUTED
            ),
            source=SOURCE,
            verification=Verification.CONFIRMED,
            provenance=Provenance.REAL,
            tx_hash=data.tx_hash,
            chain=data.chain,
            reported_status="SUCCESS" if data.executed_successfully else "REVERTED",
            evidence_url=url,
            verification_method="EVM RPC receipt status",
            details={"receipt_status": data.status, "execution_succeeded": data.executed_successfully},
            limitations=(
                "A successful receipt proves chain-level execution only; it does not prove "
                "the correct recipient received the expected asset.",
            ),
        )
    )

    if expected is not None and match is not None:
        items.append(
            EvidenceItem(
                id=f"ev-evm-transfer-{data.chain}-{data.tx_hash}",
                stage=Stage.DESTINATION_CHAIN_DELIVERY,
                event_type=EventType.DESTINATION_TRANSFER_OBSERVED,
                source=SOURCE,
                verification=Verification.CONFIRMED if match.matched else Verification.UNAVAILABLE,
                provenance=Provenance.REAL,
                tx_hash=data.tx_hash,
                chain=data.chain,
                evidence_url=url,
                verification_method=(
                    "EVM receipt log decode against expected transfer"
                    if match.matched
                    else "EVM receipt log decode: expected transfer not found"
                ),
                details={"match": match.matched, "reason": match.reason, "match_details": match.details},
                limitations=(
                    ()
                    if match.matched
                    else (
                        "The expected asset transfer could not be verified from the receipt logs.",
                        "This is a verification limitation, not evidence that the transfer failed.",
                    )
                ),
            )
        )
    return items
