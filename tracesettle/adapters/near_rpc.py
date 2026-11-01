"""NEAR RPC adapter — settlement verification.

Verified in Phase 1:

    POST https://free.rpc.fastnear.com
    {"jsonrpc":"2.0","id":1,"method":"tx",
     "params":{"tx_hash":"<hash>","sender_account_id":"intents.near","wait_until":"NONE"}}

Important behaviours learned in Phase 1:

* The ``tx`` method needs a ``sender_account_id`` or it fails to parse
  (``Failed parsing args: data did not match any variant of untagged enum
  TransactionInfo``). Callers therefore try the known signer ``intents.near``
  first, then ``bridge-mng.near`` for bridge-leg transactions.
* ``intents.near`` receipt logs contain DIP-4 ``EVENT_JSON`` entries that carry
  the ``intent_hash``. Finding the *specific* intent hash in an on-chain log is
  what turns a settlement from REPORTED into CONFIRMED.

The adapter separates four distinct notions, and never conflates them:

1. **inclusion**      — the transaction exists in a block;
2. **finality**       — ``final_execution_status`` reached ``FINAL``;
3. **execution**      — the receipt/outcome did not fail;
4. **semantic evidence** — the investigated intent hash appears in a receipt log
   of ``intents.near``.
"""

from __future__ import annotations

import json
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

SOURCE = "near_rpc"

#: Signers to try, in order. ``intents.near`` signs settlement transactions;
#: ``bridge-mng.near`` signs bridge mint/withdraw legs (observed in Phase 1).
CANDIDATE_SENDERS = ("intents.near", "bridge-mng.near")

#: The authoritative contract that executes intents.
INTENTS_CONTRACT = "intents.near"


@dataclass
class IntentWithdrawal:
    """A DIP-4 ``ft_withdraw`` destination for one intent.

    When an intent executes, ``intents.near`` emits an ``ft_withdraw`` event whose
    ``msg`` names the recipient on the destination (or refund) chain, e.g.
    ``{"recipient":"btc:bc1q…"}``. That recipient is an explicit identifier
    linking the intent hash to the chain transaction that pays it.
    """

    intent_hash: str
    recipient: str | None = None
    token: str | None = None
    amount: str | None = None


@dataclass
class NearTxData:
    tx_hash: str
    sender_account_id: str | None = None
    final_execution_status: str | None = None
    included: bool = False
    execution_failed: bool = False
    signer_id: str | None = None
    receiver_id: str | None = None
    block_hash: str | None = None
    logs: list[str] = field(default_factory=list)
    found_intent_hashes: list[str] = field(default_factory=list)
    #: Origin-chain transaction hashes found in bridge ``BRIDGED_FROM`` memos.
    bridged_from_origin_hashes: list[str] = field(default_factory=list)
    #: Bitcoin origin txids found in bridge ``utxo_added`` events (``<txid>@<vout>``).
    btc_utxo_origin_hashes: list[str] = field(default_factory=list)
    #: Intent withdrawal destinations (intent hash -> on-chain recipient).
    intent_withdrawals: list[IntentWithdrawal] = field(default_factory=list)
    error_message: str | None = None


def _extract_logs(result: dict[str, Any]) -> list[str]:
    logs: list[str] = []
    for outcome in result.get("receipts_outcome") or []:
        if not isinstance(outcome, dict):
            continue
        inner = outcome.get("outcome")
        if not isinstance(inner, dict):
            continue
        for log in inner.get("logs") or []:
            if isinstance(log, str):
                logs.append(log)
    return logs


def _execution_failed(result: dict[str, Any]) -> bool:
    """Whether the *transaction itself* failed.

    This must inspect only the transaction-level outcome. ``intents.near`` batches
    many intents into one transaction, and each intent's receipt is an independent
    outcome; a sibling receipt failing says nothing about whether this transaction
    — or the intent under investigation — failed. A failed sibling must therefore
    never be attributed to the transaction.
    """
    def failed(status: Any) -> bool:
        if not isinstance(status, dict):
            return False
        if "Failure" in status:
            return True
        # Receipt outcomes encode failure as a nested Failure value.
        return any(k == "Failure" for k in status.keys())

    tx_outcome = result.get("transaction_outcome")
    if not isinstance(tx_outcome, dict):
        return False
    return failed(tx_outcome.get("outcome", {}).get("status"))


def _intent_hashes_in_logs(logs: list[str]) -> list[str]:
    """Collect intent hashes from DIP-4 ``EVENT_JSON`` log lines."""
    found: list[str] = []
    for log in logs:
        marker = "EVENT_JSON:"
        if marker not in log:
            continue
        payload = log.split(marker, 1)[1]
        try:
            parsed = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue
        for entry in parsed.get("data") or []:
            if not isinstance(entry, dict):
                continue
            value = entry.get("intent_hash")
            if isinstance(value, str) and value and value not in found:
                found.append(value)
    return found


def _intent_withdrawals(logs: list[str]) -> list[IntentWithdrawal]:
    """Collect DIP-4 ``ft_withdraw`` destinations, keyed by intent hash.

    The ``msg`` field is a JSON string naming the withdrawal recipient, e.g.
    ``{"recipient":"btc:bc1q…","fee":"0"}``. That recipient is the explicit
    identifier connecting an intent to the chain transaction that pays it.
    """
    found: list[IntentWithdrawal] = []
    marker = "EVENT_JSON:"
    for log in logs:
        if marker not in log or "ft_withdraw" not in log:
            continue
        try:
            parsed = json.loads(log.split(marker, 1)[1])
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue
        for entry in parsed.get("data") or []:
            if not isinstance(entry, dict):
                continue
            intent_hash = entry.get("intent_hash")
            if not isinstance(intent_hash, str) or not intent_hash:
                continue
            recipient = None
            msg = entry.get("msg")
            if isinstance(msg, str) and msg:
                try:
                    decoded = json.loads(msg)
                except (ValueError, TypeError):
                    decoded = None
                if isinstance(decoded, dict) and isinstance(decoded.get("recipient"), str):
                    recipient = decoded["recipient"]
            found.append(
                IntentWithdrawal(
                    intent_hash=intent_hash,
                    recipient=recipient,
                    token=entry.get("token") if isinstance(entry.get("token"), str) else None,
                    amount=entry.get("amount") if isinstance(entry.get("amount"), str) else None,
                )
            )
    return found


def _btc_utxo_origin_hashes(logs: list[str]) -> list[str]:
    """Collect Bitcoin origin txids from bridge ``utxo_added`` events.

    When the BTC connector credits a Bitcoin deposit, it emits a ``bridge``
    ``utxo_added`` event whose ``utxo_storage_keys`` are ``"<btc_txid>@<vout>"``.
    The txid is the origin-chain transaction, named explicitly — the Bitcoin
    equivalent of the EVM ``BRIDGED_FROM`` memo.
    """
    found: list[str] = []
    marker = "EVENT_JSON:"
    for log in logs:
        if marker not in log or "utxo_added" not in log:
            continue
        try:
            parsed = json.loads(log.split(marker, 1)[1])
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue
        for entry in parsed.get("data") or []:
            if not isinstance(entry, dict):
                continue
            for key in entry.get("utxo_storage_keys") or []:
                if not isinstance(key, str) or "@" not in key:
                    continue
                txid = key.split("@", 1)[0]
                if txid and txid not in found:
                    found.append(txid)
    return found


def _bridged_from_origin_hashes(logs: list[str]) -> list[str]:
    """Collect origin-chain tx hashes from bridge ``BRIDGED_FROM`` memos.

    When the bridge credits a deposit, the ``omft.near`` transfer to ``intents.near``
    carries a memo of the form ``BRIDGED_FROM:{"chainId":"1","txHash":"0x…"}``. That
    memo is the explicit identifier linking the origin-chain transaction to the NEAR
    bridge credit — it is not inferred from amount or timestamp.
    """
    found: list[str] = []
    marker = "EVENT_JSON:"
    for log in logs:
        if marker not in log or "BRIDGED_FROM" not in log:
            continue
        try:
            parsed = json.loads(log.split(marker, 1)[1])
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue
        for entry in parsed.get("data") or []:
            if not isinstance(entry, dict):
                continue
            memo = entry.get("memo")
            if not isinstance(memo, str) or "BRIDGED_FROM:" not in memo:
                continue
            payload = memo.split("BRIDGED_FROM:", 1)[1]
            try:
                decoded = json.loads(payload)
            except (ValueError, TypeError):
                continue
            if not isinstance(decoded, dict):
                continue
            tx_hash = decoded.get("txHash")
            if isinstance(tx_hash, str) and tx_hash and tx_hash not in found:
                found.append(tx_hash)
    return found


def fetch_tx(tx_hash: str, client: HttpClient) -> tuple[SourceReport, NearTxData | None]:
    """Fetch a NEAR transaction, trying the known signers and RPC endpoints.

    Endpoints are tried in order: the primary, then any configured archive
    fallbacks. Free public nodes prune history, so the primary answers
    ``UNKNOWN_TRANSACTION`` for an old transaction even though it exists; only an
    archive endpoint can resolve it. A fallback record is validated by the same
    checks as the primary. A miss on *every* endpoint stays ``NOT_FOUND``; an
    unreachable endpoint stays ``UNAVAILABLE`` — a provider problem, not proof
    the transaction is absent.
    """
    last_status = SourceStatus.NOT_FOUND
    last_message: str | None = None
    endpoint = config.NEAR_RPC_URL

    for endpoint in config.NEAR_RPC.endpoints():
        for sender in CANDIDATE_SENDERS:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tx",
                "params": {"tx_hash": tx_hash, "sender_account_id": sender, "wait_until": "NONE"},
            }
            result = client.post_json(endpoint, payload)
            if not result.ok:
                last_status = result.status
                last_message = result.message
                # Unavailable sources short-circuit: with the source down we cannot
                # tell "absent" from "unknown", and a second endpoint would only
                # repeat the same outage. Only "not found" benefits from a fallback.
                if result.status is not SourceStatus.NOT_FOUND:
                    return (
                        SourceReport(
                            source=SOURCE,
                            status=result.status,
                            message=result.message or "NEAR RPC could not be queried.",
                            endpoint=endpoint,
                        ),
                        None,
                    )
                continue

            body = result.data
            if not isinstance(body, dict):
                last_status = SourceStatus.MALFORMED
                last_message = "NEAR RPC returned a non-object response."
                continue
            if "error" in body and "result" not in body:
                # The RPC could not resolve this hash for this sender; try the next.
                error = body.get("error")
                last_status = SourceStatus.NOT_FOUND
                if isinstance(error, dict) and isinstance(error.get("message"), str):
                    last_message = error["message"]
                continue

            inner = body.get("result")
            if not isinstance(inner, dict):
                last_status = SourceStatus.MALFORMED
                last_message = "NEAR RPC response had no 'result' object."
                continue

            tx = inner.get("transaction") if isinstance(inner.get("transaction"), dict) else {}
            logs = _extract_logs(inner)
            data = NearTxData(
                tx_hash=tx_hash,
                sender_account_id=sender,
                final_execution_status=(
                    inner.get("final_execution_status")
                    if isinstance(inner.get("final_execution_status"), str)
                    else None
                ),
                included=True,
                execution_failed=_execution_failed(inner),
                signer_id=tx.get("signer_id") if isinstance(tx.get("signer_id"), str) else None,
                receiver_id=tx.get("receiver_id") if isinstance(tx.get("receiver_id"), str) else None,
                block_hash=(
                    inner.get("transaction_outcome", {}).get("block_hash")
                    if isinstance(inner.get("transaction_outcome"), dict)
                    else None
                ),
                logs=logs,
                found_intent_hashes=_intent_hashes_in_logs(logs),
                bridged_from_origin_hashes=_bridged_from_origin_hashes(logs),
                btc_utxo_origin_hashes=_btc_utxo_origin_hashes(logs),
                intent_withdrawals=_intent_withdrawals(logs),
            )
            message = f"NEAR transaction {tx_hash} retrieved (status {data.final_execution_status})."
            if endpoint != config.NEAR_RPC_URL:
                message += f" Retrieved from fallback endpoint {endpoint}."
            return (
                SourceReport(
                    source=SOURCE,
                    status=SourceStatus.OK,
                    evidence=tuple(_build_evidence(data, endpoint)),
                    message=message,
                    endpoint=endpoint,
                ),
                data,
            )

    if last_status is SourceStatus.NOT_FOUND:
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.NOT_FOUND,
                message=(
                    f"NEAR RPC has no transaction for {tx_hash} under the known signers. "
                    "Absence of a record is not proof the transaction does not exist."
                ),
                endpoint=endpoint,
            ),
            None,
        )
    return (
        SourceReport(
            source=SOURCE, status=last_status, message=last_message, endpoint=endpoint
        ),
        None,
    )


def _build_evidence(data: NearTxData, endpoint: str) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    url = f"{config.NEAR_RPC.explorer_tx_url}{data.tx_hash}"

    items.append(
        EvidenceItem(
            id=f"ev-near-included-{data.tx_hash}",
            stage=Stage.NEAR_SETTLEMENT,
            event_type=EventType.NEAR_TX_INCLUDED,
            source=SOURCE,
            verification=Verification.CONFIRMED,
            provenance=Provenance.REAL,
            tx_hash=data.tx_hash,
            chain="near",
            evidence_url=url,
            verification_method="NEAR RPC transaction inclusion",
            details={
                "sender_account_id": data.sender_account_id,
                "signer_id": data.signer_id,
                "receiver_id": data.receiver_id,
                "block_hash": data.block_hash,
            },
            limitations=(
                "Inclusion proves the transaction exists in a block; it does not by itself "
                "prove the investigated intent settled.",
            ),
        )
    )

    if data.final_execution_status == "FINAL":
        items.append(
            EvidenceItem(
                id=f"ev-near-final-{data.tx_hash}",
                stage=Stage.NEAR_SETTLEMENT,
                event_type=EventType.NEAR_TX_FINAL,
                source=SOURCE,
                verification=Verification.CONFIRMED,
                provenance=Provenance.REAL,
                tx_hash=data.tx_hash,
                chain="near",
                reported_status=data.final_execution_status,
                evidence_url=url,
                verification_method="NEAR RPC final execution status",
                details={"final_execution_status": data.final_execution_status},
                limitations=("Finality does not, by itself, prove the intent settled.",),
            )
        )

    items.append(
        EvidenceItem(
            id=f"ev-near-exec-{data.tx_hash}",
            stage=Stage.NEAR_SETTLEMENT,
            event_type=EventType.NEAR_TX_EXECUTION,
            source=SOURCE,
            verification=Verification.CONFIRMED if not data.execution_failed else Verification.CONFIRMED,
            provenance=Provenance.REAL,
            tx_hash=data.tx_hash,
            chain="near",
            reported_status="FAILED" if data.execution_failed else "SUCCESS",
            evidence_url=url,
            verification_method="NEAR RPC execution outcome",
            details={"execution_failed": data.execution_failed},
            limitations=(
                "On-chain execution success is not, by itself, semantic proof that this "
                "investigation's intent settled.",
            ),
        )
    )

    if data.found_intent_hashes:
        items.append(
            EvidenceItem(
                id=f"ev-near-intent-{data.tx_hash}",
                stage=Stage.NEAR_SETTLEMENT,
                event_type=EventType.INTENT_EVENT_OBSERVED,
                source=SOURCE,
                verification=Verification.CONFIRMED,
                provenance=Provenance.REAL,
                tx_hash=data.tx_hash,
                chain="near",
                evidence_url=url,
                verification_method="NEAR RPC DIP-4 EVENT_JSON log parse",
                details={
                    "contract": INTENTS_CONTRACT,
                    "intent_hashes": data.found_intent_hashes,
                    "standard": "dip4",
                },
                limitations=(
                    "Confirms the named intent appears in on-chain event logs; it does not "
                    "by itself establish the real-world meaning of the transfer.",
                ),
            )
        )

    if data.intent_withdrawals:
        items.append(
            EvidenceItem(
                id=f"ev-near-withdrawal-{data.tx_hash}",
                stage=Stage.NEAR_SETTLEMENT,
                event_type=EventType.INTENT_WITHDRAWAL_OBSERVED,
                source=SOURCE,
                verification=Verification.CONFIRMED,
                provenance=Provenance.REAL,
                tx_hash=data.tx_hash,
                chain="near",
                evidence_url=url,
                verification_method="NEAR RPC DIP-4 intent-withdrawal event parse",
                details={
                    "contract": INTENTS_CONTRACT,
                    "standard": "dip4",
                    "withdrawals": [
                        {
                            "intent_hash": w.intent_hash,
                            "recipient": w.recipient,
                            "token": w.token,
                            "amount": w.amount,
                        }
                        for w in data.intent_withdrawals
                    ],
                    "withdrawal_recipients": [
                        w.recipient for w in data.intent_withdrawals if w.recipient
                    ],
                },
                limitations=(
                    "Records the on-chain withdrawal destination named for the intent. It links "
                    "the intent to a recipient address; it does not prove the destination-chain "
                    "transaction was broadcast or confirmed.",
                ),
            )
        )

    origin_hashes = data.bridged_from_origin_hashes or data.btc_utxo_origin_hashes
    if origin_hashes:
        is_btc = not data.bridged_from_origin_hashes and bool(data.btc_utxo_origin_hashes)
        items.append(
            EvidenceItem(
                id=f"ev-near-bridge-credit-{data.tx_hash}",
                stage=Stage.BRIDGE_DEPOSIT_CREDIT,
                event_type=EventType.DEPOSIT_OBSERVED,
                source=SOURCE,
                verification=Verification.CONFIRMED,
                provenance=Provenance.REAL,
                tx_hash=data.tx_hash,
                chain="near",
                evidence_url=url,
                verification_method=(
                    "NEAR RPC bridge utxo_added event parse"
                    if is_btc
                    else "NEAR RPC BRIDGED_FROM memo parse"
                ),
                details={
                    "bridge_contract": "btc-connector.bridge.near" if is_btc else "omft.near",
                    "credited_to": "intents.near",
                    "bridged_from_origin_hashes": origin_hashes,
                    "memo_marker": "utxo_added" if is_btc else "BRIDGED_FROM",
                },
                limitations=(
                    (
                        "Confirms an on-chain bridge credit carrying a utxo_added event whose "
                        "utxo_storage_key names the origin Bitcoin transaction. It is corroborating "
                        "evidence, not proof of the wider settlement claim."
                        if is_btc
                        else "Confirms an on-chain bridge credit carrying a BRIDGED_FROM memo. The memo "
                        "links the origin transaction hash explicitly; it is corroborating evidence, "
                        "not proof of the wider settlement claim."
                    ),
                ),
            )
        )
    return items
