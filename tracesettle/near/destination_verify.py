"""Independent verification of the destination-chain delivery of a swap.

A provider's ``SUCCESS`` status is a claim. The origin-chain deposit can be
verified, but that proves only that the money *left* the source — it says nothing
about whether the intended asset reached the intended recipient on the intended
destination chain. This module closes that gap for the supported EVM destination
scope: it reads the destination chain directly and confirms, from the receipt
itself, that the expected asset was transferred to the expected recipient for the
expected amount.

Every check is by explicit identifier — the destination chain id, the transaction
hash, the token contract, the recipient address, and the transferred amount in the
asset's smallest unit. Amount is never used to *find* or *correlate* a transaction;
it is only ever compared once the transaction is already identified. A provider
``SUCCESS`` is never consulted here.

It is read-only. It fetches an EVM receipt (``eth_getTransactionReceipt``) and
re-derives what the chain says.

``VERIFIED``
    The transaction is included, succeeded, and its ``Transfer`` log shows the
    expected token moving to the expected recipient for the expected amount.
``UNCONFIRMED``
    The transaction was found but a required check did not hold (a receipt that is
    not yet final, or an amount that differs from the quote). Insufficient
    evidence, never proof of failure.
``CONTRADICTORY``
    The transaction is confirmed to have reverted, or pays a different recipient,
    or transfers a different token, so it cannot be the delivery it is claimed to be.
``NOT_FOUND``
    The hash is not present on the destination chain.
``UNAVAILABLE``
    The destination chain could not be queried. A source problem, not a verdict.
``UNSUPPORTED``
    No public source is configured for the destination chain, so the claim cannot
    be checked here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .. import config
from ..adapters import evm_rpc
from ..httpclient import HttpClient
from ..model import SourceStatus


class DestinationVerdict(str, Enum):
    """The outcome of independently checking a claimed destination delivery."""

    VERIFIED = "VERIFIED"
    UNCONFIRMED = "UNCONFIRMED"
    CONTRADICTORY = "CONTRADICTORY"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class DestinationVerification:
    """The result of checking one claimed destination-chain delivery."""

    level: DestinationVerdict
    chain: str
    tx_hash: str
    summary: str
    checks: dict[str, Any] = field(default_factory=dict)
    evidence_url: str | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "chain": self.chain,
            "tx_hash": self.tx_hash,
            "summary": self.summary,
            "checks": self.checks,
            "evidence_url": self.evidence_url,
            "limitations": list(self.limitations),
        }


def verify_destination_delivery(
    *,
    chain: str,
    tx_hash: str,
    recipient: str | None,
    token_contract: str | None,
    expected_amount: str | None,
    client: HttpClient,
    min_confirmations: int = 1,
    latest_block_number: int | None = None,
) -> DestinationVerification:
    """Independently verify a claimed destination-chain delivery against the chain.

    ``chain`` is the destination chain key (``eth``, ``base`` …). ``tx_hash`` is
    the destination transaction the provider named. ``recipient`` is the quote's
    Intents recipient the delivery must pay. ``token_contract`` is the ERC-20
    contract when the destination asset is a token, or ``None`` for a native
    asset. ``expected_amount`` is the quote's expected output in base units; when
    supplied, a mismatch is disclosed, never silently ignored. It is never used to
    *find* the transaction.

    ``min_confirmations`` and ``latest_block_number`` express a finality
    requirement: when ``latest_block_number`` is supplied, a receipt whose block is
    fewer than ``min_confirmations`` behind it is reported as insufficient evidence
    (``UNCONFIRMED``), never as a delivery. When no head is supplied, finality is
    not checked and that is stated as a limitation rather than assumed.
    """
    chain = (chain or "").strip().lower()
    if not tx_hash or not isinstance(tx_hash, str):
        return DestinationVerification(
            level=DestinationVerdict.UNCONFIRMED,
            chain=chain,
            tx_hash=str(tx_hash),
            summary="No destination-chain transaction hash was supplied to verify.",
        )

    rpc = config.rpc_for_chain(chain)
    if rpc is None or rpc.kind != "evm":
        return DestinationVerification(
            level=DestinationVerdict.UNSUPPORTED,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                f"No public source is configured for destination chain '{chain or 'unknown'}', so "
                "the delivery claim cannot be independently checked here."
            ),
        )

    # An origin receipt is fetched without an expectation; a destination receipt
    # with one. The adapter validates that the returned receipt is for *this* hash
    # and decodes the transfer log against the expectation, so identity and the
    # semantic transfer check are both performed there and re-derived below.
    expected = evm_rpc.ExpectedTransfer(
        token_contract=token_contract,
        recipient=recipient,
        amount_base_units=expected_amount,
    )
    report, data = evm_rpc.fetch_receipt(tx_hash, chain, client, expected=expected)

    if report.status is SourceStatus.UNSUPPORTED:
        return DestinationVerification(
            level=DestinationVerdict.UNSUPPORTED,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                f"No public source is configured for destination chain '{chain}', so the "
                "delivery claim cannot be independently checked here."
            ),
        )
    if report.status is SourceStatus.NOT_FOUND:
        return DestinationVerification(
            level=DestinationVerdict.NOT_FOUND,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The claimed destination transaction is not present on the destination chain. "
                "This is a missing record, not proof the transfer failed."
            ),
        )
    if report.status is not SourceStatus.OK or data is None:
        # A receipt for a *different* hash is a contradiction, not an outage.
        if report.status is SourceStatus.MALFORMED and "different transaction hash" in (
            report.message or ""
        ):
            return DestinationVerification(
                level=DestinationVerdict.CONTRADICTORY,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    "The destination source returned a receipt for a different transaction hash, "
                    "so the claimed delivery could not be tied to a transaction."
                ),
            )
        return DestinationVerification(
            level=DestinationVerdict.UNAVAILABLE,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                f"The destination chain could not be queried ({report.status.value}), so the "
                "delivery claim was not independently checked. This is a source-availability "
                "problem, not a failed transfer."
            ),
        )

    url = f"{rpc.explorer_tx_url}{tx_hash}"
    checks: dict[str, Any] = {
        "included": data.included,
        "receipt_status": data.status,
        "execution_succeeded": data.executed_successfully,
        "chain_id": data.chain_id,
        "expected_chain_id": rpc.chain_id,
        "block_number": data.block_number,
        "to": data.to_address,
    }

    if not data.executed_successfully:
        return DestinationVerification(
            level=DestinationVerdict.CONTRADICTORY,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The destination transaction is confirmed to have reverted, so it delivered "
                "nothing. Its inclusion in a block does not make it a delivery."
            ),
            checks=checks,
            evidence_url=url,
        )

    # Finality: a receipt is only a delivery once it is buried under enough blocks.
    if latest_block_number is not None and data.block_number is not None:
        confirmations = latest_block_number - data.block_number + 1
        checks["confirmations"] = confirmations
        checks["min_confirmations"] = min_confirmations
        if confirmations < min_confirmations:
            return DestinationVerification(
                level=DestinationVerdict.UNCONFIRMED,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    f"The destination transaction is included but has only {confirmations} "
                    f"confirmation(s), fewer than the required {min_confirmations}. This is "
                    "insufficient evidence, not a failure."
                ),
                checks=checks,
                evidence_url=url,
            )

    want_contract = (token_contract or "").lower() or None
    want_recipient = (recipient or "").lower() or None
    if want_recipient is None:
        # Without the intended recipient we cannot tie any transfer to this intent.
        return DestinationVerification(
            level=DestinationVerdict.UNCONFIRMED,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The intended destination recipient is unknown, so the delivered transfer cannot "
                "be tied to this intent. Insufficient evidence, not a failure."
            ),
            checks=checks,
            evidence_url=url,
            limitations=("The quote did not name a destination recipient.",),
        )

    if want_contract is not None:
        transfer = _matching_transfer(data, want_contract, want_recipient)
        checks["expected_token"] = want_contract
        checks["expected_recipient"] = want_recipient
        if transfer is None:
            # A different recipient is a contradiction; a missing transfer of the
            # expected token is likewise not this delivery.
            return DestinationVerification(
                level=DestinationVerdict.CONTRADICTORY,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    "The transaction succeeded but carries no transfer of the expected token to "
                    "the intended recipient, so it is not the claimed delivery."
                ),
                checks=checks,
                evidence_url=url,
            )
        observed = transfer["amount_base_units"]
        checks["observed_amount_base_units"] = observed
        if expected_amount is not None and observed is not None and str(observed) != str(expected_amount):
            checks["expected_amount_base_units"] = str(expected_amount)
            return DestinationVerification(
                level=DestinationVerdict.UNCONFIRMED,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    "The token and recipient match, but the transferred amount differs from the "
                    "quote's expected output. The difference is disclosed, not reconciled."
                ),
                checks=checks,
                evidence_url=url,
            )
        return DestinationVerification(
            level=DestinationVerdict.VERIFIED,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "Independently verified on the destination chain: the transaction succeeded and "
                "transferred the expected token to the intended recipient."
            ),
            checks=checks,
            evidence_url=url,
            limitations=(
                "This verifies the destination leg; the origin deposit is verified separately.",
            ),
        )

    # Native asset: the top-level ``to`` is the recipient. A receipt does not carry
    # the transferred ``value`` (that is in the transaction body), so the recipient
    # is verified here and the amount is disclosed as not checked rather than guessed.
    checks["expected_recipient"] = want_recipient
    if (data.to_address or "").lower() != want_recipient:
        return DestinationVerification(
            level=DestinationVerdict.CONTRADICTORY,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The transaction succeeded but its recipient is not the intended destination, so "
                "it is not the claimed delivery."
            ),
            checks=checks,
            evidence_url=url,
        )
    return DestinationVerification(
        level=DestinationVerdict.VERIFIED,
        chain=chain,
        tx_hash=tx_hash,
        summary=(
            "Independently verified on the destination chain: the transaction succeeded and pays "
            "the intended recipient."
        ),
        checks=checks,
        evidence_url=url,
        limitations=(
            "This verifies the destination leg; the origin deposit is verified separately.",
            "A receipt does not carry the native value transferred, so the amount was not "
            "independently checked for a native-asset delivery.",
        ),
    )


def fetch_latest_block_number(chain: str, client: HttpClient) -> int | None:
    """The destination chain's current head block number, or ``None``.

    Used only to express a confirmation depth. A failure to read the head is not a
    verdict about any transaction: it returns ``None`` and the caller reports
    finality as not checked rather than guessing a depth.
    """
    rpc = config.rpc_for_chain(chain)
    if rpc is None or rpc.kind != "evm":
        return None
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}
    for endpoint in rpc.endpoints():
        result = client.post_json(endpoint, payload)
        if not result.ok or not isinstance(result.data, dict):
            # A head read is best-effort: an unreachable endpoint ends the search
            # rather than fanning out, and the caller reports finality as unchecked.
            break
        value = result.data.get("result")
        number = evm_rpc._hex_to_int(value)
        if number is not None:
            return number
    return None


def _matching_transfer(
    data: evm_rpc.EvmReceiptData, token: str, recipient: str
) -> dict[str, Any] | None:
    """The first ERC-20 ``Transfer`` log for ``token`` to ``recipient``, or ``None``.

    Matching is on the exact token contract and the exact recipient address
    (case-folded hex), never on the amount, so a transfer is located by identity
    and only then is its amount compared.
    """
    for log in data.logs:
        topics = log.get("topics")
        if not isinstance(topics, list) or len(topics) < 3:
            continue
        if str(topics[0]).lower() != evm_rpc.TRANSFER_TOPIC:
            continue
        if (log.get("address") or "").lower() != token:
            continue
        to_addr = evm_rpc._topic_to_address(topics[2])
        if to_addr != recipient:
            continue
        amount = evm_rpc._hex_to_int(log.get("data"))
        return {
            "amount_base_units": str(amount) if amount is not None else None,
            "log_index": log.get("logIndex"),
        }
    return None
