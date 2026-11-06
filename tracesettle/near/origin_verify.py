"""Independent verification of a user-supplied origin-chain deposit hash.

The lifecycle records the deposit hash the user's own wallet reports. That hash
is a *claim* until it is checked against the chain. This module checks the claim
the only way the tool ever checks one: by reading the origin chain directly and
comparing explicit identifiers — the recipient address, the token contract and
the amount — never by trusting a provider and never by amount/timestamp
similarity alone.

It is read-only. It fetches a transaction receipt (EVM) or transaction (Bitcoin),
re-derives what the chain says, and returns a structured verdict whose level
mirrors the evidence vocabulary:

``VERIFIED``
    The transaction is included, succeeded, and pays the deposit address the
    expected token and amount.
``UNCONFIRMED``
    The transaction was found but a required check did not hold (for example an
    unmined transaction, or a value that differs from the quote). The specific
    mismatch is named; this is insufficient evidence, never proof of failure.
``CONTRADICTORY``
    The transaction is confirmed to have reverted, or it pays a different
    recipient, so it cannot be the deposit it is claimed to be.
``NOT_FOUND``
    The hash is not present on the origin chain.
``UNAVAILABLE``
    The origin chain could not be queried. A source problem, not a verdict.
``UNSUPPORTED``
    No public source is configured for the origin chain, so the claim cannot be
    checked here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..adapters import btc_rpc, evm_rpc
from ..config import rpc_for_chain
from ..httpclient import HttpClient
from ..model import SourceStatus


class OriginVerdict(str, Enum):
    """The outcome of independently checking a claimed origin-chain deposit."""

    VERIFIED = "VERIFIED"
    UNCONFIRMED = "UNCONFIRMED"
    CONTRADICTORY = "CONTRADICTORY"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class OriginVerification:
    """The result of checking one claimed origin-chain deposit transaction."""

    level: OriginVerdict
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


#: A 20-byte EVM contract address embedded in a ``nep141:<chain>-0x….omft.near``
#: asset id. Anchored so a malformed id yields no contract rather than a guess.
_EVM_CONTRACT_RE = re.compile(r"^(0x[0-9a-fA-F]{40})")


def origin_contract_address(asset_id: str | None) -> str | None:
    """The EVM contract address an Intents origin asset id names, or ``None``.

    A native asset (for example ``nep141:btc.omft.near``) names no contract; an
    ERC-20 asset (for example ``nep141:eth-0xdac…c7.omft.near``) embeds the
    contract after the chain prefix. Anything that does not match the exact shape
    yields ``None`` so the caller treats the asset as native rather than inventing
    a contract to match against.
    """
    if not isinstance(asset_id, str) or not asset_id.startswith("nep141:"):
        return None
    rest = asset_id[len("nep141:"):]
    if "-" not in rest:
        return None
    _, after_chain = rest.split("-", 1)
    match = _EVM_CONTRACT_RE.match(after_chain)
    return match.group(1).lower() if match else None


def verify_origin_deposit(
    *,
    chain: str,
    tx_hash: str,
    deposit_address: str,
    token_contract: str | None,
    expected_amount: str | None,
    client: HttpClient,
) -> OriginVerification:
    """Independently verify a claimed origin-chain deposit against the chain.

    ``chain`` is the origin chain key (``eth``, ``base``, ``btc`` …).
    ``deposit_address`` is the quote's deposit address the transaction must pay.
    ``token_contract`` is the ERC-20 contract when the origin asset is a token,
    or ``None`` for a native asset. ``expected_amount`` is the quote's expected
    input amount in base units; when supplied, a mismatch is reported, never
    silently ignored. It is never used to *find* the transaction.
    """
    chain = (chain or "").strip().lower()
    if not tx_hash or not isinstance(tx_hash, str):
        return OriginVerification(
            level=OriginVerdict.UNCONFIRMED,
            chain=chain,
            tx_hash=str(tx_hash),
            summary="No origin-chain transaction hash was supplied to verify.",
        )
    if chain == "btc":
        return _verify_btc(
            tx_hash=tx_hash,
            deposit_address=deposit_address,
            expected_amount=expected_amount,
            client=client,
        )
    return _verify_evm(
        chain=chain,
        tx_hash=tx_hash,
        deposit_address=deposit_address,
        token_contract=token_contract,
        expected_amount=expected_amount,
        client=client,
    )


def _verify_evm(
    *,
    chain: str,
    tx_hash: str,
    deposit_address: str,
    token_contract: str | None,
    expected_amount: str | None,
    client: HttpClient,
) -> OriginVerification:
    report, data = evm_rpc.fetch_receipt(tx_hash, chain, client, expected=None)
    if report.status is SourceStatus.UNSUPPORTED:
        return OriginVerification(
            level=OriginVerdict.UNSUPPORTED,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                f"No public source is configured for origin chain '{chain}', so the deposit "
                "claim cannot be independently checked here."
            ),
        )
    if report.status is SourceStatus.NOT_FOUND:
        return OriginVerification(
            level=OriginVerdict.NOT_FOUND,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The claimed deposit transaction is not present on the origin chain. This is a "
                "missing record, not proof the transaction failed."
            ),
        )
    if report.status is not SourceStatus.OK or data is None:
        # A receipt for a *different* hash is a contradiction, not an outage.
        if report.status is SourceStatus.MALFORMED and "different transaction hash" in (
            report.message or ""
        ):
            return OriginVerification(
                level=OriginVerdict.CONTRADICTORY,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    "The origin source returned a receipt for a different transaction hash, so "
                    "the claimed deposit could not be tied to a transaction."
                ),
            )
        return OriginVerification(
            level=OriginVerdict.UNAVAILABLE,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                f"The origin chain could not be queried ({report.status.value}), so the deposit "
                "claim was not independently checked. This is a source-availability problem."
            ),
        )

    checks: dict[str, Any] = {
        "included": data.included,
        "receipt_status": data.status,
        "execution_succeeded": data.executed_successfully,
        "to": data.to_address,
        "block_number": data.block_number,
    }
    rpc = rpc_for_chain(chain)
    url = f"{rpc.explorer_tx_url}{tx_hash}" if rpc else None

    if not data.executed_successfully:
        return OriginVerification(
            level=OriginVerdict.CONTRADICTORY,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The deposit transaction is confirmed to have reverted, so it transferred "
                "nothing. Its inclusion in a block does not make it a deposit."
            ),
            checks=checks,
            evidence_url=url,
        )

    want = (deposit_address or "").lower()
    if token_contract:
        transfer = _matching_transfer(data, token_contract.lower(), want)
        checks["expected_token"] = token_contract.lower()
        checks["expected_recipient"] = want
        if transfer is None:
            return OriginVerification(
                level=OriginVerdict.CONTRADICTORY,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    "The transaction succeeded but carries no transfer of the expected token to "
                    "the deposit address, so it is not the claimed deposit."
                ),
                checks=checks,
                evidence_url=url,
            )
        observed = transfer["amount_base_units"]
        checks["observed_amount_base_units"] = observed
        if expected_amount is not None and observed is not None and str(observed) != str(expected_amount):
            checks["expected_amount_base_units"] = str(expected_amount)
            return OriginVerification(
                level=OriginVerdict.UNCONFIRMED,
                chain=chain,
                tx_hash=tx_hash,
                summary=(
                    "The token and recipient match, but the transferred amount differs from the "
                    "quote's expected input. The difference is disclosed, not reconciled."
                ),
                checks=checks,
                evidence_url=url,
            )
        return OriginVerification(
            level=OriginVerdict.VERIFIED,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "Independently verified on the origin chain: the transaction succeeded and "
                "transferred the expected token to the deposit address."
            ),
            checks=checks,
            evidence_url=url,
            limitations=("This verifies the origin leg only; it does not prove delivery.",),
        )

    # Native asset: the top-level ``to`` is the deposit address. A receipt does not
    # carry the transferred ``value`` (that is in the transaction body), so the
    # recipient is verified here and the amount is disclosed as not checked from
    # the receipt rather than guessed.
    checks["expected_recipient"] = want
    if (data.to_address or "").lower() != want:
        return OriginVerification(
            level=OriginVerdict.CONTRADICTORY,
            chain=chain,
            tx_hash=tx_hash,
            summary=(
                "The transaction succeeded but its recipient is not the deposit address, so it is "
                "not the claimed deposit."
            ),
            checks=checks,
            evidence_url=url,
        )
    return OriginVerification(
        level=OriginVerdict.VERIFIED,
        chain=chain,
        tx_hash=tx_hash,
        summary=(
            "Independently verified on the origin chain: the transaction succeeded and pays the "
            "deposit address."
        ),
        checks=checks,
        evidence_url=url,
        limitations=(
            "This verifies the origin leg only; it does not prove delivery.",
            "A receipt does not carry the native value transferred, so the amount was not "
            "independently checked for a native-asset deposit.",
        ),
    )


def _matching_transfer(data: evm_rpc.EvmReceiptData, token: str, recipient: str) -> dict[str, Any] | None:
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
        return {"amount_base_units": str(amount) if amount is not None else None, "log_index": log.get("logIndex")}
    return None


def _verify_btc(
    *,
    tx_hash: str,
    deposit_address: str,
    expected_amount: str | None,
    client: HttpClient,
) -> OriginVerification:
    report, data = btc_rpc.fetch_tx(tx_hash, client)
    if report.status is SourceStatus.NOT_FOUND:
        return OriginVerification(
            level=OriginVerdict.NOT_FOUND,
            chain="btc",
            tx_hash=tx_hash,
            summary=(
                "The claimed deposit transaction is not present on the Bitcoin chain. This is a "
                "missing record, not proof the transaction failed."
            ),
        )
    if report.status is not SourceStatus.OK or data is None:
        return OriginVerification(
            level=OriginVerdict.UNAVAILABLE,
            chain="btc",
            tx_hash=tx_hash,
            summary=(
                f"The Bitcoin chain could not be queried ({report.status.value}), so the deposit "
                "claim was not independently checked. This is a source-availability problem."
            ),
        )

    payouts = data.paying_outputs_by_script(deposit_address)
    checks: dict[str, Any] = {
        "confirmed": data.confirmed,
        "block_height": data.block_height,
        "paying_outputs": [{"value": o.value, "address": o.address} for o in payouts],
    }
    url = f"https://mempool.space/tx/{tx_hash}"
    if not payouts:
        return OriginVerification(
            level=OriginVerdict.CONTRADICTORY,
            chain="btc",
            tx_hash=tx_hash,
            summary=(
                "The transaction does not pay the deposit address, so it is not the claimed "
                "deposit."
            ),
            checks=checks,
            evidence_url=url,
        )
    observed = str(sum(o.value or 0 for o in payouts))
    checks["observed_amount_base_units"] = observed
    if not data.confirmed:
        return OriginVerification(
            level=OriginVerdict.UNCONFIRMED,
            chain="btc",
            tx_hash=tx_hash,
            summary=(
                "The transaction pays the deposit address but is not yet confirmed in a block. "
                "This is insufficient evidence, not a failure."
            ),
            checks=checks,
            evidence_url=url,
        )
    if expected_amount is not None and observed != str(expected_amount):
        checks["expected_amount_base_units"] = str(expected_amount)
        return OriginVerification(
            level=OriginVerdict.UNCONFIRMED,
            chain="btc",
            tx_hash=tx_hash,
            summary=(
                "The recipient and confirmation match, but the amount paid differs from the "
                "quote's expected input. The difference is disclosed, not reconciled."
            ),
            checks=checks,
            evidence_url=url,
        )
    return OriginVerification(
        level=OriginVerdict.VERIFIED,
        chain="btc",
        tx_hash=tx_hash,
        summary=(
            "Independently verified on the origin chain: a confirmed Bitcoin transaction pays the "
            "deposit address."
        ),
        checks=checks,
        evidence_url=url,
        limitations=("This verifies the origin leg only; it does not prove delivery.",),
    )
