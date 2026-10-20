"""Investigation orchestrator.

Turns an input identifier into a deterministic
:class:`~tracesettle.model.ReconciliationResult` by:

1. classifying and validating the identifier;
2. querying each applicable source through its adapter;
3. correlating further lookups **only** through explicit identifiers returned by
   an authoritative source (never by amount or timestamp);
4. normalizing everything into evidence items;
5. handing the evidence to the deterministic engine.

Partial failures are first-class: whatever evidence was collected is retained,
and the affected sources are reported as unavailable rather than turning into a
transaction-failure claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import config
from .adapters import evm_rpc, near_rpc, oneclick, solver_relay
from .assets import TokenCatalog, chain_of, contract_of
from .httpclient import HttpClient
from .identifiers import (
    classify_identifier,
    is_intent_hash,
    is_near_tx_hash,
    normalize,
    validate_deposit_address,
)
from .model import (
    EventType,
    EvidenceItem,
    IdentifierType,
    Provenance,
    SourceReport,
    SourceStatus,
    Stage,
    Verification,
)
from .reconcile import reconcile

#: 1Click statuses that assert an intent was created and can be verified on-chain.
_SETTLEMENT_STATUSES = frozenset({"SUCCESS", "PROCESSING", "REFUNDED", "FAILED"})


@dataclass
class Investigation:
    identifier: str
    identifier_type: IdentifierType
    source_reports: list[SourceReport] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Intent hashes this investigation is actually about. Populated from the 1Click
    #: status record (deposit-address path) or the identifier itself (intent-hash
    #: path). The engine requires settlement evidence to name one of these, so that
    #: an unrelated intent in the same NEAR transaction cannot confirm settlement.
    expected_intent_hashes: list[str] = field(default_factory=list)
    #: Origin-chain transaction hashes this investigation is about. Populated from the
    #: 1Click status record. The engine requires bridge-credit evidence to name one of
    #: these (via its BRIDGED_FROM memo) to confirm the bridge-deposit-credit stage.
    expected_origin_tx_hashes: list[str] = field(default_factory=list)

    @property
    def source_statuses(self) -> dict[str, SourceStatus]:
        # A source may be queried more than once; the worst outcome wins so the
        # engine never treats a partially unavailable source as fully healthy.
        out: dict[str, SourceStatus] = {}
        for report in self.source_reports:
            existing = out.get(report.source)
            if existing is None or _severity(report.status) > _severity(existing):
                out[report.source] = report.status
        return out



def _severity(status: SourceStatus) -> int:
    order = {
        SourceStatus.OK: 0,
        SourceStatus.NOT_FOUND: 1,
        SourceStatus.MALFORMED: 2,
        SourceStatus.UNSUPPORTED: 3,
        SourceStatus.UNAUTHORIZED: 4,
        SourceStatus.RATE_LIMITED: 5,
        SourceStatus.SERVER_ERROR: 6,
        SourceStatus.NETWORK_ERROR: 7,
        SourceStatus.TIMEOUT: 8,
    }
    return order.get(status, 9)


def investigate(
    raw_identifier: str,
    client: HttpClient,
    catalog: TokenCatalog | None = None,
    identifier_type: IdentifierType | None = None,
) -> Investigation:
    """Run a read-only investigation for one identifier."""
    identifier = normalize(raw_identifier)
    inv = Investigation(
        identifier=identifier,
        identifier_type=identifier_type or classify_identifier(identifier),
    )

    if not identifier:
        inv.notes.append("No identifier was provided.")
        return inv

    if inv.identifier_type is IdentifierType.DEPOSIT_ADDRESS:
        _investigate_by_deposit_address(inv, client, catalog)
    elif inv.identifier_type is IdentifierType.INTENT_HASH:
        _investigate_by_intent_hash(inv, client)
    elif inv.identifier_type is IdentifierType.ORIGIN_CHAIN_TX_HASH:
        inv.notes.append(
            "An origin-chain transaction hash cannot be used to look up a 1Click record: "
            "the 1Click status endpoint is keyed on the quote deposit address, and no reverse "
            "lookup from a transaction hash is documented. Supply the deposit address to "
            "investigate the full path."
        )
    else:
        # Ambiguous base58 identifiers: offer the intent-hash path and explain the boundary.
        if is_intent_hash(identifier) or is_near_tx_hash(identifier):
            inv.notes.append(
                "This identifier is a base58 hash. It is treated as an intent hash for the "
                "solver-relay lookup. If it is actually a NEAR transaction hash, that lookup "
                "will simply find no record."
            )
            inv.identifier_type = IdentifierType.INTENT_HASH
            _investigate_by_intent_hash(inv, client)
        else:
            inv.notes.append(
                "This identifier could not be classified as a supported deposit address or "
                "intent hash."
            )
    return inv


def _investigate_by_deposit_address(
    inv: Investigation, client: HttpClient, catalog: TokenCatalog | None
) -> None:
    ok, reason = validate_deposit_address(inv.identifier)
    if not ok:
        inv.notes.append(f"Invalid deposit address: {reason}.")
        return

    report, status = oneclick.investigate(inv.identifier, client)
    inv.source_reports.append(report)
    inv.evidence.extend(report.evidence)

    if status is None:
        return

    # The intent hashes this investigation is about, as reported by 1Click. The
    # engine requires on-chain settlement evidence to name one of these.
    inv.expected_intent_hashes = list(status.intent_hashes)
    # Likewise the origin-chain transaction hashes, used to gate bridge-credit
    # confirmation on the BRIDGED_FROM memo naming this deposit's origin tx.
    inv.expected_origin_tx_hashes = list(status.origin_chain_tx_hashes)

    if status.deposit_type and status.deposit_type != "ORIGIN_CHAIN":
        inv.notes.append(
            f"The quote used depositType '{status.deposit_type}'. This tool supports the "
            "ORIGIN_CHAIN flow; other deposit types are shown only as reported evidence."
        )

    origin_chain = chain_of(status.origin_asset)
    destination_chain = chain_of(status.destination_asset)

    # --- origin-chain transactions (deposit and/or refund) -------------------
    # A refund returns the asset to ``refundTo``; a deposit sends it to the
    # quote's ``depositAddress``. We attribute each origin-chain transaction by
    # comparing on-chain recipient addresses — an explicit identifier, never an
    # amount or timestamp.
    refund_candidates: list[evm_rpc.EvmReceiptData] = []
    if status.origin_chain_tx_hashes:
        if origin_chain and config.rpc_for_chain(origin_chain):
            for tx_hash in status.origin_chain_tx_hashes:
                report, data = evm_rpc.fetch_receipt(tx_hash, origin_chain, client, expected=None)
                inv.source_reports.append(report)
                if data is None:
                    # The receipt could not be retrieved; mark the source stage as
                    # unverifiable rather than missing or failed.
                    inv.evidence.append(
                        _unavailable(
                            f"ev-origin-unavailable-{tx_hash}",
                            Stage.SOURCE_CHAIN_DEPOSIT,
                            EventType.SOURCE_TX_INCLUDED,
                            "evm_rpc",
                            report.status.value,
                            tx_hash,
                            origin_chain,
                        )
                    )
                    continue
                role = _classify_origin(data, status.deposit_address, status.refund_to)
                if role == "refund":
                    refund_candidates.append(data)
                    inv.notes.append(
                        f"Origin-chain transaction {tx_hash} pays the quote's refund address, so it "
                        "is treated as a refund candidate rather than the deposit."
                    )
                elif role == "deposit":
                    inv.evidence.extend(report.evidence)
                else:
                    inv.notes.append(
                        f"Origin-chain transaction {tx_hash} pays neither the quote's deposit address "
                        "nor its refund address, so it could not be attributed to the deposit stage. "
                        "It is not counted as source-chain deposit evidence."
                    )
                    inv.evidence.append(
                        _unavailable(
                            f"ev-origin-unattributed-{tx_hash}",
                            Stage.SOURCE_CHAIN_DEPOSIT,
                            EventType.SOURCE_TX_INCLUDED,
                            "evm_rpc",
                            "NOT_ATTRIBUTABLE",
                            tx_hash,
                            origin_chain,
                        )
                    )
        else:
            inv.notes.append(
                f"The origin chain '{origin_chain or 'unknown'}' has no configured public RPC, "
                "so the source-chain deposit could not be independently verified. This is an "
                "unverified stage, not a failed transaction."
            )
            inv.evidence.append(
                _unavailable(
                    "ev-origin-chain-unsupported",
                    Stage.SOURCE_CHAIN_DEPOSIT,
                    EventType.SOURCE_TX_INCLUDED,
                    "evm_rpc",
                    "UNSUPPORTED_CHAIN",
                    None,
                    origin_chain,
                )
            )

    # --- refund verification -------------------------------------------------
    _verify_refund(inv, status, refund_candidates, origin_chain)

    # --- settlement (NEAR) ---------------------------------------------------
    settlement_verified = False
    for near_tx_hash in status.near_tx_hashes:
        report, _ = near_rpc.fetch_tx(near_tx_hash, client)
        inv.source_reports.append(report)
        inv.evidence.extend(report.evidence)
        if report.status is SourceStatus.OK:
            settlement_verified = True

    for intent_hash in status.intent_hashes:
        report, _ = solver_relay.investigate(intent_hash, client)
        inv.source_reports.append(report)
        inv.evidence.extend(report.evidence)
        if report.status is SourceStatus.OK:
            settlement_verified = True

    if (status.near_tx_hashes or status.intent_hashes) and not settlement_verified:
        inv.evidence.append(
            _unavailable(
                "ev-settlement-unavailable",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_INCLUDED,
                "near_rpc",
                "SOURCE_UNAVAILABLE",
                None,
                "near",
            )
        )

    # Confirm the specific intent hash appears in the NEAR logs. If the 1Click
    # status reported intent hashes but no NEAR tx carried them, add an explicit
    # source-issue marker rather than silently downgrading.
    _mark_missing_intent_correlation(inv, status)

    # --- destination delivery -------------------------------------------------
    if status.destination_chain_tx_hashes:
        if destination_chain and config.rpc_for_chain(destination_chain):
            expected = evm_rpc.ExpectedTransfer(
                token_contract=contract_of(status.destination_asset),
                recipient=status.recipient,
                amount_base_units=status.swap_details.get("amountOut")
                if isinstance(status.swap_details.get("amountOut"), str)
                else None,
            )
            for tx_hash in status.destination_chain_tx_hashes:
                report, _ = evm_rpc.fetch_receipt(
                    tx_hash, destination_chain, client, expected=expected
                )
                inv.source_reports.append(report)
                inv.evidence.extend(report.evidence)
                if report.status is not SourceStatus.OK:
                    inv.evidence.append(
                        _unavailable(
                            f"ev-destination-unavailable-{tx_hash}",
                            Stage.DESTINATION_CHAIN_DELIVERY,
                            EventType.DESTINATION_TX_INCLUDED,
                            "evm_rpc",
                            report.status.value,
                            tx_hash,
                            destination_chain,
                        )
                    )
        else:
            inv.notes.append(
                f"The destination chain '{destination_chain or 'unknown'}' has no configured "
                "public RPC, so destination delivery could not be independently verified. This "
                "is an unverified stage, not a failed transfer."
            )
            inv.evidence.append(
                _unavailable(
                    "ev-destination-chain-unsupported",
                    Stage.DESTINATION_CHAIN_DELIVERY,
                    EventType.DESTINATION_TX_INCLUDED,
                    "evm_rpc",
                    "UNSUPPORTED_CHAIN",
                    None,
                    destination_chain,
                )
            )


def _classify_origin(
    receipt: evm_rpc.EvmReceiptData, deposit_address: str | None, refund_to: str | None
) -> str:
    """Attribute an origin-chain transaction to deposit / refund / unknown.

    Attribution uses recipient addresses from the quote (explicit identifiers).
    A transaction that pays the deposit address is a deposit; one that pays the
    refund address is a refund. Anything else is 'unknown' and is not used to
    advance either stage.
    """
    to_addr = (receipt.to_address or "").lower()
    deposit = (deposit_address or "").lower()
    refund = (refund_to or "").lower()
    if refund and to_addr == refund:
        return "refund"
    if deposit and to_addr == deposit:
        return "deposit"
    return "unknown"


def _verify_refund(
    inv: Investigation,
    status: oneclick.OneClickStatusData,
    refund_candidates: list[evm_rpc.EvmReceiptData],
    origin_chain: str | None,
) -> None:
    """Confirm a reported refund only from an on-chain refund transaction."""
    reported = status.status == "REFUNDED" or _is_positive_decimal(status.refunded_amount)
    if not reported:
        return

    refund_to = status.refund_to
    origin_contract = contract_of(status.origin_asset)
    expected_amount = status.refunded_amount if _is_positive_decimal(status.refunded_amount) else None

    matched = False
    for receipt in refund_candidates:
        expectation = evm_rpc.ExpectedTransfer(
            token_contract=origin_contract, recipient=refund_to, amount_base_units=expected_amount
        )
        match = evm_rpc.match_expected_transfer(receipt, expectation)
        if match.matched:
            matched = True
            inv.evidence.append(
                EvidenceItem(
                    id=f"ev-refund-confirmed-{receipt.chain}-{receipt.tx_hash}",
                    stage=Stage.REFUND,
                    event_type=EventType.REFUND_TX_CONFIRMED,
                    source="evm_rpc",
                    verification=Verification.CONFIRMED,
                    provenance=Provenance.REAL,
                    tx_hash=receipt.tx_hash,
                    chain=receipt.chain,
                    reported_status="CONFIRMED",
                    evidence_url=config.explorer_url_for(receipt.chain, receipt.tx_hash),
                    details={"reason": match.reason, "match_details": match.details},
                    limitations=(
                        "Confirms a matching on-chain transfer to the refund address; it does not "
                        "establish the wider claim that all funds were returned.",
                    ),
                )
            )
            break

    if not matched:
        inv.notes.append(
            "1Click reports a refund, but no on-chain refund transaction could be located and "
            "verified for the origin chain. The refund therefore remains a reported claim, not a "
            "confirmed fact. This is not proof that the refund did not happen."
        )
        if not origin_chain or not config.rpc_for_chain(origin_chain):
            inv.notes.append(
                f"No public RPC is configured for origin chain '{origin_chain or 'unknown'}', so a "
                "refund transaction could not be searched for at all."
            )
            inv.evidence.append(
                _unavailable(
                    "ev-refund-unavailable",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    "evm_rpc",
                    "UNSUPPORTED_CHAIN",
                    None,
                    origin_chain,
                )
            )
        elif not refund_candidates and not any(
            r.source == "evm_rpc" and r.status is SourceStatus.OK for r in inv.source_reports
        ):
            # The origin chain has an RPC, but no receipt could be retrieved for the
            # reported origin transactions. The refund cannot be checked.
            inv.evidence.append(
                _unavailable(
                    "ev-refund-unavailable",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    "evm_rpc",
                    "SOURCE_UNAVAILABLE",
                    None,
                    origin_chain,
                )
            )


def _unavailable(
    evidence_id: str,
    stage: Stage,
    event_type: EventType,
    source: str,
    reason: str,
    tx_hash: str | None,
    chain: str | None,
) -> EvidenceItem:
    """An explicit marker that a stage could not be verified by its source."""
    return EvidenceItem(
        id=evidence_id,
        stage=stage,
        event_type=event_type,
        source=source,
        verification=Verification.UNAVAILABLE,
        provenance=Provenance.REAL,
        tx_hash=tx_hash,
        chain=chain,
        details={"reason": reason},
        limitations=(
            "This stage could not be independently verified. An unavailable source is not "
            "evidence that the stage failed.",
        ),
    )


def _is_positive_decimal(value: str | None) -> bool:
    if not value:
        return False
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def _fetch_evm_destination(
    inv: Investigation, client: HttpClient, tx_hash: str, chain: str, expected: evm_rpc.ExpectedTransfer
) -> None:
    report, _ = evm_rpc.fetch_receipt(tx_hash, chain, client, expected=expected)
    inv.source_reports.append(report)
    inv.evidence.extend(report.evidence)


def _mark_missing_intent_correlation(inv: Investigation, status: oneclick.OneClickStatusData) -> None:
    if not status.intent_hashes:
        return
    observed = {
        ih
        for item in inv.evidence
        for ih in (item.details.get("intent_hashes") or [])
        if item.details.get("standard") == "dip4"
    }
    if not observed:
        return
    missing = [ih for ih in status.intent_hashes if ih not in observed]
    if missing:
        inv.notes.append(
            "1Click reported intent hash(es) that were not found in the retrieved NEAR "
            f"transaction logs: {', '.join(missing)}. Settlement for those intents is not "
            "independently verified."
        )


def _investigate_by_intent_hash(inv: Investigation, client: HttpClient) -> None:
    if not (is_intent_hash(inv.identifier) or is_near_tx_hash(inv.identifier)):
        inv.notes.append("The identifier is not a valid base58 intent hash.")
        return

    inv.expected_intent_hashes = [inv.identifier]

    report, _ = solver_relay.investigate(inv.identifier, client)
    inv.source_reports.append(report)
    inv.evidence.extend(report.evidence)

    inv.notes.append(
        "The 1Click status record is keyed on the quote deposit address and offers no reverse "
        "lookup from an intent hash, so it could not be resolved from this identifier. Only the "
        "solver-relay view is available for an intent-hash investigation."
    )


def build_result(inv: Investigation):
    """Reconcile an investigation's collected evidence."""
    return reconcile(
        inv.evidence,
        inv.source_statuses,
        inv.expected_intent_hashes,
        inv.expected_origin_tx_hashes,
    )
