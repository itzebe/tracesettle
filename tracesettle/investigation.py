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
from typing import Any

from . import btc_verify, config
from .adapters import btc_rpc, evm_rpc, near_rpc, oneclick, solver_relay
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

    # --- settlement (NEAR) ---------------------------------------------------
    # Fetched first: the intent's on-chain withdrawal event names the destination
    # (or refund) recipient. That recipient is the explicit identifier used later
    # to correlate a chain payout to *this* intent, so it must be observed before
    # refund/delivery correlation runs.
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

    # --- origin-chain transactions (deposit and/or refund) -------------------
    # A refund returns the asset to ``refundTo``; a deposit sends it to the
    # quote's ``depositAddress``. We attribute each origin-chain transaction by
    # comparing on-chain recipient addresses — an explicit identifier, never an
    # amount or timestamp.
    refund_candidates: list = []
    if status.origin_chain_tx_hashes:
        if origin_chain and config.rpc_for_chain(origin_chain):
            for tx_hash in status.origin_chain_tx_hashes:
                report, data = _fetch_origin_receipt(origin_chain, tx_hash, client)
                inv.source_reports.append(report)
                if data is None:
                    # The receipt could not be retrieved; mark the source stage as
                    # unverifiable rather than missing or failed.
                    inv.evidence.append(
                        _unavailable(
                            f"ev-origin-unavailable-{tx_hash}",
                            Stage.SOURCE_CHAIN_DEPOSIT,
                            EventType.SOURCE_TX_INCLUDED,
                            _source_name(origin_chain),
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
                            _source_name(origin_chain),
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
                    _source_name(origin_chain),
                    "UNSUPPORTED_CHAIN",
                    None,
                    origin_chain,
                )
            )

    # --- refund verification -------------------------------------------------
    _verify_refund(inv, status, refund_candidates, origin_chain, client)

    # --- destination delivery -------------------------------------------------
    # Delivery verification is implemented for EVM destination chains, where the
    # expected asset transfer can be matched from the receipt logs. Other chains
    # are reported as unverified, never as a failed transfer.
    dest_rpc = config.rpc_for_chain(destination_chain) if destination_chain else None
    if status.destination_chain_tx_hashes:
        if destination_chain and dest_rpc is not None and dest_rpc.kind == "evm":
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
                "EVM RPC, so destination delivery could not be independently verified. This "
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


def _source_name(chain: str | None) -> str:
    """The adapter name that verifies a chain, for evidence attribution."""
    if chain == "btc":
        return btc_rpc.SOURCE
    return evm_rpc.SOURCE


def _fetch_origin_receipt(
    chain: str, tx_hash: str, client: HttpClient
) -> tuple[SourceReport, Any]:
    """Fetch an origin-chain transaction using the adapter for that chain.

    Bitcoin uses the Esplora REST adapter; EVM chains use the receipt adapter.
    Anything else has no configured source and must be reported as unsupported.
    """
    if chain == "btc":
        return btc_rpc.fetch_tx(tx_hash, client)
    return evm_rpc.fetch_receipt(tx_hash, chain, client, expected=None)


def _receipt_pays(receipt: Any, address: str | None) -> bool:
    """True when an origin-chain transaction pays ``address``.

    EVM: the top-level ``to`` equals the address. Bitcoin: any output's address
    equals the address. This is an exact-identifier comparison, never an amount.
    """
    if not address:
        return False
    if isinstance(receipt, btc_rpc.BtcTxData):
        return bool(receipt.paying_outputs(address))
    to_addr = (getattr(receipt, "to_address", None) or "").lower()
    return to_addr == address.lower()


def _classify_origin(receipt: Any, deposit_address: str | None, refund_to: str | None) -> str:
    """Attribute an origin-chain transaction to deposit / refund / unknown.

    Attribution uses recipient addresses from the quote (explicit identifiers).
    A transaction that pays the deposit address is a deposit; one that pays the
    refund address is a refund. Anything else is 'unknown' and is not used to
    advance either stage.
    """
    if _receipt_pays(receipt, refund_to):
        return "refund"
    if _receipt_pays(receipt, deposit_address):
        return "deposit"
    return "unknown"


def _intent_withdrawal_recipients(
    inv: Investigation, intent_hashes: list[str]
) -> set[str]:
    """Withdrawal recipients named on-chain for the investigated intents.

    ``intents.near`` emits a DIP-4 ``ft_withdraw`` event per executed intent whose
    ``msg`` names the on-chain recipient. This is the explicit link between the
    intent and the chain transaction that pays it, so a payout to a recipient that
    was never named for this intent must not be treated as a refund of it.
    """
    wanted = set(intent_hashes)
    recipients: set[str] = set()
    for item in inv.evidence:
        if item.event_type is not EventType.INTENT_WITHDRAWAL_OBSERVED:
            continue
        for withdrawal in item.details.get("withdrawals") or []:
            if not isinstance(withdrawal, dict):
                continue
            if withdrawal.get("intent_hash") in wanted and isinstance(
                withdrawal.get("recipient"), str
            ):
                recipients.add(withdrawal["recipient"])
    return recipients


def _btc_refund_recipient(expected: str | None, named_recipients: set[str]) -> tuple[str | None, str | None]:
    """Resolve the Bitcoin address a refund must pay, and why it is untrusted.

    The authoritative destination is the address recorded on-chain in the intent's
    withdrawal event. The quote's ``refundTo`` is only a client-stated hint and is
    never used as the sole anchor, because a payment to a client-supplied address
    cannot be tied to this intent. When the two disagree, no payout is correlated.
    """
    named_btc = sorted(r.split(":", 1)[1] for r in named_recipients if r.startswith("btc:"))
    if not named_btc:
        return None, (
            "the intent's on-chain withdrawal recipient was not observed, so no Bitcoin payout "
            "can be tied to this intent and the refund cannot be independently confirmed"
        )
    if expected and expected not in named_btc:
        return None, (
            "the quote's refund address does not match the withdrawal recipient recorded "
            "on-chain for this intent, so a payout to either address is not correlated to it"
        )
    return named_btc[0], None


def _verify_refund(
    inv: Investigation,
    status: oneclick.OneClickStatusData,
    refund_candidates: list,
    origin_chain: str | None,
    client: HttpClient,
) -> None:
    """Confirm a reported refund only from an independently checked chain payout.

    EVM origin chains are matched on an ERC-20 ``Transfer`` to the refund address.
    Bitcoin origin chains are matched on a *confirmed* transaction whose output
    pays the refund address. In both cases the recipient address is the correlation
    anchor; a payout that cannot be tied to the investigated intent stays reported.
    """
    reported = status.status == "REFUNDED" or _is_positive_decimal(status.refunded_amount)
    if not reported:
        return

    refund_to = status.refund_to
    expected_amount = status.refunded_amount if _is_positive_decimal(status.refunded_amount) else None
    source = _source_name(origin_chain)
    named_recipients = _intent_withdrawal_recipients(inv, status.intent_hashes)

    if origin_chain == "btc":
        _verify_refund_btc(
            inv, status, refund_candidates, refund_to, expected_amount, named_recipients, client
        )
        return

    # --- EVM origin chain ----------------------------------------------------
    origin_contract = contract_of(status.origin_asset)
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
                    source=evm_rpc.SOURCE,
                    verification=Verification.CONFIRMED,
                    provenance=Provenance.REAL,
                    tx_hash=receipt.tx_hash,
                    chain=receipt.chain,
                    reported_status="CONFIRMED",
                    evidence_url=config.explorer_url_for(receipt.chain, receipt.tx_hash),
                    verification_method="EVM receipt log decode against expected refund transfer",
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
                    source,
                    "UNSUPPORTED_CHAIN",
                    None,
                    origin_chain,
                )
            )
        elif not refund_candidates and not any(
            r.source == evm_rpc.SOURCE and r.status is SourceStatus.OK for r in inv.source_reports
        ):
            # The origin chain has an RPC, but no receipt could be retrieved for the
            # reported origin transactions. The refund cannot be checked.
            inv.evidence.append(
                _unavailable(
                    "ev-refund-unavailable",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    source,
                    "SOURCE_UNAVAILABLE",
                    None,
                    origin_chain,
                )
            )


def _verify_refund_btc(
    inv: Investigation,
    status: oneclick.OneClickStatusData,
    refund_candidates: list,
    refund_to: str | None,
    expected_amount: str | None,
    named_recipients: set[str],
    client: HttpClient,
) -> None:
    """Bitcoin refund verification, via the reusable :mod:`tracesettle.btc_verify` rules.

    Bitcoin refunds move through the bridge's connector/relayer flow, so the refund
    is a Bitcoin transaction paying the refund address. The provider exposes no
    refund transaction hash, so candidates come from (a) any origin-chain hashes it
    did expose and (b) the refund address's own history. Candidate *selection* —
    including the refusal to correlate on amount, timestamp, or mere uniqueness —
    is delegated to :func:`btc_verify.select_refund_candidate`; this function only
    gathers candidates, records their verification level, and translates the
    selection into evidence. Only a confirmed, correlated payout confirms REFUND.
    """
    expected_btc, untrusted_reason = _btc_refund_recipient(refund_to, named_recipients)
    if untrusted_reason:
        inv.notes.append(f"Refund correlation caveat: {untrusted_reason}.")

    if expected_btc is None:
        # Without the on-chain withdrawal recipient there is no correlation anchor,
        # so no payout can be tied to this intent. This is an explicit gap, not a
        # failed refund.
        inv.evidence.append(
            _unavailable(
                "ev-refund-unavailable",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                btc_rpc.SOURCE,
                "NO_ONCHAIN_REFUND_RECIPIENT",
                None,
                "btc",
            )
        )
        return

    by_txid: dict[str, btc_rpc.BtcTxData] = {}

    # --- Tier A: provider-named origin-chain transactions ---------------------
    # Validate any provider-named transaction that pays the refund address,
    # including its raw-byte identity, before it can be a candidate.
    explicit: list[btc_verify.Candidate] = []
    for data in refund_candidates:
        if not isinstance(data, btc_rpc.BtcTxData):
            continue
        data.discovery = "explicit"
        by_txid[data.txid] = data
        _maybe_validate_identity(data, client, inv)
        candidate = btc_rpc.to_candidate(data, expected_btc, "explicit")
        if candidate.pays_recipient:
            explicit.append(candidate)

    # --- Tier B/C/D: refund address history ----------------------------------
    history_candidates: list[btc_verify.Candidate] = []
    history_ok = False
    report, history = btc_rpc.fetch_address_history(expected_btc, client)
    inv.source_reports.append(report)
    history_ok = report.status is SourceStatus.OK
    if history_ok:
        inv.notes.append(f"Refund address history: {history.reason}.")
        for data in history.txs:
            data.discovery = "history"
            by_txid.setdefault(data.txid, data)
            candidate = btc_rpc.to_candidate(data, expected_btc, "history")
            if candidate.pays_recipient:
                history_candidates.append(candidate)

    selection = btc_verify.select_refund_candidate(
        explicit,
        history_candidates,
        history_complete=history.complete if history_ok else False,
    )

    if selection.selected is not None:
        chosen = selection.selected
        data = by_txid.get(chosen.txid)
        if data is None:
            # Should not happen: the candidate was projected from a fetched tx.
            report, data = btc_rpc.fetch_tx(chosen.txid, client)
            inv.source_reports.append(report)
        if data is None:
            inv.evidence.append(
                _unavailable(
                    "ev-refund-unavailable",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    btc_rpc.SOURCE,
                    "CANDIDATE_UNRETRIEVABLE",
                    chosen.txid,
                    "btc",
                )
            )
            return
        _maybe_validate_identity(data, client, inv)
        if data.identity_mismatch:
            # The bytes the source returned do not hash to the requested txid. The
            # source's report and the raw bytes contradict each other, so the payout
            # cannot be confirmed from it.
            inv.evidence.append(
                _contradiction(
                    "ev-refund-contradiction",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    btc_rpc.SOURCE,
                    "TXID_BYTES_MISMATCH",
                    chosen.txid,
                    "btc",
                    (
                        "The Bitcoin source reported a transaction, but the raw transaction "
                        "bytes it returned hash to a different txid. The report and the bytes "
                        "conflict, so the payout cannot be confirmed from this source."
                    ),
                )
            )
            return
        match = btc_rpc.match_expected_payout(data, expected_btc)
        inv.evidence.append(
            btc_rpc.refund_payout_evidence(
                data,
                match,
                expected_amount,
                correlation_method=selection.correlation_method,
                discovery=chosen.discovery,
            )
        )
        return

    if selection.tier is btc_verify.CandidateTier.AMBIGUOUS:
        if selection.reason.startswith("the provider named"):
            inv.notes.append(f"Refund correlation caveat: {selection.reason}.")
        else:
            txids = ", ".join(sorted(c.txid for c in history_candidates))
            inv.notes.append(
                f"Refund correlation caveat: {len(history_candidates)} confirmed Bitcoin "
                f"transactions pay the refund address ({txids}), and the provider named none of "
                "them. None can be tied to this intent by an explicit identifier, so the refund "
                "is not confirmed. This is a correlation gap, not a failed refund."
            )
        inv.evidence.append(
            _unavailable(
                "ev-refund-unavailable",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                btc_rpc.SOURCE,
                "AMBIGUOUS_REFUND_PAYOUT",
                None,
                "btc",
            )
        )
        return

    if selection.tier is btc_verify.CandidateTier.INCOMPLETE_SEARCH:
        if not history_ok:
            inv.notes.append(
                "1Click reports a refund, but the refund address history could not be retrieved "
                "from any Bitcoin source, so the refund transaction could not be checked. This is "
                "a source problem, not proof the refund failed."
            )
            inv.evidence.append(
                _unavailable(
                    "ev-refund-unavailable",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    btc_rpc.SOURCE,
                    "SOURCE_UNAVAILABLE",
                    None,
                    "btc",
                )
            )
        else:
            inv.notes.append(
                f"Refund correlation caveat: {selection.reason}. The refund is therefore not "
                "confirmed; this is a search-scope limitation, not a failed refund."
            )
            inv.evidence.append(
                _incomplete(
                    "ev-refund-incomplete",
                    Stage.REFUND,
                    EventType.REFUND_TX_CONFIRMED,
                    btc_rpc.SOURCE,
                    "INCOMPLETE_ADDRESS_HISTORY",
                    None,
                    "btc",
                )
            )
        return

    # --- Tier D: a complete search found no matching payout. ------------------
    # Reaching here means the address history was retrieved in full and no payout
    # matched, so the payout is absent from a complete search scope. The provider's
    # claim still stands on its own; it is simply not independently confirmed.
    inv.notes.append(
        "1Click reports a refund, but no confirmed Bitcoin transaction paying the refund "
        "address could be located. The refund therefore remains a reported claim, not a "
        "confirmed fact. This is not proof that the refund did not happen."
    )


def _maybe_validate_identity(data: btc_rpc.BtcTxData, client: HttpClient, inv: Investigation) -> None:
    """Attach locally-validated identity to a transaction, when the host serves it.

    Fetches the raw transaction and recomputes its txid. A mismatch marks the
    transaction as *not* identity-validated and records why; it never upgrades the
    evidence. Failure to retrieve the bytes is a limitation, not a contradiction.
    """
    if data.identity_validated:
        return
    report, raw = btc_rpc.fetch_raw_tx(data.txid, client)
    inv.source_reports.append(report)
    if raw is None:
        return
    identity = btc_verify.verify_tx_identity(raw, data.txid)
    data.identity_validated = identity.validated
    if identity.validated:
        return
    if identity.computed_txid:
        # The host returned bytes that hash to a different transaction. That is a
        # material contradiction: the bytes cannot be the transaction under
        # investigation, so this evidence must not be treated as confirmed.
        data.identity_mismatch = True
        inv.notes.append(
            f"Bitcoin transaction {data.txid} could not be identity-validated: {identity.reason}"
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
        verification_method="source query failed; no independent check possible",
        details={"reason": reason},
        limitations=(
            "This stage could not be independently verified. An unavailable source is not "
            "evidence that the stage failed.",
        ),
    )


def _incomplete(
    evidence_id: str,
    stage: Stage,
    event_type: EventType,
    source: str,
    reason: str,
    tx_hash: str | None,
    chain: str | None,
) -> EvidenceItem:
    """A marker that a required search could not be completed.

    Distinct from :func:`_unavailable`: the source answered, but the search was not
    exhaustive (for example a page budget or a drifting transaction count), so the
    evidence is insufficient rather than absent or unavailable.
    """
    return EvidenceItem(
        id=evidence_id,
        stage=stage,
        event_type=event_type,
        source=source,
        verification=Verification.INCOMPLETE,
        provenance=Provenance.REAL,
        tx_hash=tx_hash,
        chain=chain,
        verification_method="search not exhaustive; absence cannot be established",
        details={"reason": reason},
        limitations=(
            "A search that could not be completed is not evidence that the thing searched for "
            "is absent.",
        ),
    )


def _contradiction(
    evidence_id: str,
    stage: Stage,
    event_type: EventType,
    source: str,
    reason: str,
    tx_hash: str | None,
    chain: str | None,
    contradiction: str,
) -> EvidenceItem:
    """An explicit marker that independent evidence materially conflicts.

    Used when a source's own report and the bytes it served disagree, e.g. raw
    transaction bytes that do not hash to the requested txid.
    """
    return EvidenceItem(
        id=evidence_id,
        stage=stage,
        event_type=event_type,
        source=source,
        verification=Verification.CONTRADICTORY,
        provenance=Provenance.REAL,
        tx_hash=tx_hash,
        chain=chain,
        verification_method="independent evidence conflicts",
        details={"reason": reason, "contradiction": contradiction},
        limitations=(
            "Independent evidence conflicts here, so no confirmation can be drawn from it.",
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
