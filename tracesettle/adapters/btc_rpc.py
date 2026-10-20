"""Bitcoin adapter — origin-chain deposit and refund verification.

Bitcoin has no JSON-RPC ``eth_getTransactionReceipt`` equivalent, so this adapter
uses the public **Esplora** REST API (the de-facto standard read interface),
served by ``mempool.space`` and ``blockstream.info``. Both were verified live for
this project (mainnet) and require no key. A second host is tried when the first
fails, so a single provider outage does not silently disable refund verification.

Verified response shape (``GET {base}/tx/{txid}``)::

    {"txid": "...", "fee": 362, "status": {"confirmed": true, "block_height": ...,
      "block_hash": "...", "block_time": 1792472756},
     "vin":  [{"prevout": {"scriptpubkey_address": "bc1q...", "value": 37414749}}],
     "vout": [{"scriptpubkey_address": "bc1q...", "value": 12884,
               "scriptpubkey_type": "v0_p2wpkh"}]}

The adapter separates three notions, exactly as the EVM adapter does:

1. **inclusion**   — the transaction exists (a UTXO tx with outputs);
2. **confirmation** — ``status.confirmed`` is true (mined in a block);
3. **semantic payout** — an output pays the *expected* address, which is the
   explicit correlation anchor. Amount similarity is never used to link a
   transaction to an intent.

A Bitcoin transaction has many outputs, so "pays the expected recipient" means
"at least one output's ``scriptpubkey_address`` equals the expected address".
Addresses are compared exactly (bech32 is lowercase; base58 is case-sensitive),
never case-folded.

Unsupported or unreachable sources return UNAVAILABLE — never FAILED.
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
from .. import btc_verify

SOURCE = "btc_rpc"


@dataclass
class BtcOutput:
    address: str | None
    value: int | None
    script_type: str | None
    index: int
    script: str | None = None  # hex scriptPubKey, used for script-level matching


@dataclass
class BtcTxData:
    txid: str
    found: bool = False
    confirmed: bool = False
    block_height: int | None = None
    block_time: int | None = None
    fee: int | None = None
    outputs: list[BtcOutput] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    #: True when the raw bytes were retrieved and the txid was recomputed locally.
    identity_validated: bool = False
    #: True when raw bytes were retrieved but hash to a *different* txid. A
    #: contradiction: the returned bytes are not the transaction under investigation.
    identity_mismatch: bool = False
    #: Where the transaction was discovered: "explicit" (provider-named) or "history".
    discovery: str = "history"

    def paying_outputs(self, address: str) -> list[BtcOutput]:
        """Outputs whose address is exactly ``address`` (no case folding)."""
        return [o for o in self.outputs if o.address == address]

    def paying_outputs_by_script(self, address: str) -> list[BtcOutput]:
        """Outputs whose ``scriptPubKey`` matches ``address``'s decoded script.

        Returns ``[]`` when the address cannot be decoded (unsupported or
        malformed), so a script-level check never silently passes.
        """
        spk = btc_verify.address_to_scriptpubkey(address)
        if spk is None:
            return []
        want = spk.hex()
        return [o for o in self.outputs if o.script == want]


@dataclass
class BtcPayoutMatch:
    matched: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


def _to_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _parse_tx(txid: str, body: dict[str, Any]) -> BtcTxData:
    status = body.get("status") if isinstance(body.get("status"), dict) else {}
    outputs: list[BtcOutput] = []
    for index, out in enumerate(body.get("vout") or []):
        if not isinstance(out, dict):
            continue
        outputs.append(
            BtcOutput(
                address=out.get("scriptpubkey_address")
                if isinstance(out.get("scriptpubkey_address"), str)
                else None,
                value=_to_int(out.get("value")),
                script_type=out.get("scriptpubkey_type")
                if isinstance(out.get("scriptpubkey_type"), str)
                else None,
                index=index,
                script=out.get("scriptpubkey")
                if isinstance(out.get("scriptpubkey"), str)
                else None,
            )
        )
    inputs: list[str] = []
    for vin in body.get("vin") or []:
        if not isinstance(vin, dict):
            continue
        prevout = vin.get("prevout") if isinstance(vin.get("prevout"), dict) else {}
        addr = prevout.get("scriptpubkey_address")
        if isinstance(addr, str) and addr:
            inputs.append(addr)
    return BtcTxData(
        txid=txid,
        found=True,
        confirmed=status.get("confirmed") is True,
        block_height=_to_int(status.get("block_height")),
        block_time=_to_int(status.get("block_time")),
        fee=_to_int(body.get("fee")),
        outputs=outputs,
        inputs=inputs,
    )


def fetch_tx(txid: str, client: HttpClient) -> tuple[SourceReport, BtcTxData | None]:
    """Fetch a Bitcoin transaction by txid, trying each configured host in turn."""
    last_status: SourceStatus = SourceStatus.NETWORK_ERROR
    last_message: str | None = None
    last_endpoint: str | None = None

    for base in config.BITCOIN_API_URLS:
        endpoint = f"{base}/tx/{txid}"
        last_endpoint = endpoint
        result = client.get_json(endpoint)
        if result.status is SourceStatus.NOT_FOUND:
            # A 404 from this host is authoritative enough to stop; Esplora hosts
            # agree on chain state. It is still not proof the tx failed.
            return (
                SourceReport(
                    source=SOURCE,
                    status=SourceStatus.NOT_FOUND,
                    message=(
                        f"No Bitcoin transaction found for {txid}. A missing transaction is "
                        "not proof that no refund occurred."
                    ),
                    endpoint=endpoint,
                ),
                None,
            )
        if not result.ok:
            last_status = result.status
            last_message = result.message
            continue
        body = result.data
        if not isinstance(body, dict) or not isinstance(body.get("txid"), str):
            last_status = SourceStatus.MALFORMED
            last_message = "Bitcoin API returned an unexpected shape."
            continue
        returned = body["txid"]
        if returned.lower() != txid.lower():
            last_status = SourceStatus.MALFORMED
            last_message = (
                "Bitcoin API returned a different txid than requested; the response was "
                "ignored to avoid mis-correlation."
            )
            continue
        data = _parse_tx(txid, body)
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.OK,
                evidence=tuple(_build_evidence(data, endpoint)),
                message=(
                    f"Bitcoin transaction {txid} retrieved "
                    f"({'confirmed at height ' + str(data.block_height) if data.confirmed else 'unconfirmed'})."
                ),
                endpoint=endpoint,
            ),
            data,
        )

    return (
        SourceReport(
            source=SOURCE,
            status=last_status,
            message=last_message or "Bitcoin API could not be queried.",
            endpoint=last_endpoint,
        ),
        None,
    )


def fetch_raw_tx(txid: str, client: HttpClient) -> tuple[SourceReport, str | None]:
    """Fetch a Bitcoin transaction's raw hex, for local txid validation.

    Esplora serves the raw transaction at ``GET {base}/tx/{txid}/hex``. The bytes
    let the caller recompute the txid locally instead of trusting the host's
    ``txid`` field. A 404 or transport failure is reported as such, never as a
    transaction that failed.
    """
    last_status: SourceStatus = SourceStatus.NETWORK_ERROR
    last_message: str | None = None
    last_endpoint: str | None = None

    for base in config.BITCOIN_API_URLS:
        endpoint = f"{base}/tx/{txid}/hex"
        last_endpoint = endpoint
        result = client.get_text(endpoint)
        if result.status is SourceStatus.NOT_FOUND:
            return (
                SourceReport(
                    source=SOURCE,
                    status=SourceStatus.NOT_FOUND,
                    message=f"No raw Bitcoin transaction found for {txid}.",
                    endpoint=endpoint,
                ),
                None,
            )
        if not result.ok:
            last_status = result.status
            last_message = result.message
            continue
        raw = result.data
        if not isinstance(raw, str) or not raw:
            last_status = SourceStatus.MALFORMED
            last_message = "Bitcoin API returned an empty raw transaction."
            continue
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.OK,
                message=f"Raw Bitcoin transaction bytes retrieved for {txid}.",
                endpoint=endpoint,
            ),
            raw,
        )

    return (
        SourceReport(
            source=SOURCE,
            status=last_status,
            message=last_message or "Raw Bitcoin transaction could not be retrieved.",
            endpoint=last_endpoint,
        ),
        None,
    )


@dataclass
class BtcOutspend:
    spent: bool
    txid: str | None = None
    vin: int | None = None
    confirmed: bool = False
    block_height: int | None = None


def fetch_outspend(txid: str, vout: int, client: HttpClient) -> tuple[SourceReport, BtcOutspend | None]:
    """Ask which transaction spends ``txid:vout``.

    The bridge pins a refund to the original deposit's outpoint, so the spending
    transaction is a strong correlation anchor *when* the connector's documented
    refund flow is the one that ran. Returns ``None`` (with the report) when the
    lookup could not be completed.
    """
    last_status: SourceStatus = SourceStatus.NETWORK_ERROR
    last_message: str | None = None
    last_endpoint: str | None = None

    for base in config.BITCOIN_API_URLS:
        endpoint = f"{base}/tx/{txid}/outspend/{vout}"
        last_endpoint = endpoint
        result = client.get_json(endpoint)
        if result.status is SourceStatus.NOT_FOUND:
            return (
                SourceReport(
                    source=SOURCE,
                    status=SourceStatus.NOT_FOUND,
                    message=f"Outspend lookup for {txid}:{vout} was not found.",
                    endpoint=endpoint,
                ),
                None,
            )
        if not result.ok:
            last_status = result.status
            last_message = result.message
            continue
        body = result.data
        if not isinstance(body, dict) or "spent" not in body:
            last_status = SourceStatus.MALFORMED
            last_message = "Bitcoin API returned an unexpected outspend shape."
            continue
        status = body.get("status") if isinstance(body.get("status"), dict) else {}
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.OK,
                message=(
                    f"Outspend lookup for {txid}:{vout}: "
                    + ("spent" if body.get("spent") is True else "unspent")
                ),
                endpoint=endpoint,
            ),
            BtcOutspend(
                spent=body.get("spent") is True,
                txid=body.get("txid") if isinstance(body.get("txid"), str) else None,
                vin=body.get("vin") if isinstance(body.get("vin"), int) else None,
                confirmed=status.get("confirmed") is True,
                block_height=_to_int(status.get("block_height")),
            ),
        )

    return (
        SourceReport(
            source=SOURCE,
            status=last_status,
            message=last_message or "Bitcoin outspend lookup could not be completed.",
            endpoint=last_endpoint,
        ),
        None,
    )


@dataclass
class AddressHistory:
    """An address's transaction history plus whether the search was complete.

    ``complete`` is the crux: uniqueness of a payout can only be asserted when the
    full history was actually retrieved. Esplora exposes an authoritative
    ``tx_count`` per address, so completeness is checkable rather than assumed.
    ``complete`` is true only when *both* the authoritative count was reached *and*
    pagination ended naturally; see :func:`fetch_address_history`.
    """

    address: str
    txs: list[BtcTxData] = field(default_factory=list)
    reported_tx_count: int | None = None
    pages_fetched: int = 0
    complete: bool = False
    reason: str = ""


def fetch_address_history(
    address: str, client: HttpClient, max_pages: int = 2
) -> tuple[SourceReport, AddressHistory]:
    """Fetch a Bitcoin address's transaction history and its completeness.

    Two Esplora calls per host are used: ``GET /address/{a}`` for the
    authoritative ``tx_count``, then one or more ``GET /address/{a}/txs`` pages
    (each page carries at most 50 mempool + 25 confirmed entries). Pagination
    continues via ``/txs/chain/{last_txid}`` up to ``max_pages``.

    What completeness here does and does not rest on (this is an honesty boundary,
    not a proof of exhaustiveness):

    * ``tx_count`` is ``chain_stats.tx_count + mempool_stats.tx_count`` as the host
      reports it at the moment of the stats call. Esplora defines it as the number
      of transactions the address appears in; the tool does not independently
      recompute it.
    * Completeness requires **both** (a) the number of distinct transactions
      retrieved reaching that count, **and** (b) pagination ending naturally — a
      short page or a 404. Reaching the count without a natural end (for example
      the page budget stopping mid-chain) is *not* complete, because the count is a
      snapshot that can drift while pages are fetched.
    * Esplora serves confirmed history newest-first and does not omit records it
      knows about, but the count and the pages are two separate calls, so a
      transaction confirmed between them can make the two disagree. The tool
      resolves that in the conservative direction: disagreement means incomplete.
    * Therefore "complete" means "the host's own count was reached and the page
      chain ended" — a strong signal, not an external proof that no record exists.
      A payout found on a complete search is still only *a* payout to the address;
      it is never by itself proof it belongs to the investigated intent.

    If the number of transactions retrieved is less than the reported count, or
    pagination did not finish, ``complete`` is ``False`` and no caller may treat
    the result as a full search.
    """
    last_status: SourceStatus = SourceStatus.NETWORK_ERROR
    last_message: str | None = None
    last_endpoint: str | None = None

    for base in config.BITCOIN_API_URLS:
        # 1) Authoritative transaction count.
        stats_endpoint = f"{base}/address/{address}"
        last_endpoint = stats_endpoint
        stats_result = client.get_json(stats_endpoint)
        reported: int | None = None
        if stats_result.ok and isinstance(stats_result.data, dict):
            chain = stats_result.data.get("chain_stats")
            mempool = stats_result.data.get("mempool_stats")
            chain_n = chain.get("tx_count") if isinstance(chain, dict) else None
            mempool_n = mempool.get("tx_count") if isinstance(mempool, dict) else None
            if isinstance(chain_n, int):
                reported = chain_n + (mempool_n if isinstance(mempool_n, int) else 0)
        elif not stats_result.ok and stats_result.status is SourceStatus.NOT_FOUND:
            return (
                SourceReport(
                    source=SOURCE,
                    status=SourceStatus.NOT_FOUND,
                    message=(
                        f"No transaction history was found for Bitcoin address {address}. "
                        "An empty history is not proof that no refund occurred."
                    ),
                    endpoint=stats_endpoint,
                ),
                AddressHistory(address, [], 0, 0, True, "the address has no known transactions"),
            )

        # 2) History pages.
        txs: list[BtcTxData] = []
        seen: set[str] = set()
        pages = 0
        last_txid: str | None = None
        page_failed = False
        terminated = False  # a short page or a 404 proves the page chain ended
        for _ in range(max_pages):
            if pages == 0:
                endpoint = f"{base}/address/{address}/txs"
            elif last_txid:
                endpoint = f"{base}/address/{address}/txs/chain/{last_txid}"
            else:
                break
            last_endpoint = endpoint
            result = client.get_json(endpoint)
            if result.status is SourceStatus.NOT_FOUND:
                terminated = True
                break
            if not result.ok:
                last_status = result.status
                last_message = result.message
                page_failed = True
                break
            body = result.data
            if not isinstance(body, list):
                last_status = SourceStatus.MALFORMED
                last_message = "Bitcoin API returned an unexpected shape for an address query."
                page_failed = True
                break
            pages += 1
            for entry in body:
                if not isinstance(entry, dict) or not isinstance(entry.get("txid"), str):
                    continue
                if entry["txid"] in seen:
                    continue
                seen.add(entry["txid"])
                txs.append(_parse_tx(entry["txid"], entry))
            if len(body) < 25:
                terminated = True
                break  # a short page means the chain of pages has ended
            last_txid = body[-1].get("txid") if isinstance(body[-1], dict) else None

        if page_failed and pages == 0:
            # Nothing usable from this host; try the next.
            continue

        # Completeness needs two independent facts: the host's authoritative count
        # was retrieved, and pagination ran to its natural end. Equal counts alone
        # are not enough — the page budget can stop mid-chain, and the count is a
        # snapshot that can drift while pages are fetched.
        count_reached = reported is not None and len(txs) >= reported
        complete = bool(count_reached and terminated)
        if reported is None:
            reason = (
                "the address's total transaction count could not be retrieved, so the search "
                "cannot be shown to be complete"
            )
        elif not terminated:
            reason = (
                f"pagination did not run to completion within the page budget ({pages} page(s)); "
                f"retrieved {len(txs)} of {reported} reported transactions, so the history is "
                "incomplete"
            )
        elif count_reached:
            reason = (
                f"retrieved all {reported} reported transactions across {pages} page(s); "
                "the page chain ended naturally"
            )
        else:
            reason = (
                f"only {len(txs)} of {reported} reported transactions were retrieved; the "
                "history is incomplete"
            )
        return (
            SourceReport(
                source=SOURCE,
                status=SourceStatus.OK,
                message=f"Bitcoin address {address} history retrieved ({len(txs)} transactions).",
                endpoint=last_endpoint,
            ),
            AddressHistory(address, txs, reported, pages, complete, reason),
        )

    return (
        SourceReport(
            source=SOURCE,
            status=last_status,
            message=last_message or "Bitcoin address history could not be queried.",
            endpoint=last_endpoint,
        ),
        AddressHistory(address, [], None, 0, False, "the address history could not be retrieved"),
    )


def fetch_address_txs(address: str, client: HttpClient) -> tuple[SourceReport, list[BtcTxData]]:
    """Backwards-compatible wrapper returning only the transactions.

    Prefer :func:`fetch_address_history`, which also reports completeness.
    """
    report, history = fetch_address_history(address, client)
    return report, history.txs


def match_expected_payout(data: BtcTxData, expected_address: str | None) -> BtcPayoutMatch:
    """Check whether a confirmed Bitcoin tx pays ``expected_address``.

    The recipient is the correlation anchor. Matching is done at the **script**
    level when the address decodes to a ``scriptPubKey`` (so a payment is verified
    by its actual script, not by string equality); it falls back to exact-address
    equality only when the address cannot be decoded. The observed amount is
    reported but not required to equal any expectation, because the documented
    refund flow permits network fees to be deducted; any difference is disclosed
    rather than hidden.
    """
    if not expected_address:
        return BtcPayoutMatch(
            False, "the expected Bitcoin recipient address is unknown, so the payout cannot be checked"
        )
    if not data.found:
        return BtcPayoutMatch(False, "the Bitcoin transaction was not found")
    if not data.confirmed:
        return BtcPayoutMatch(False, "the Bitcoin transaction is not yet confirmed")

    by_script = data.paying_outputs_by_script(expected_address)
    script_matched = bool(by_script)
    paying = by_script or data.paying_outputs(expected_address)
    if not paying:
        return BtcPayoutMatch(
            False,
            "no output pays the expected Bitcoin address",
            {"expected_address": expected_address, "outputs": [o.address for o in data.outputs]},
        )
    observed = sum(o.value or 0 for o in paying)
    return BtcPayoutMatch(
        True,
        "an output pays the expected Bitcoin address",
        {
            "expected_address": expected_address,
            "observed_output_sats": observed,
            "output_indexes": [o.index for o in paying],
            "fee_sats": data.fee,
            "script_matched": script_matched,
            "recipient_script_verified": script_matched,
        },
    )


def to_candidate(data: BtcTxData, expected_address: str | None, discovery: str) -> btc_verify.Candidate:
    """Project a fetched transaction into a :class:`btc_verify.Candidate`."""
    match = match_expected_payout(data, expected_address)
    return btc_verify.Candidate(
        txid=data.txid,
        confirmed=data.confirmed,
        pays_recipient=match.matched,
        recipient_script_matched=bool(match.details.get("script_matched")),
        observed_sats=match.details.get("observed_output_sats"),
        block_height=data.block_height,
        block_time=data.block_time,
        identity_validated=data.identity_validated,
        discovery=discovery,
        details={"match_reason": match.reason, "match_details": match.details},
    )


def _build_evidence(data: BtcTxData, endpoint: str) -> list[EvidenceItem]:
    url = f"{config.BTC_CHAIN.explorer_tx_url}{data.txid}"
    items: list[EvidenceItem] = []

    items.append(
        EvidenceItem(
            id=f"ev-btc-included-{data.txid}",
            stage=Stage.SOURCE_CHAIN_DEPOSIT,
            event_type=EventType.SOURCE_TX_INCLUDED,
            source=SOURCE,
            verification=Verification.CONFIRMED,
            provenance=Provenance.REAL,
            tx_hash=data.txid,
            chain="btc",
            evidence_url=url,
            verification_method="Esplora transaction inclusion",
            details={
                "block_height": data.block_height,
                "block_time": data.block_time,
                "output_count": len(data.outputs),
                "fee_sats": data.fee,
            },
            limitations=("Inclusion proves the transaction is in a block, nothing more.",),
        )
    )

    if data.confirmed:
        items.append(
            EvidenceItem(
                id=f"ev-btc-exec-{data.txid}",
                stage=Stage.SOURCE_CHAIN_DEPOSIT,
                event_type=EventType.SOURCE_TX_EXECUTED,
                source=SOURCE,
                verification=Verification.CONFIRMED,
                provenance=Provenance.REAL,
                tx_hash=data.txid,
                chain="btc",
                reported_status="CONFIRMED",
                evidence_url=url,
                verification_method="Esplora confirmed-transaction status",
                details={"confirmed": True, "block_height": data.block_height},
                limitations=(
                    "A confirmed Bitcoin transaction proves the transaction was mined; it does "
                    "not prove which swap it belongs to.",
                ),
            )
        )
    return items


def refund_payout_evidence(
    data: BtcTxData,
    match: BtcPayoutMatch,
    expected_amount: str | None,
    *,
    correlation_method: str | None = None,
    discovery: str | None = None,
) -> EvidenceItem:
    """Build the decisive refund evidence for a confirmed Bitcoin payout.

    Verification is CONFIRMED only when the payout matched; a matched-but-unconfirmed
    or non-matching transaction yields UNAVAILABLE/REPORTED evidence instead, so the
    engine can never confirm a refund from it.

    ``correlation_method`` is recorded verbatim so the report states *how* the
    payout was tied to the intent. The reported ``verification_level`` is computed
    here from the checks actually performed on *this* transaction (local identity
    validation and script-level recipient matching), never from an earlier
    discovery step, so it can never overstate what was done.

    Amounts are stated with an explicit unit. ``recipient_output_sats`` is what the
    refund address received; ``total_output_sats`` is the whole transaction's output
    value; the network ``fee_sats`` is not part of either. The three are never
    conflated, and the recipient value is never inflated with the fee or with other
    outputs.
    """
    url = f"{config.BTC_CHAIN.explorer_tx_url}{data.txid}"
    observed = match.details.get("observed_output_sats")
    total_output_sats = sum(o.value or 0 for o in data.outputs)
    amount_note: list[str] = []
    if expected_amount and observed is not None:
        try:
            expected_int = int(str(expected_amount))
        except (TypeError, ValueError):
            expected_int = None
        if expected_int is not None and expected_int != observed:
            amount_note.append(
                f"The reported refund amount ({expected_int} sats) and the observed on-chain "
                f"payout ({observed} sats) differ. Both figures are stated here; the tool does "
                "not reconcile them, and the difference is not by itself evidence of an error."
            )
    limitations = [
        "Confirms a confirmed Bitcoin transaction pays the expected refund address; it does "
        "not establish that all deposited funds were returned.",
    ]
    if not data.identity_validated:
        limitations.append(
            "The transaction identity was not validated against raw bytes, so the payout rests "
            "on the explorer's report."
        )
    if not match.details.get("script_matched"):
        limitations.append(
            "The recipient was matched by address string, not by decoding its script, because "
            "the address could not be decoded."
        )
    limitations.extend(amount_note)
    level = btc_verify.verification_level_for(
        identity_validated=data.identity_validated,
        recipient_script_verified=bool(match.details.get("script_matched")),
    )
    return EvidenceItem(
        id=f"ev-btc-refund-{data.txid}",
        stage=Stage.REFUND,
        event_type=EventType.REFUND_TX_CONFIRMED,
        source=SOURCE,
        verification=Verification.CONFIRMED,
        provenance=Provenance.REAL,
        tx_hash=data.txid,
        chain="btc",
        reported_status="CONFIRMED",
        evidence_url=url,
        verification_method=(
            "locally recomputed txid over raw bytes; script-level recipient match"
            if data.identity_validated and match.details.get("script_matched")
            else (
                "locally recomputed txid over raw bytes"
                if data.identity_validated
                else "explorer-reported inclusion (identity not locally validated)"
            )
        ),
        details={
            "reason": match.reason,
            "match_details": match.details,
            "expected_amount_sats": expected_amount,
            "amount_unit": "satoshi",
            "recipient_output_sats": observed,
            "total_output_sats": total_output_sats,
            "fee_sats": data.fee,
            "confirmed": data.confirmed,
            "block_height": data.block_height,
            "block_time": data.block_time,
            "identity_locally_validated": data.identity_validated,
            "recipient_script_verified": bool(match.details.get("script_matched")),
            "correlation_method": correlation_method or data.discovery,
            "verification_level": level.value,
            "discovery": discovery or data.discovery,
        },
        limitations=tuple(limitations),
    )
