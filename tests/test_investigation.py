"""End-to-end investigation tests: identifier -> evidence -> engine -> report.

These drive the real orchestrator and adapters with a fake transport, using the
real Phase 1 fixtures plus clearly-labelled synthetic fixtures.
"""

from __future__ import annotations

import copy

from tracesettle.identifiers import classify_identifier, validate_deposit_address
from tracesettle.investigation import build_result, investigate
from tracesettle.model import (
    IdentifierType,
    OverallOutcome,
    Provenance,
    SourceStatus,
    Stage,
    StageState,
    Verification,
)
from tracesettle.report import build_report

from conftest import (
    ev as make_ev,
    FakeOpener,
    RAW_DIR,
    REAL_DEPOSIT_ADDRESS,
    REAL_INTENT_HASH,
    REAL_ORIGIN_TX,
    client_for,
    load_raw,
    load_synthetic,
)

CREATED_AT = "2026-10-19T22:00:00Z"


def _wire_full_success(opener: FakeOpener, status_payload=None) -> FakeOpener:
    """Wire every real fixture for the verified ETH -> USDC swap."""
    opener.json(
        "GET", "/v0/status", status_payload or load_raw("oneclick_status_SUCCESS.json")
    )
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), once=True)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    # NEAR RPC: first the intents tx (has the intent logs), then the bridge leg.
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"), once=True)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx_omft.json"))
    return opener


# --- Scenario 1: full successful investigation ------------------------------


def test_full_success_investigation(opener: FakeOpener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)

    assert inv.identifier_type is IdentifierType.DEPOSIT_ADDRESS
    assert result.outcome is OverallOutcome.SETTLED_VERIFIED
    assert result.last_confirmed_stage is Stage.DESTINATION_CHAIN_DELIVERY
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.CONFIRMED
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.CONFIRMED
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.CONFIRMED
    assert result.contradictions == ()

    # The bridge credit is confirmed from on-chain BRIDGED_FROM evidence, not just
    # the upstream report.
    assert result.stage(Stage.BRIDGE_DEPOSIT_CREDIT).state is StageState.CONFIRMED
    credit = [e for e in inv.evidence if e.stage is Stage.BRIDGE_DEPOSIT_CREDIT
              and e.verification is Verification.CONFIRMED]
    assert credit, "expected a confirmed on-chain bridge-credit evidence item"
    assert REAL_ORIGIN_TX in credit[0].details["bridged_from_origin_hashes"]

    # Correlation is via explicit identifiers only.
    intent_items = [
        e for e in inv.evidence if e.event_type.value == "INTENT_EVENT_OBSERVED"
    ]
    assert intent_items and REAL_INTENT_HASH in intent_items[0].details["intent_hashes"]


def test_bridge_credit_not_confirmed_when_origin_tx_differs(opener: FakeOpener):
    """If 1Click reports an origin tx the bridge memo does not name, no confirmation.

    The bridge stage must stay unconfirmed. The overall outcome may still be
    SETTLED_VERIFIED when settlement and delivery are independently confirmed, since
    an executed intent implies the deposit was credited; the point of this test is
    that the *stage* is not confirmed from an unrelated memo.
    """
    # Point 1Click at a different origin tx hash than the one in the BRIDGED_FROM memo.
    status = load_raw("oneclick_status_SUCCESS.json")
    status["swapDetails"]["originChainTxHashes"] = [
        {"hash": "0x" + "9" * 64, "explorerUrl": ""}
    ]
    _wire_full_success(opener, status_payload=status)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    stage = result.stage(Stage.BRIDGE_DEPOSIT_CREDIT)
    assert stage.state is not StageState.CONFIRMED
    assert "different origin" in stage.summary.lower()


def test_full_success_report_is_exportable(opener: FakeOpener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    report = build_report(inv, build_result(inv), CREATED_AT)

    data = report.to_dict()
    assert data["tool"]["read_only"] is True
    assert data["outcome"] == "SETTLED_VERIFIED"
    assert "cannot recover" in data["disclaimer"]
    assert data["evidence"]
    # Every evidence item has a classification and a source.
    for item in data["evidence"]:
        assert item["verification"] in {v.value for v in Verification}
        assert item["source"]
    # JSON and Markdown both render.
    assert "TRACESETTLE investigation report" in report.to_markdown()
    assert data["investigation_id"].startswith("ts-")


def test_report_contains_no_secrets(opener: FakeOpener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    report = build_report(inv, build_result(inv), CREATED_AT)
    blob = report.to_json().lower()
    # No credential material or credential-bearing field names. (The disclaimer may
    # legitimately *mention* private keys; that is a statement about behaviour, not
    # a leaked value.)
    for needle in ("x-api-key", "api_key", "api-key", "authorization", "bearer ", "secret_key", "private_key", "seed_phrase"):
        assert needle not in blob, f"report leaked '{needle}'"


# --- Scenario 2: failed intent with a verified refund -----------------------


def test_verified_refund_end_to_end(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_REFUNDED.json"))
    opener.json("POST", "ethereum-rpc", load_synthetic("evm_receipt_refund_verified.json"))
    inv = investigate("0xcccc000000000000000000000000000000000003", client_for(opener))
    result = build_result(inv)
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    assert result.safety["reported_refund_not_confirmed"] is True


# --- Scenario 3: reported refund that cannot be verified --------------------


def test_reported_refund_unverified_end_to_end(opener: FakeOpener):
    # 1Click reports a refund, but the origin receipt has no matching transfer.
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_REFUNDED.json"))
    origin = load_raw("evm_receipt_origin.json")
    origin["result"]["transactionHash"] = "0xaaaa000000000000000000000000000000000000000000000000000000000001"
    # Pay the refund address (0xaaaa...0001) so it is classified as a refund candidate,
    # but with no matching ERC-20 Transfer log, so it cannot be confirmed.
    origin["result"]["to"] = "0xaaaa000000000000000000000000000000000001"
    origin["result"]["logs"] = []
    opener.json("POST", "ethereum-rpc", origin)
    inv = investigate("0xcccc000000000000000000000000000000000003", client_for(opener))
    result = build_result(inv)
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    assert result.stage(Stage.REFUND).state is StageState.REPORTED
    assert any("refund" in n.lower() for n in inv.notes)


# --- Scenario 4: successful source, missing downstream ----------------------


def test_source_confirmed_missing_downstream(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"))
    # NEAR RPC and solver relay are unavailable.
    opener.timeout("POST", "rpc.fastnear")
    opener.timeout("POST", "solver-relay")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.CONFIRMED
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert result.safety["unavailable_rpc_is_not_failure"] is True


# --- Scenario 6: 1Click 404 -------------------------------------------------


def test_oneclick_404_end_to_end(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 404, b"{}")
    inv = investigate("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", client_for(opener))
    result = build_result(inv)
    assert result.outcome is OverallOutcome.NOT_FOUND
    assert "not proof" in result.summary.lower() or "not found" in result.summary.lower()


# --- Scenario 7: 1Click 401 -------------------------------------------------


def test_oneclick_401_end_to_end(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 401, b"{}")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert inv.source_statuses["oneclick_status"] is SourceStatus.UNAUTHORIZED
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert "unavailable" in result.summary.lower()


# --- Scenario 8: RPC unavailable -------------------------------------------


def test_all_sources_unavailable_does_not_claim_failure(opener: FakeOpener):
    opener.network_error("GET", "/v0/status")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.safety["unavailable_rpc_is_not_failure"] is True


# --- Scenario 9: destination exists but transfer unverifiable ---------------


def test_destination_exists_but_transfer_unverifiable(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), once=True)
    # Destination receipt succeeds but has no USDC transfer log to the recipient.
    dest = load_raw("evm_receipt_destination.json")
    dest["result"]["logs"] = []
    opener.json("POST", "ethereum-rpc", dest)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is not StageState.CONFIRMED
    assert result.outcome is OverallOutcome.DELIVERY_UNVERIFIED
    assert result.safety["no_missing_destination_is_failure"] is True


# --- Scenario 10: uncorrelatable identifier --------------------------------


def test_ambiguous_base58_hash_is_not_forced_into_a_wrong_path(opener: FakeOpener):
    # A 44-char base58 string is ambiguous between a NEAR tx hash and an intent hash.
    ambiguous = "1111111111111111111111111111111111111111111"
    assert classify_identifier(ambiguous) is IdentifierType.UNKNOWN
    opener.json("POST", "solver-relay", {"result": {"intent_hash": ambiguous, "status": "NOT_FOUND_OR_NOT_VALID"}})
    inv = investigate(ambiguous, client_for(opener))
    result = build_result(inv)
    assert any("base58" in n for n in inv.notes)
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED


def test_origin_tx_hash_cannot_be_reverse_looked_up(opener: FakeOpener):
    inv = investigate(REAL_ORIGIN_TX, client_for(opener))
    assert inv.identifier_type is IdentifierType.ORIGIN_CHAIN_TX_HASH
    assert any("reverse lookup" in n for n in inv.notes)
    assert inv.source_reports == []
    result = build_result(inv)
    assert result.outcome is OverallOutcome.UNKNOWN


# --- Intent-hash-only investigation ----------------------------------------


def test_intent_hash_only_uses_solver_relay_and_states_limitation(opener: FakeOpener):
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_INTENT_HASH, client_for(opener), identifier_type=IdentifierType.INTENT_HASH)
    result = build_result(inv)
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.REPORTED
    assert any("no reverse lookup" in n for n in inv.notes)


# --- Scenario 12: unsupported chain ----------------------------------------


def test_unsupported_destination_chain_is_unavailable(opener: FakeOpener):
    payload = load_raw("oneclick_status_SUCCESS.json")
    payload["quoteResponse"]["quoteRequest"]["destinationAsset"] = "nep141:doge-xyz.omft.near"
    opener.json("GET", "/v0/status", payload)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"))
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert any("no configured EVM RPC" in n for n in inv.notes)


# --- Scenario 11: malformed API response -----------------------------------


def test_malformed_status_response_end_to_end(opener: FakeOpener):
    opener.json("GET", "/v0/status", {"unexpected": True})
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert inv.source_statuses["oneclick_status"] is SourceStatus.MALFORMED
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED


# --- Scenario 14: simulated evidence is labelled ---------------------------


def test_simulated_evidence_marked_in_report(opener: FakeOpener):
    from tracesettle.model import EventType

    opener.http_error("GET", "/v0/status", 404, b"{}")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    inv.evidence.append(
        make_ev(
            "ev-sim",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TRANSFER_OBSERVED,
            Verification.SIMULATED,
            provenance=Provenance.SIMULATED,
        )
    )
    report = build_report(inv, build_result(inv), CREATED_AT)
    assert report.to_dict()["stages"]
    sim = [e for e in report.to_dict()["evidence"] if e["provenance"] == "SIMULATED"]
    assert sim and sim[0]["verification"] == "SIMULATED"
    # The engine must label the result as containing simulated evidence.
    assert "simulated" in report.to_dict()["summary"].lower()


# --- Invalid identifiers ----------------------------------------------------


def test_invalid_deposit_address_is_rejected():
    ok, reason = validate_deposit_address("0xnothex")
    assert not ok and reason


def test_empty_identifier():
    inv = investigate("", client_for(FakeOpener()))
    assert inv.notes and "No identifier" in inv.notes[0]
    assert build_result(inv).outcome is OverallOutcome.UNKNOWN


# --- Correlation safety -----------------------------------------------------


def test_origin_deposit_is_attributed_by_recipient_not_amount(opener: FakeOpener):
    """Attribution uses the deposit address, never the amount."""
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    # An origin receipt that pays an unrelated address must not count as the deposit.
    origin = load_raw("evm_receipt_origin.json")
    origin["result"]["to"] = "0x0000000000000000000000000000000000000099"
    opener.json("POST", "ethereum-rpc", origin)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is not StageState.CONFIRMED
    assert any("could not be attributed" in n for n in inv.notes)


# --- BTC refund: verified, unverified, and correlation safety ---------------

BTC_REFUND_DEPOSIT = "bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm"
BTC_REFUND_PAYS = "bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw"


def _wire_btc_address(opener: FakeOpener, address: str, txs: list, tx_count: int) -> None:
    """Wire an Esplora address lookup: the stats call and the history page.

    The ``/txs`` route is registered *before* the stats route because both URLs
    contain ``/address/<addr>``; the more specific needle must match first.
    """
    opener.json("GET", f"mempool.space/api/address/{address}/txs", txs)
    opener.json(
        "GET", f"mempool.space/api/address/{address}",
        {"chain_stats": {"tx_count": tx_count}, "mempool_stats": {"tx_count": 0}},
    )


def _wire_btc_refund(opener: FakeOpener) -> FakeOpener:
    """Wire the real BTC refund case: 1Click report + real NEAR + real BTC txs."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    # The two NEAR transactions are distinguished by their hashes in the request body.
    opener.json(
        "POST", "rpc.fastnear",
        load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear",
        load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    # Bitcoin lookups, keyed by txid in the URL (GET requests carry no body).
    # The raw-bytes route is keyed on the /hex suffix so it cannot shadow the plain
    # /tx route (route matching is substring-based).
    opener.raw(
        "GET",
        "377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f/hex",
        _raw_hex_bytes("btc_tx_refund.hex"),
    )
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    opener.json("GET", "mempool.space/api/tx/377b55", load_raw("btc_tx_refund.json"))
    # 1Click does not expose the refund transaction hash, so the refund payout is
    # discovered from the refund address's own confirmed history. The stats call
    # reports a total count so completeness can be established.
    _wire_btc_address(opener, BTC_REFUND_PAYS, [load_raw("btc_tx_refund.json")], tx_count=1)
    # The solver relay is a secondary settlement source; leave it unavailable here.
    opener.timeout("POST", "solver-relay")
    return opener


def _raw_hex_bytes(name: str) -> bytes:
    return (RAW_DIR / name).read_bytes()


def test_btc_refund_verified_end_to_end(opener: FakeOpener):
    """A reported BTC refund is independently confirmed from the on-chain payout."""
    _wire_btc_refund(opener)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    assert result.safety["reported_refund_not_confirmed"] is True
    assert result.safety["bitcoin_refund_requires_confirmed_payout"] is True
    # The decisive evidence names the real refund transaction and is confirmed.
    refund_items = [
        e for e in inv.evidence if e.event_type.value == "REFUND_TX_CONFIRMED"
    ]
    assert refund_items and refund_items[0].details["confirmed"] is True


def test_btc_refund_payout_to_wrong_address_is_not_confirmed(opener: FakeOpener):
    """A confirmed BTC tx that pays a different address must not confirm the refund."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    # Re-point the payout to an address the refund address never pays. Both the
    # address and its script must change: matching is script-level, so changing the
    # address string alone would (correctly) still match the same script.
    refund = load_raw("btc_tx_refund.json")
    refund["vout"][0]["scriptpubkey_address"] = BTC_REFUND_DEPOSIT
    refund["vout"][0]["scriptpubkey"] = "001490ece5c59554abddeb10ddbb9fec2e69617e27f5"
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    opener.json("GET", "mempool.space/api/tx/377b55", refund)
    _wire_btc_address(opener, BTC_REFUND_PAYS, [refund], tx_count=1)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert any("no confirmed Bitcoin transaction paying" in n for n in inv.notes)


def test_btc_refund_unavailable_source_is_not_failure(opener: FakeOpener):
    """When Bitcoin sources are down, the refund is UNAVAILABLE, never 'no refund'."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    # The origin-chain Bitcoin transactions cannot be retrieved from either host.
    opener.timeout("GET", "mempool.space/api/tx")
    opener.timeout("GET", "blockstream.info/api/tx")
    opener.timeout("GET", "mempool.space/api/address")
    opener.timeout("GET", "blockstream.info/api/address")
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.UNAVAILABLE
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    assert result.safety["reported_refund_not_confirmed"] is True


def test_btc_refund_without_onchain_recipient_stays_reported(opener: FakeOpener):
    """If the intent's on-chain withdrawal recipient is absent, no payout is correlated."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    # NEAR returns a transaction with no withdrawal event.
    settlement = load_raw("near_rpc_tx_btc_settlement.json")
    for outcome in settlement["result"].get("receipts_outcome") or []:
        logs = (outcome.get("outcome") or {}).get("logs")
        if logs is not None:
            outcome["outcome"]["logs"] = [l for l in logs if "ft_withdraw" not in l]
    opener.json(
        "POST", "rpc.fastnear", settlement,
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.timeout("POST", "solver-relay")
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert any("correlation caveat" in n.lower() for n in inv.notes)


def test_btc_refund_recipient_mismatch_is_not_correlated(opener: FakeOpener):
    """If the quote's refund address disagrees with the on-chain recipient, no correlation."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    settlement = load_raw("near_rpc_tx_btc_settlement.json")
    # Rewrite the on-chain withdrawal recipient to a different address than the quote's.
    for outcome in settlement["result"].get("receipts_outcome") or []:
        for i, log in enumerate((outcome.get("outcome") or {}).get("logs") or []):
            if "ft_withdraw" in log and BTC_REFUND_PAYS in log:
                outcome["outcome"]["logs"][i] = log.replace(
                    BTC_REFUND_PAYS, "bc1qotherunrelatedaddresszzzzzzzzzzzzzzzzzzz"
                )
    opener.json(
        "POST", "rpc.fastnear", settlement,
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    opener.timeout("POST", "solver-relay")
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert any("does not match the withdrawal recipient" in n for n in inv.notes)


def test_btc_refund_investigation_is_deterministic(opener: FakeOpener):
    """The same captured evidence must reconcile to the same result every time."""
    _wire_btc_refund(opener)
    first = build_result(investigate(BTC_REFUND_DEPOSIT, client_for(opener))).to_dict()

    second_opener = FakeOpener()
    _wire_btc_refund(second_opener)
    second = build_result(
        investigate(BTC_REFUND_DEPOSIT, client_for(second_opener))
    ).to_dict()

    assert first == second


def test_btc_refund_with_multiple_payouts_is_not_confirmed(opener: FakeOpener):
    """Several confirmed payouts to the refund address must not confirm the refund."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    refund = load_raw("btc_tx_refund.json")
    # A second confirmed transaction paying the same refund address. Only the
    # recipient address is a reliable anchor, so neither can be tied to this intent.
    other = copy.deepcopy(refund)
    other["txid"] = "f" * 64
    _wire_btc_address(opener, BTC_REFUND_PAYS, [refund, other], tx_count=2)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert any("None can be tied to this intent" in n for n in inv.notes)


def test_btc_refund_real_address_history_is_ambiguous(opener: FakeOpener):
    """The real refund address's history has several payouts; none may be confirmed.

    Captured from mempool.space for the refund address of a real BTC->TRON swap.
    Four confirmed transactions pay that address, and 1Click named none of them, so
    the refund must stay unconfirmed rather than guess a payout.
    """
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    _wire_btc_address(opener, BTC_REFUND_PAYS, load_raw("btc_address_history.json"), tx_count=7)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.UNAVAILABLE
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    assert result.safety["reported_refund_not_confirmed"] is True
    assert any("AMBIGUOUS_REFUND_PAYOUT" in str(e.details.get("reason")) for e in inv.evidence)


# --- BTC refund: independent verification strengthening ---------------------


def test_btc_refund_verified_reports_script_level_verification(opener: FakeOpener):
    """A confirmed refund must record how strongly it was verified."""
    _wire_btc_refund(opener)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    item = next(e for e in inv.evidence if e.event_type.value == "REFUND_TX_CONFIRMED")
    assert item.details["identity_locally_validated"] is True
    assert item.details["recipient_script_verified"] is True
    assert item.details["verification_level"] == "SCRIPT_VALIDATED"
    assert item.details["correlation_method"] == "on-chain withdrawal recipient address"


def test_btc_refund_txid_bytes_mismatch_is_contradictory(opener: FakeOpener):
    """If raw bytes do not hash to the claimed txid, the refund is contradictory.

    The engine must never confirm a payout whose returned bytes belong to a
    different transaction.
    """
    op = FakeOpener()
    _wire_btc_refund(op)
    # Replace the refund raw bytes with the *deposit* transaction's bytes: they
    # parse fine but hash to a different txid. The /hex route is inserted first so
    # it is matched before the plain /tx route (substring matching, in order).
    op._routes = [r for r in op._routes if "/hex" not in (r[1] or "")]
    op.raw_first(
        "GET",
        "377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f/hex",
        (RAW_DIR / "btc_tx_deposit.hex").read_bytes(),
    )
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(op))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.CONTRADICTORY
    assert result.outcome is OverallOutcome.CONTRADICTORY
    assert any("TXID_BYTES_MISMATCH" in str(e.details.get("reason")) for e in inv.evidence)


def test_btc_refund_incomplete_history_is_not_confirmed(opener: FakeOpener):
    """A single matching payout on an incomplete history must not confirm the refund."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    # One payout is visible, but the address reports far more transactions than were
    # returned, so uniqueness cannot be established.
    _wire_btc_address(opener, BTC_REFUND_PAYS, [load_raw("btc_tx_refund.json")], tx_count=99)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    # An incomplete search is *insufficient evidence*, not a source outage, so the
    # stage is UNKNOWN rather than UNAVAILABLE — but it is still never confirmed.
    assert result.stage(Stage.REFUND).state is StageState.UNKNOWN
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    incomplete = [e for e in inv.evidence if e.verification is Verification.INCOMPLETE]
    assert incomplete, "an incomplete search must be recorded as INCOMPLETE evidence"
    assert any("INCOMPLETE_ADDRESS_HISTORY" in str(e.details.get("reason")) for e in incomplete)


def test_btc_refund_explicit_named_hash_is_confirmed(opener: FakeOpener):
    """When the provider names the refund tx hash, it is confirmed via that anchor.

    Tier A: an explicit identifier outranks the address-history fallback, so no
    address lookup is required for correlation.
    """
    status = load_synthetic("oneclick_status_btc_REFUNDED.json")
    # The provider names the refund transaction among the origin-chain hashes.
    status["swapDetails"]["originChainTxHashes"] = [
        {"hash": "9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226", "explorerUrl": ""},
        {"hash": "377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f", "explorerUrl": ""},
    ]
    opener.json("GET", "/v0/status", status)
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    opener.json("GET", "mempool.space/api/tx/377b55", load_raw("btc_tx_refund.json"))
    _wire_btc_address(opener, BTC_REFUND_PAYS, [load_raw("btc_tx_refund.json")], tx_count=1)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    item = next(e for e in inv.evidence if e.event_type.value == "REFUND_TX_CONFIRMED")
    assert item.details["discovery"] == "explicit"


def test_btc_refund_missing_raw_bytes_is_a_limitation_not_a_contradiction(opener: FakeOpener):
    """Raw bytes being unavailable must not turn a valid payout into a contradiction.

    When the explorer's ``/hex`` endpoint fails but the transaction JSON is valid,
    the identity simply cannot be locally validated. The refund may still be
    confirmed from the explorer's report, with the weaker level recorded — the
    missing bytes are a limitation, never a contradiction.
    """
    _wire_btc_refund(opener)
    # Drop the raw-bytes route so the /hex fetch 404s for every host, while the
    # plain /tx JSON still answers.
    opener._routes = [r for r in opener._routes if "/hex" not in (r[1] or "")]
    opener.http_error("GET", "/hex", 404)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    item = next(e for e in inv.evidence if e.event_type.value == "REFUND_TX_CONFIRMED")
    assert item.details["identity_locally_validated"] is False
    # Script matched but identity not validated => level cannot exceed EXPLORER_REPORTED.
    assert item.details["verification_level"] == "EXPLORER_REPORTED"
    assert item.verification is Verification.CONFIRMED
    assert not any(e.verification is Verification.CONTRADICTORY for e in inv.evidence)


def test_btc_refund_report_states_verification_level_and_amount_unit(opener: FakeOpener):
    """The structured and Markdown reports must carry the level and amount semantics."""
    _wire_btc_refund(opener)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    report = build_report(inv, result, "2026-10-20T00:00:00Z")
    data = report.to_dict()
    refund_items = [
        e for e in data["evidence"] if e["event_type"] == "REFUND_TX_CONFIRMED"
    ]
    assert refund_items
    details = refund_items[0]["details"]
    assert details["verification_level"] == "SCRIPT_VALIDATED"
    assert details["amount_unit"] == "satoshi"
    assert details["recipient_output_sats"] == 12884
    assert details["total_output_sats"] > details["recipient_output_sats"]
    # The evidence item states *how* the level was reached, in the model field.
    assert refund_items[0]["verification_method"]
    # The Markdown report explains the evidence classes and the tool's limitations.
    md = report.to_markdown()
    assert "Class meanings" in md
    assert "does not prove block inclusion" in md
    # The Markdown evidence table carries the method column.
    assert "| Method |" in md
    # Structured and Markdown agree on the outcome.
    assert data["outcome"] in md


def test_btc_refund_unknown_state_appears_in_report(opener: FakeOpener):
    """An incomplete-search (UNKNOWN) refund stage must be visible in the report."""
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_btc_REFUNDED.json"))
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"),
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"),
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    opener.timeout("POST", "solver-relay")
    opener.json("GET", "mempool.space/api/tx/9a80de", load_raw("btc_tx_deposit.json"))
    _wire_btc_address(opener, BTC_REFUND_PAYS, [load_raw("btc_tx_refund.json")], tx_count=99)
    inv = investigate(BTC_REFUND_DEPOSIT, client_for(opener))
    result = build_result(inv)
    report = build_report(inv, result, "2026-10-20T00:00:00Z")
    data = report.to_dict()
    assert "REFUND" in data["unknown_stages"]
    assert data["outcome"] == "REFUND_REPORTED_UNVERIFIED"
    assert "insufficient evidence" in report.to_markdown()
