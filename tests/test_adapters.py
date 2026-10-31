"""Adapter tests: real fixtures, error handling, and schema validation.

These exercise the real adapter code with a fake transport, so parsing,
classification, and error mapping are genuinely tested.
"""

from __future__ import annotations

import urllib.parse

import pytest

from tracesettle import config
from tracesettle.adapters import btc_rpc, evm_rpc, near_rpc, oneclick, solver_relay
from tracesettle.assets import parse_asset_id
from tracesettle.model import (
    EventType,
    EvidenceItem,
    Provenance,
    SourceStatus,
    Stage,
    Verification,
)

from conftest import (
    FakeOpener,
    RAW_DIR,
    REAL_DEPOSIT_ADDRESS,
    REAL_DESTINATION_TX,
    REAL_INTENT_HASH,
    REAL_NEAR_TX,
    REAL_NEAR_TX_BRIDGE,
    REAL_ORIGIN_TX,
    client_for,
    load_raw,
)


# --- 1Click status ----------------------------------------------------------


def test_oneclick_status_success_real_fixture(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    report, data = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data is not None
    assert data.status == "SUCCESS"
    assert data.intent_hashes == [REAL_INTENT_HASH]
    assert len(data.near_tx_hashes) == 2
    assert data.origin_chain_tx_hashes == [REAL_ORIGIN_TX]
    assert data.destination_chain_tx_hashes == [REAL_DESTINATION_TX]
    # Every 1Click item is REPORTED, never CONFIRMED.
    assert all(item.verification is Verification.REPORTED for item in report.evidence)
    # Empty explorer URLs must not break parsing.
    assert data.destination_chain_tx_hashes


def test_oneclick_status_pending_deposit_real_fixture(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_PENDING_DEPOSIT.json"))
    report, data = oneclick.investigate("0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B", client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.status == "PENDING_DEPOSIT"
    # Null amounts and empty hash lists are handled.
    assert data.near_tx_hashes == []
    assert data.intent_hashes == []


def test_oneclick_404_is_not_found_not_failure(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 404, b'{"message":"Deposit address not found"}')
    report, data = oneclick.investigate("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", client_for(opener))
    assert report.status is SourceStatus.NOT_FOUND
    assert data is None
    assert "not evidence that the swap failed" in report.message


def test_oneclick_401_marks_source_unavailable(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 401, b'{"message":"Unauthorized"}')
    report, data = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.UNAUTHORIZED
    assert data is None
    assert "authentication may have become mandatory" in report.message.lower()


def test_oneclick_429_is_rate_limited(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 429, b"{}")
    report, _ = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.RATE_LIMITED


def test_oneclick_500_is_server_error(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 500, b"{}")
    report, _ = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.SERVER_ERROR


def test_oneclick_malformed_json(opener: FakeOpener):
    opener.raw("GET", "/v0/status", b"<html>not json</html>", status=200)
    report, _ = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.MALFORMED


def test_oneclick_missing_status_field_is_malformed(opener: FakeOpener):
    opener.json("GET", "/v0/status", {"swapDetails": {}})
    report, data = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.MALFORMED
    assert data is None


def test_oneclick_timeout(opener: FakeOpener):
    opener.timeout("GET", "/v0/status")
    report, _ = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.TIMEOUT


def test_oneclick_network_error(opener: FakeOpener):
    opener.network_error("GET", "/v0/status")
    report, _ = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.NETWORK_ERROR


def test_oneclick_retries_on_500_then_succeeds():
    opener = FakeOpener()
    opener.http_error("GET", "/v0/status", 500, b"{}", once=True)
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    report, data = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener, attempts=2))
    assert report.status is SourceStatus.OK
    assert data is not None
    assert len(opener.calls) == 2


def test_oneclick_does_not_retry_404():
    opener = FakeOpener()
    opener.http_error("GET", "/v0/status", 404, b"{}")
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    report, _ = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener, attempts=3))
    assert report.status is SourceStatus.NOT_FOUND
    assert len(opener.calls) == 1


# --- Solver relay -----------------------------------------------------------


def test_solver_relay_settled_real_fixture(opener: FakeOpener):
    opener.json("POST", "/rpc", load_raw("solver_relay_get_status_SETTLED.json"))
    report, data = solver_relay.investigate(REAL_INTENT_HASH, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.status == "SETTLED"
    assert data.near_tx_hash == REAL_NEAR_TX
    assert all(item.verification is Verification.REPORTED for item in report.evidence)


def test_solver_relay_not_found_is_not_failure(opener: FakeOpener):
    opener.json(
        "POST",
        "/rpc",
        {"result": {"intent_hash": REAL_INTENT_HASH, "status": "NOT_FOUND_OR_NOT_VALID"}, "id": 1},
    )
    report, data = solver_relay.investigate(REAL_INTENT_HASH, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.status == "NOT_FOUND_OR_NOT_VALID"
    assert any("not proof that the intent failed" in lim for item in report.evidence for lim in item.limitations)


def test_solver_relay_rejects_mismatched_intent_hash(opener: FakeOpener):
    opener.json(
        "POST",
        "/rpc",
        {"result": {"intent_hash": "someOtherHash0000000000000000000000000000000", "status": "SETTLED"}},
    )
    report, data = solver_relay.investigate(REAL_INTENT_HASH, client_for(opener))
    assert report.status is SourceStatus.MALFORMED
    assert data is None


def test_solver_relay_handles_jsonrpc_error(opener: FakeOpener):
    opener.json("POST", "/rpc", {"error": {"code": -32602, "message": "Invalid params"}})
    report, data = solver_relay.investigate(REAL_INTENT_HASH, client_for(opener))
    assert report.status is SourceStatus.MALFORMED
    assert "Invalid params" in report.message


# --- NEAR RPC ---------------------------------------------------------------


def test_near_rpc_finds_intent_hash_in_logs(opener: FakeOpener):
    opener.json("POST", "/", load_raw("near_rpc_tx.json"))
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.final_execution_status == "FINAL"
    assert REAL_INTENT_HASH in data.found_intent_hashes
    events = {item.event_type.value for item in report.evidence}
    assert "INTENT_EVENT_OBSERVED" in events
    assert "NEAR_TX_FINAL" in events


def test_near_rpc_inclusion_alone_is_confirmed_but_not_semantic(opener: FakeOpener):
    """A NEAR tx with no matching intent log must not confirm settlement."""
    payload = load_raw("near_rpc_tx.json")
    # Strip the intent-hash logs to simulate an unrelated successful transaction.
    for receipt in payload["result"]["receipts_outcome"]:
        receipt["outcome"]["logs"] = []
    opener.json("POST", "/", payload)
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.found_intent_hashes == []
    assert not any(item.event_type.value == "INTENT_EVENT_OBSERVED" for item in report.evidence)


def test_near_rpc_not_found(opener: FakeOpener):
    opener.json("POST", "/", {"jsonrpc": "2.0", "error": {"message": "Unknown transaction"}})
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert report.status is SourceStatus.NOT_FOUND
    assert data is None


def test_near_rpc_unavailable_short_circuits(opener: FakeOpener):
    opener.timeout("POST", "/")
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert report.status is SourceStatus.TIMEOUT
    assert data is None


def test_near_rpc_bridge_leg_yields_confirmed_deposit_credit(opener: FakeOpener):
    """The bridge mint leg carries a BRIDGED_FROM memo naming the origin tx."""
    opener.json("POST", "/", load_raw("near_rpc_tx_omft.json"))
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX_BRIDGE, client_for(opener))
    assert report.status is SourceStatus.OK
    assert REAL_ORIGIN_TX in data.bridged_from_origin_hashes
    credit = [i for i in report.evidence if i.event_type.value == "DEPOSIT_OBSERVED"]
    assert credit, "expected a bridge deposit-credit evidence item"
    assert credit[0].stage.value == "BRIDGE_DEPOSIT_CREDIT"
    assert credit[0].verification is Verification.CONFIRMED
    assert REAL_ORIGIN_TX in credit[0].details["bridged_from_origin_hashes"]
    # The limitation must be a tuple of whole strings. A bare string here would be
    # serialized character by character, so the guard checks both the type and the
    # rendered shape.
    assert isinstance(credit[0].limitations, tuple)
    assert all(isinstance(s, str) and len(s) > 20 for s in credit[0].limitations)
    assert all(len(s) > 20 for s in credit[0].to_dict()["limitations"])


def test_evidence_item_coerces_bare_string_limitations():
    """A bare-string limitation is normalized, never split into characters."""
    item = EvidenceItem(
        id="ev-x",
        stage=Stage.NEAR_SETTLEMENT,
        event_type=EventType.INTENT_EVENT_OBSERVED,
        source="test",
        verification=Verification.CONFIRMED,
        provenance=Provenance.REAL,
        limitations="one whole limitation",
    )
    assert item.limitations == ("one whole limitation",)
    assert item.to_dict()["limitations"] == ["one whole limitation"]


def test_near_rpc_settlement_leg_yields_no_bridge_credit(opener: FakeOpener):
    """The settlement leg has no BRIDGED_FROM memo, so it must not claim a credit."""
    opener.json("POST", "/", load_raw("near_rpc_tx.json"))
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert data.bridged_from_origin_hashes == []
    assert not any(i.event_type.value == "DEPOSIT_OBSERVED" for i in report.evidence)


def test_near_rpc_malformed_bridged_from_memo_is_ignored(opener: FakeOpener):
    """A malformed BRIDGED_FROM memo must not crash or fabricate a hash."""
    payload = load_raw("near_rpc_tx_omft.json")
    for receipt in payload["result"]["receipts_outcome"]:
        logs = receipt["outcome"].get("logs") or []
        receipt["outcome"]["logs"] = [
            'EVENT_JSON:{"standard":"nep141","event":"ft_transfer","data":[{"memo":"BRIDGED_FROM:{not json"}]}'
            if "BRIDGED_FROM" in log
            else log
            for log in logs
        ]
    opener.json("POST", "/", payload)
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX_BRIDGE, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.bridged_from_origin_hashes == []


# --- EVM RPC ----------------------------------------------------------------


def test_evm_origin_receipt_real_fixture(opener: FakeOpener):
    opener.json("POST", "/", load_raw("evm_receipt_origin.json"))
    report, data = evm_rpc.fetch_receipt(REAL_ORIGIN_TX, "eth", client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.executed_successfully
    assert all(item.verification is Verification.CONFIRMED for item in report.evidence)


def test_evm_destination_transfer_verified_real_fixture(opener: FakeOpener):
    opener.json("POST", "/", load_raw("evm_receipt_destination.json"))
    expected = evm_rpc.ExpectedTransfer(
        token_contract="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        recipient="0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
        amount_base_units="347350080510",
    )
    report, data = evm_rpc.fetch_receipt(REAL_DESTINATION_TX, "eth", client_for(opener), expected=expected)
    assert report.status is SourceStatus.OK
    transfer = [i for i in report.evidence if i.event_type.value == "DESTINATION_TRANSFER_OBSERVED"]
    assert transfer, "expected a transfer observation"
    assert transfer[0].verification is Verification.CONFIRMED
    assert transfer[0].details["match"] is True


def test_evm_successful_receipt_without_matching_transfer_is_not_confirmed(opener: FakeOpener):
    """Scenario 13: a successful receipt that does not establish the expected transfer."""
    opener.json("POST", "/", load_raw("evm_receipt_destination.json"))
    expected = evm_rpc.ExpectedTransfer(
        token_contract="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        recipient="0x000000000000000000000000000000000000dead",  # wrong recipient
        amount_base_units="347350080510",
    )
    report, _ = evm_rpc.fetch_receipt(REAL_DESTINATION_TX, "eth", client_for(opener), expected=expected)
    transfer = [i for i in report.evidence if i.event_type.value == "DESTINATION_TRANSFER_OBSERVED"]
    assert transfer
    assert transfer[0].verification is Verification.UNAVAILABLE
    assert "not evidence that the transfer failed" in " ".join(transfer[0].limitations)


def test_evm_unsupported_chain_is_unavailable_not_failed(opener: FakeOpener):
    report, data = evm_rpc.fetch_receipt("0xabc", "doge", client_for(opener))
    assert report.status is SourceStatus.UNSUPPORTED
    assert data is None
    assert "not a failed transfer" in report.message


def test_evm_null_receipt_is_not_found(opener: FakeOpener):
    opener.json("POST", "/", {"jsonrpc": "2.0", "id": 1, "result": None})
    report, data = evm_rpc.fetch_receipt(REAL_DESTINATION_TX, "eth", client_for(opener))
    assert report.status is SourceStatus.NOT_FOUND
    assert "not proof the transaction failed" in report.message


def test_evm_mismatched_tx_hash_is_rejected(opener: FakeOpener):
    payload = load_raw("evm_receipt_destination.json")
    payload["result"]["transactionHash"] = "0x" + "11" * 32
    opener.json("POST", "/", payload)
    report, data = evm_rpc.fetch_receipt(REAL_DESTINATION_TX, "eth", client_for(opener))
    assert report.status is SourceStatus.MALFORMED
    assert data is None


def test_evm_reverted_receipt_is_confirmed_revert(opener: FakeOpener):
    payload = load_raw("evm_receipt_origin.json")
    payload["result"]["status"] = "0x0"
    opener.json("POST", "/", payload)
    report, data = evm_rpc.fetch_receipt(REAL_ORIGIN_TX, "eth", client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.executed_successfully is False
    exec_items = [i for i in report.evidence if i.event_type.value == "SOURCE_TX_EXECUTED"]
    assert exec_items[0].reported_status == "REVERTED"


# --- Bitcoin (Esplora) adapter ---------------------------------------------

BTC_REFUND_TXID = "377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f"
BTC_DEPOSIT_TXID = "9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226"
#: The address the real refund transaction actually pays.
BTC_REFUND_PAYS = "bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw"
#: The swap's BTC deposit address, which the refund transaction does NOT pay.
BTC_DEPOSIT_ADDRESS = "bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm"


def test_btc_fetch_tx_real_refund_fixture(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_tx_refund.json"))
    report, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data is not None
    assert data.txid == BTC_REFUND_TXID
    assert data.confirmed is True
    assert data.block_height == 972263


def test_btc_payout_match_requires_exact_address(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_tx_refund.json"))
    _, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    assert btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS).matched is True
    # The deposit address is not paid by the refund transaction, so it must not match.
    assert btc_rpc.match_expected_payout(data, BTC_DEPOSIT_ADDRESS).matched is False


def test_btc_unconfirmed_payout_never_matches():
    unconfirmed = btc_rpc.BtcTxData(
        txid="x", found=True, confirmed=False,
        outputs=[btc_rpc.BtcOutput(address=BTC_REFUND_PAYS, value=12884, script_type="v0_p2wpkh", index=0)],
    )
    match = btc_rpc.match_expected_payout(unconfirmed, BTC_REFUND_PAYS)
    assert match.matched is False
    assert "not yet confirmed" in match.reason


def test_btc_missing_address_is_not_a_match():
    data = btc_rpc.BtcTxData(txid="x", found=True, confirmed=True, outputs=[])
    match = btc_rpc.match_expected_payout(data, None)
    assert match.matched is False
    assert "unknown" in match.reason


def test_btc_not_found_is_not_failure(opener: FakeOpener):
    opener.http_error("GET", "mempool.space/api/tx", 404)
    report, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.NOT_FOUND
    assert data is None
    assert "not proof that no refund occurred" in report.message


def test_btc_falls_back_to_second_host(opener: FakeOpener):
    opener.network_error("GET", "mempool.space/api/tx")
    opener.json("GET", "blockstream.info/api/tx", load_raw("btc_tx_refund.json"))
    report, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data is not None
    assert "blockstream.info" in (report.endpoint or "")


def test_btc_both_hosts_down_is_unavailable(opener: FakeOpener):
    opener.timeout("GET", "mempool.space/api/tx")
    opener.timeout("GET", "blockstream.info/api/tx")
    report, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.TIMEOUT
    assert data is None


def test_btc_mismatched_txid_is_rejected(opener: FakeOpener):
    payload = load_raw("btc_tx_refund.json")
    payload["txid"] = "0" * 64
    opener.json("GET", "mempool.space/api/tx", payload)
    # The adapter falls through to the fallback host; register the same bad shape
    # there so both hosts are exhausted and the result is MALFORMED.
    opener.json("GET", "blockstream.info/api/tx", payload)
    report, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.MALFORMED
    assert data is None


def test_btc_address_history_lookup(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/address", [load_raw("btc_tx_refund.json")])
    report, txs = btc_rpc.fetch_address_txs(BTC_REFUND_PAYS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert len(txs) == 1
    assert txs[0].txid == BTC_REFUND_TXID


def test_btc_refund_evidence_requires_confirmed(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_tx_refund.json"))
    _, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    item = btc_rpc.refund_payout_evidence(data, match, "11746")
    assert item.verification is Verification.CONFIRMED
    assert item.details["confirmed"] is True
    # Amounts carry an explicit unit; the recipient's output is distinguished from
    # the transaction's total output value and the network fee.
    assert item.details["amount_unit"] == "satoshi"
    assert item.details["recipient_output_sats"] == 12884
    assert item.details["total_output_sats"] == 12884 + 37401503
    assert item.details["total_output_sats"] != item.details["recipient_output_sats"]
    # Identity was not validated here (no raw bytes fetched), so the level must be
    # EXPLORER_REPORTED, never SCRIPT_VALIDATED, despite the script matching.
    assert item.details["verification_level"] == "EXPLORER_REPORTED"


def test_btc_raw_tx_retrieval_returns_hex(opener: FakeOpener):
    opener.raw(
        "GET", f"mempool.space/api/tx/{BTC_REFUND_TXID}/hex",
        (RAW_DIR / "btc_tx_refund.hex").read_bytes(),
    )
    report, raw = btc_rpc.fetch_raw_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.OK
    assert raw is not None and raw.startswith("02000000")


def test_btc_raw_tx_not_found_is_not_failure(opener: FakeOpener):
    opener.http_error("GET", "mempool.space/api/tx", 404)
    report, raw = btc_rpc.fetch_raw_tx(BTC_REFUND_TXID, client_for(opener))
    assert report.status is SourceStatus.NOT_FOUND
    assert raw is None


def test_btc_outspend_reports_spending_transaction(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_outspend_deposit_vout0.json"))
    report, outspend = btc_rpc.fetch_outspend(BTC_REFUND_TXID, 0, client_for(opener))
    assert report.status is SourceStatus.OK
    assert outspend is not None
    assert outspend.spent is True
    assert outspend.txid == "3ae5a12f1eff2b7ea795a905931f1f18defc835ddae59faa5b5d2e4af393c0c1"


def test_btc_outspend_unspent(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_outspend_deposit_vout1.json"))
    report, outspend = btc_rpc.fetch_outspend(BTC_REFUND_TXID, 1, client_for(opener))
    assert report.status is SourceStatus.OK
    assert outspend is not None and outspend.spent is False


def test_btc_outspend_both_hosts_down_is_unavailable(opener: FakeOpener):
    opener.timeout("GET", "mempool.space/api/tx")
    opener.timeout("GET", "blockstream.info/api/tx")
    report, outspend = btc_rpc.fetch_outspend(BTC_REFUND_TXID, 0, client_for(opener))
    assert report.status is SourceStatus.TIMEOUT
    assert outspend is None


def test_btc_address_history_complete_when_counts_match(opener: FakeOpener):
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs", [load_raw("btc_tx_refund.json")])
    opener.json(
        "GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}",
        {"chain_stats": {"tx_count": 1}, "mempool_stats": {"tx_count": 0}},
    )
    report, history = btc_rpc.fetch_address_history(BTC_REFUND_PAYS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert history.complete is True
    assert history.reported_tx_count == 1
    assert len(history.txs) == 1


def test_btc_address_history_incomplete_when_counts_differ(opener: FakeOpener):
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs", [load_raw("btc_tx_refund.json")])
    opener.json(
        "GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}",
        {"chain_stats": {"tx_count": 500}, "mempool_stats": {"tx_count": 0}},
    )
    report, history = btc_rpc.fetch_address_history(BTC_REFUND_PAYS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert history.complete is False
    assert "incomplete" in history.reason


def test_btc_address_history_unknown_count_is_incomplete(opener: FakeOpener):
    # The stats call fails but the history page still answers: completeness cannot
    # be established, so it must be reported as incomplete rather than complete.
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs", [load_raw("btc_tx_refund.json")])
    opener.http_error("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}", 500)
    report, history = btc_rpc.fetch_address_history(BTC_REFUND_PAYS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert history.complete is False
    assert history.reported_tx_count is None


def test_btc_address_history_count_match_but_pagination_unfinished_is_incomplete(opener: FakeOpener):
    # A full page (25 entries) with the count reached would previously be read as
    # complete even though the page chain had not ended. The page budget stopping
    # mid-chain must be reported as incomplete.
    page = [load_raw("btc_tx_refund.json") for _ in range(25)]
    for i, entry in enumerate(page):
        entry["txid"] = f"{i:064x}"
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs", page)
    opener.json(
        "GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}",
        {"chain_stats": {"tx_count": 25}, "mempool_stats": {"tx_count": 0}},
    )
    report, history = btc_rpc.fetch_address_history(BTC_REFUND_PAYS, client_for(opener), max_pages=1)
    assert report.status is SourceStatus.OK
    assert history.complete is False
    assert "pagination did not run to completion" in history.reason


def test_btc_address_history_page_failure_midway_is_incomplete(opener: FakeOpener):
    # First page is full (25 entries, forcing a second page), the second page fails.
    page = [load_raw("btc_tx_refund.json") for _ in range(25)]
    for i, entry in enumerate(page):
        entry["txid"] = f"{i:064x}"
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs", page)
    opener.http_error("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs/chain/", 500)
    opener.json(
        "GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}",
        {"chain_stats": {"tx_count": 40}, "mempool_stats": {"tx_count": 0}},
    )
    report, history = btc_rpc.fetch_address_history(BTC_REFUND_PAYS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert history.complete is False
    assert "incomplete" in history.reason


def test_btc_address_history_multi_page_natural_end_is_complete(opener: FakeOpener):
    # Two pages: the first full (25), the second short (5). The chain ends naturally
    # and the count is reached, so the history is complete.
    page1 = [load_raw("btc_tx_refund.json") for _ in range(25)]
    for i, entry in enumerate(page1):
        entry["txid"] = f"{i:064x}"
    page2 = [load_raw("btc_tx_refund.json") for _ in range(5)]
    for i, entry in enumerate(page2):
        entry["txid"] = f"{100 + i:064x}"
    # The /txs/chain needle must be registered before the plain /txs needle, since
    # route matching is substring-based and in order.
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs/chain/", page2)
    opener.json("GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}/txs", page1)
    opener.json(
        "GET", f"mempool.space/api/address/{BTC_REFUND_PAYS}",
        {"chain_stats": {"tx_count": 30}, "mempool_stats": {"tx_count": 0}},
    )
    report, history = btc_rpc.fetch_address_history(BTC_REFUND_PAYS, client_for(opener))
    assert report.status is SourceStatus.OK
    assert history.complete is True
    assert len(history.txs) == 30
    assert history.pages_fetched == 2


def test_btc_script_level_match_is_recorded(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_tx_refund.json"))
    _, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    assert match.details["script_matched"] is True
    assert match.details["recipient_script_verified"] is True


def test_btc_to_candidate_projects_fields(opener: FakeOpener):
    opener.json("GET", "mempool.space/api/tx", load_raw("btc_tx_refund.json"))
    _, data = btc_rpc.fetch_tx(BTC_REFUND_TXID, client_for(opener))
    candidate = btc_rpc.to_candidate(data, BTC_REFUND_PAYS, "history")
    assert candidate.pays_recipient is True
    assert candidate.recipient_script_matched is True
    assert candidate.observed_sats == 12884
    assert candidate.discovery == "history"


def test_btc_refund_amount_denomination_edge_cases():
    """Amount semantics: explicit satoshi units, no mixing with BTC, fee excluded.

    The decisive refund evidence must state amounts in satoshis, keep the
    recipient's output separate from the transaction's total output value, and
    never fold the network fee into the refunded value.
    """
    # Real refund transaction: 12884 sats to the refund address, 37401503 sats to a
    # change output, 362 sats fee.
    data = btc_rpc.BtcTxData(
        txid="f" * 64,
        found=True,
        confirmed=True,
        fee=362,
        outputs=[
            btc_rpc.BtcOutput(address=BTC_REFUND_PAYS, value=12884, script_type="v0_p2wpkh", index=0),
            btc_rpc.BtcOutput(address="bc1qother", value=37401503, script_type="v0_p2wpkh", index=1),
        ],
    )
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    item = btc_rpc.refund_payout_evidence(data, match, "11746")
    details = item.details
    assert details["amount_unit"] == "satoshi"
    assert details["recipient_output_sats"] == 12884
    assert details["total_output_sats"] == 12884 + 37401503
    assert details["fee_sats"] == 362
    # The fee is not counted as refunded value: the recipient output is the output
    # value only, never the output plus the fee.
    assert details["recipient_output_sats"] != details["recipient_output_sats"] + details["fee_sats"]
    # A reported amount that differs is disclosed, never silently reconciled.
    assert any("differ" in lim for lim in item.limitations)


def test_btc_refund_evidence_without_reported_amount_has_no_denomination_guess():
    """With no reported amount, no satoshi figure is invented for the expectation."""
    data = btc_rpc.BtcTxData(
        txid="f" * 64,
        found=True,
        confirmed=True,
        outputs=[btc_rpc.BtcOutput(address=BTC_REFUND_PAYS, value=12884, script_type="v0_p2wpkh", index=0)],
    )
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    item = btc_rpc.refund_payout_evidence(data, match, None)
    assert item.details["expected_amount_sats"] is None
    # The observed on-chain value is still reported, with its unit.
    assert item.details["recipient_output_sats"] == 12884
    assert item.details["amount_unit"] == "satoshi"


def test_btc_refund_evidence_states_its_verification_method():
    """The decisive refund evidence records how its level was reached."""
    data = btc_rpc.BtcTxData(
        txid="f" * 64,
        found=True,
        confirmed=True,
        identity_validated=True,
        outputs=[
            btc_rpc.BtcOutput(
                address=BTC_REFUND_PAYS, value=12884, script_type="v0_p2wpkh", index=0
            )
        ],
    )
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    item = btc_rpc.refund_payout_evidence(data, match, None)
    assert item.verification_method
    assert "recomputed txid" in item.verification_method


def test_btc_refund_evidence_without_identity_validation_says_so():
    """Without local identity validation the method must not claim it."""
    data = btc_rpc.BtcTxData(
        txid="f" * 64,
        found=True,
        confirmed=True,
        identity_validated=False,
        outputs=[
            btc_rpc.BtcOutput(
                address=BTC_REFUND_PAYS, value=12884, script_type="v0_p2wpkh", index=0
            )
        ],
    )
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    item = btc_rpc.refund_payout_evidence(data, match, None)
    assert "explorer-reported" in (item.verification_method or "")


def test_btc_refund_unconfirmed_transaction_is_not_confirmed_evidence():
    """An unconfirmed payout yields a non-CONFIRMED classification, never a refund."""
    data = btc_rpc.BtcTxData(
        txid="f" * 64,
        found=True,
        confirmed=False,
        outputs=[btc_rpc.BtcOutput(address=BTC_REFUND_PAYS, value=12884, script_type="v0_p2wpkh", index=0)],
    )
    match = btc_rpc.match_expected_payout(data, BTC_REFUND_PAYS)
    assert match.matched is False
    assert "not yet confirmed" in match.reason


# --- NEAR RPC: intent withdrawal extraction ---------------------------------


def test_near_rpc_extracts_intent_withdrawal_recipient(opener: FakeOpener):
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_settlement.json"))
    report, data = near_rpc.fetch_tx("83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1", client_for(opener))
    assert report.status is SourceStatus.OK
    withdrawals = data.intent_withdrawals
    assert withdrawals and withdrawals[0].recipient == "btc:bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw"
    item = [i for i in report.evidence if i.event_type.value == "INTENT_WITHDRAWAL_OBSERVED"]
    assert item and item[0].details["withdrawal_recipients"] == [
        "btc:bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw"
    ]


def test_near_rpc_bridge_credit_from_btc_deposit(opener: FakeOpener):
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx_btc_deposit.json"))
    report, data = near_rpc.fetch_tx("5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T", client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.btc_utxo_origin_hashes == [BTC_DEPOSIT_TXID]
    credit = [i for i in report.evidence if i.event_type.value == "DEPOSIT_OBSERVED"]
    assert credit and credit[0].details["bridged_from_origin_hashes"] == [BTC_DEPOSIT_TXID]
    assert credit[0].details["memo_marker"] == "utxo_added"


# --- Asset parsing ----------------------------------------------------------


@pytest.mark.parametrize(
    "asset_id,chain,contract",
    [
        ("nep141:eth.omft.near", "eth", None),
        ("nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near", "eth", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        ("nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near", "base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
        ("nep141:wrap.near", "near", "wrap.near"),
        ("btc:mainnet:native", "btc", None),
    ],
)
def test_asset_id_chain_derivation(asset_id, chain, contract):
    info = parse_asset_id(asset_id)
    assert info.chain == chain
    assert info.contract == contract


def test_rpc_map_has_no_secrets():
    """The chain map must never contain credentials."""
    for rpc in config.EVM_RPC_MAP.values():
        assert "key=" not in rpc.url
        assert "apikey" not in rpc.url.lower()
        assert "token=" not in rpc.url.lower()


# --- NEAR RPC: transaction-level failure attribution ------------------------
#
# ``intents.near`` batches intents into one transaction, so a sibling receipt's
# failure must not be attributed to the transaction. Only the transaction-level
# outcome decides ``execution_failed``.


def test_near_execution_failed_ignores_sibling_receipt_failure(opener: FakeOpener):
    """A failed sibling receipt does not mark the transaction as failed."""
    payload = load_raw("near_rpc_tx.json")
    payload["result"]["receipts_outcome"].append(
        {"outcome": {"status": {"Failure": {"ActionError": "slippage"}}, "logs": []}}
    )
    opener.json("POST", "/", payload)
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.execution_failed is False
    exec_items = [i for i in report.evidence if i.event_type.value == "NEAR_TX_EXECUTION"]
    assert exec_items and exec_items[0].reported_status == "SUCCESS"


def test_near_execution_failed_true_for_transaction_level_failure(opener: FakeOpener):
    """A transaction-level failure is still reported as a failure."""
    payload = load_raw("near_rpc_tx.json")
    payload["result"]["transaction_outcome"]["outcome"]["status"] = {
        "Failure": {"ActionError": "out of gas"}
    }
    opener.json("POST", "/", payload)
    report, data = near_rpc.fetch_tx(REAL_NEAR_TX, client_for(opener))
    assert report.status is SourceStatus.OK
    assert data.execution_failed is True
    exec_items = [i for i in report.evidence if i.event_type.value == "NEAR_TX_EXECUTION"]
    assert exec_items and exec_items[0].reported_status == "FAILED"


def test_near_execution_failed_false_without_transaction_outcome():
    """A response with no transaction outcome is not treated as a failure."""
    assert near_rpc._execution_failed({}) is False
    assert near_rpc._execution_failed({"receipts_outcome": [{"outcome": {"status": {"Failure": {}}}}]}) is False


# --- 1Click status URL encoding ---------------------------------------------


def test_build_status_url_encodes_an_ordinary_address():
    url = oneclick.build_status_url("0xABC123")
    assert url == f"{config.ONECLICK_BASE}{config.ONECLICK_STATUS_PATH}?depositAddress=0xABC123"


@pytest.mark.parametrize(
    "raw, expected_query",
    [
        ("a&b", "depositAddress=a%26b"),
        ("a=b", "depositAddress=a%3Db"),
        ("a?b", "depositAddress=a%3Fb"),
        ("a b", "depositAddress=a+b"),
        ("a/b", "depositAddress=a%2Fb"),
        ("a#b", "depositAddress=a%23b"),
        ("a+b", "depositAddress=a%2Bb"),
        ("\u00e9", "depositAddress=%C3%A9"),
        ("\u4e2d\u6587", "depositAddress=%E4%B8%AD%E6%96%87"),
        ("\U0001f600", "depositAddress=%F0%9F%98%80"),
    ],
)
def test_build_status_url_encodes_special_characters(raw, expected_query):
    url = oneclick.build_status_url(raw)
    prefix = f"{config.ONECLICK_BASE}{config.ONECLICK_STATUS_PATH}?"
    assert url == prefix + expected_query


def test_build_status_url_keeps_a_single_depositaddress_parameter():
    """A '&' in the value must not create a second query parameter."""
    url = oneclick.build_status_url("0xdead&evil=1")
    query = url.split("?", 1)[1]
    parsed = urllib.parse.parse_qs(query)
    assert list(parsed.keys()) == ["depositAddress"]
    assert parsed["depositAddress"] == ["0xdead&evil=1"]


@pytest.mark.parametrize(
    "raw",
    ["a&b=c", "x?y#z", "space here", "unicode\u00e9", "0x" + "a" * 40, "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"],
)
def test_build_status_url_round_trips_the_address(raw):
    url = oneclick.build_status_url(raw)
    query = url.split("?", 1)[1]
    parsed = urllib.parse.parse_qs(query)
    assert parsed["depositAddress"] == [raw]


def test_build_status_url_does_not_alter_the_live_request(opener: FakeOpener):
    """The real HTTP request still uses urlencoded params and the same endpoint."""
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    report, data = oneclick.investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    assert report.status is SourceStatus.OK
    # The request the client actually issued carried the address as one parameter.
    assert opener.calls, "expected at least one HTTP call"
    request = opener.calls[0]
    assert "depositAddress=" in request
    assert REAL_DEPOSIT_ADDRESS in urllib.parse.unquote(request)
