"""Adapter tests: real fixtures, error handling, and schema validation.

These exercise the real adapter code with a fake transport, so parsing,
classification, and error mapping are genuinely tested.
"""

from __future__ import annotations

import pytest

from tracesettle import config
from tracesettle.adapters import evm_rpc, near_rpc, oneclick, solver_relay
from tracesettle.assets import parse_asset_id
from tracesettle.model import SourceStatus, Verification

from conftest import (
    FakeOpener,
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
