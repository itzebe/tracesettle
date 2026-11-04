"""Independent destination-chain settlement verification.

These tests exercise the real verifier, the real EVM receipt adapter, and the real
lifecycle over the canned transport (``FakeOpener``). The reference transaction is
a real mainnet USDC transfer captured in ``evidence/raw/evm_receipt_destination.json``:
a provider-claimed destination delivery that the tool must confirm — or refuse to
confirm — from the chain alone.

The mission rule under test: a provider ``SUCCESS`` is a claim, never proof, and the
destination leg must be independently verified by explicit identifiers (chain,
transaction hash, token contract, recipient), never by amount or timestamp.
"""

from __future__ import annotations

import copy

from tracesettle.near.destination_verify import (
    DestinationVerdict,
    fetch_latest_block_number,
    verify_destination_delivery,
)

from conftest import (
    REAL_DESTINATION_TX,
    REAL_RECIPIENT,
    client_for,
    load_raw,
)

USDC_ETH = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
DEST_AMOUNT_OUT = "347350080510"
# The reference receipt is at block 0x1903ac4.
DEST_BLOCK = 0x1903AC4


def _receipt(**overrides):
    payload = load_raw("evm_receipt_destination.json")
    result = payload["result"]
    for key, value in overrides.items():
        result[key] = value
    return payload


# -- the reference transaction is confirmed ----------------------------------


def test_reference_destination_delivery_is_verified(opener):
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
        latest_block_number=DEST_BLOCK + 100,
    )
    assert verification.level is DestinationVerdict.VERIFIED
    assert verification.checks["execution_succeeded"] is True
    assert verification.checks["observed_amount_base_units"] == DEST_AMOUNT_OUT
    assert verification.checks["expected_recipient"] == REAL_RECIPIENT.lower()


def test_a_reverted_destination_transaction_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", _receipt(status="0x0"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.CONTRADICTORY
    assert "revert" in verification.summary.lower()


def test_a_receipt_for_a_different_hash_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", _receipt(transactionHash="0xdeadbeef"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.CONTRADICTORY


def test_a_payment_to_a_different_recipient_is_contradictory(opener):
    """The transfer must pay the intended recipient, never merely *some* address."""
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient="0x000000000000000000000000000000000000dead",
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.CONTRADICTORY


def test_a_different_token_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract="0x0000000000000000000000000000000000000001",
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.CONTRADICTORY


def test_an_amount_shortfall_is_disclosed_not_confirmed(opener):
    """A short delivery is not a verified delivery; the difference is disclosed."""
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount="999999999999",  # more than was delivered
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.UNCONFIRMED
    assert verification.checks["observed_amount_base_units"] == DEST_AMOUNT_OUT
    assert verification.checks["expected_amount_base_units"] == "999999999999"


def test_a_shallowly_confirmed_delivery_is_unconfirmed(opener):
    """A receipt one block from the head is not yet a delivery."""
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
        latest_block_number=DEST_BLOCK,  # 1 confirmation
        min_confirmations=12,
    )
    assert verification.level is DestinationVerdict.UNCONFIRMED
    assert verification.checks["confirmations"] == 1


def test_a_missing_destination_transaction_is_not_found(opener):
    """A null receipt is a missing record, never proof the transfer failed."""
    null = {"jsonrpc": "2.0", "id": 1, "result": None}
    opener.json("POST", "ethereum-rpc", null)
    opener.json("POST", "drpc", null)
    opener.json("POST", "blastapi", null)
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.NOT_FOUND


def test_an_unreachable_destination_source_is_unavailable(opener):
    opener.timeout("POST", "ethereum-rpc")
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.UNAVAILABLE


def test_an_unsupported_destination_chain_is_unsupported(opener):
    verification = verify_destination_delivery(
        chain="doge",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=None,
        expected_amount=None,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.UNSUPPORTED


def test_a_native_delivery_verifies_the_recipient_and_discloses_the_amount(opener):
    """For a native asset the receipt carries no value, so the amount is not claimed."""
    payload = _receipt()
    payload["result"]["to"] = REAL_RECIPIENT
    payload["result"]["logs"] = []
    opener.json("POST", "ethereum-rpc", payload)
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=None,
        expected_amount=None,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.VERIFIED
    assert any("native value" in lim for lim in verification.limitations)


def test_a_native_delivery_to_the_wrong_recipient_is_contradictory(opener):
    payload = _receipt()
    payload["result"]["to"] = "0x000000000000000000000000000000000000dead"
    payload["result"]["logs"] = []
    opener.json("POST", "ethereum-rpc", payload)
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=REAL_RECIPIENT,
        token_contract=None,
        expected_amount=None,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.CONTRADICTORY


def test_no_recipient_is_unconfirmed_not_verified(opener):
    """Without the intended recipient a transfer cannot be tied to this intent."""
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    verification = verify_destination_delivery(
        chain="eth",
        tx_hash=REAL_DESTINATION_TX,
        recipient=None,
        token_contract=USDC_ETH,
        expected_amount=DEST_AMOUNT_OUT,
        client=client_for(opener),
    )
    assert verification.level is DestinationVerdict.UNCONFIRMED


# -- finality head fetch -----------------------------------------------------


def test_latest_block_number_reads_the_head(opener):
    opener.json("POST", "ethereum-rpc", {"jsonrpc": "2.0", "id": 1, "result": "0x1903ac4"})
    assert fetch_latest_block_number("eth", client_for(opener)) == DEST_BLOCK


def test_latest_block_number_is_none_when_the_head_cannot_be_read(opener):
    opener.timeout("POST", "ethereum-rpc")
    assert fetch_latest_block_number("eth", client_for(opener)) is None


# -- determinism -------------------------------------------------------------


def test_verification_is_deterministic(opener):
    payload = load_raw("evm_receipt_destination.json")
    opener.json("POST", "ethereum-rpc", payload)
    first = verify_destination_delivery(
        chain="eth", tx_hash=REAL_DESTINATION_TX, recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH, expected_amount=DEST_AMOUNT_OUT, client=client_for(opener),
    )
    opener.json("POST", "ethereum-rpc", copy.deepcopy(payload))
    second = verify_destination_delivery(
        chain="eth", tx_hash=REAL_DESTINATION_TX, recipient=REAL_RECIPIENT,
        token_contract=USDC_ETH, expected_amount=DEST_AMOUNT_OUT, client=client_for(opener),
    )
    assert first.to_dict() == second.to_dict()
