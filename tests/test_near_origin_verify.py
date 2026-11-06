"""Unit tests for independent origin-chain deposit verification.

The verifier reads the origin chain directly and compares explicit identifiers —
recipient, token contract, amount — never a provider claim. These tests exercise
the real adapter and the real HTTP client; only the transport is substituted
(``FakeOpener``), so the code under test is the shipped code path.
"""

from __future__ import annotations


from tracesettle.near.origin_verify import (
    OriginVerdict,
    origin_contract_address,
    verify_origin_deposit,
)

from conftest import client_for

DEPOSIT = "0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"
OTHER = "0x1111111111111111111111111111111111111111"
TOKEN = "0xdac17f958d2ee523a2206206994597c13d831ec7"
TX = "0xfca11aa01bce5fc20a6cbeb4ca30e8af994cda47de9bd5fa53a9ca4295ba01d2"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _word(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def _receipt(*, to=DEPOSIT, status="0x1", logs=None, tx_hash=TX):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "transactionHash": tx_hash,
            "status": status,
            "from": OTHER,
            "to": to,
            "blockNumber": "0x1900000",
            "logs": logs or [],
        },
    }


def _transfer_log(*, token=TOKEN, to=DEPOSIT, amount="145987303918706045000"):
    return {
        "address": token,
        "topics": [TRANSFER_TOPIC, _word(OTHER), _word(to)],
        "data": hex(int(amount)),
        "logIndex": "0x1",
    }


# -- asset-id contract parsing -----------------------------------------------


def test_origin_contract_address_reads_an_erc20_asset():
    assert origin_contract_address(f"nep141:eth-{TOKEN}.omft.near") == TOKEN


def test_origin_contract_address_is_none_for_a_native_asset():
    assert origin_contract_address("nep141:eth.omft.near") is None
    assert origin_contract_address("nep141:btc.omft.near") is None


def test_origin_contract_address_rejects_a_malformed_id():
    assert origin_contract_address("nep141:eth-nothex.omft.near") is None
    assert origin_contract_address("nope") is None
    assert origin_contract_address(None) is None


# -- EVM: native and token ---------------------------------------------------


def test_native_evm_deposit_to_the_right_address_is_verified(opener):
    opener.json("POST", "ethereum-rpc", _receipt())
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.VERIFIED
    assert v.checks["execution_succeeded"] is True


def test_native_evm_deposit_to_a_wrong_address_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", _receipt(to=OTHER))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.CONTRADICTORY


def test_reverted_evm_deposit_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", _receipt(status="0x0"))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.CONTRADICTORY


def test_erc20_transfer_to_the_deposit_address_is_verified(opener):
    opener.json("POST", "ethereum-rpc", _receipt(to=TOKEN, logs=[_transfer_log()]))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=TOKEN,
        expected_amount="145987303918706045000", client=client_for(opener),
    )
    assert v.level is OriginVerdict.VERIFIED
    assert v.checks["observed_amount_base_units"] == "145987303918706045000"


def test_erc20_transfer_of_a_different_amount_is_unconfirmed_not_verified(opener):
    opener.json("POST", "ethereum-rpc", _receipt(to=TOKEN, logs=[_transfer_log(amount="999")]))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=TOKEN,
        expected_amount="145987303918706045000", client=client_for(opener),
    )
    assert v.level is OriginVerdict.UNCONFIRMED


def test_erc20_with_no_matching_transfer_is_contradictory(opener):
    # A token asset, but the receipt carries no Transfer of that token to the address.
    opener.json("POST", "ethereum-rpc", _receipt(to=TOKEN, logs=[]))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=TOKEN,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.CONTRADICTORY


def test_erc20_transfer_to_a_different_recipient_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", _receipt(to=TOKEN, logs=[_transfer_log(to=OTHER)]))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=TOKEN,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.CONTRADICTORY


def test_missing_evm_receipt_is_not_found(opener):
    # A null receipt is a definitive "not found", so the adapter tries every
    # configured endpoint; wire the primary and the fallback.
    opener.json("POST", "ethereum-rpc", {"jsonrpc": "2.0", "id": 1, "result": None})
    opener.json("POST", "eth.drpc.org", {"jsonrpc": "2.0", "id": 1, "result": None})
    opener.json("POST", "blastapi.io", {"jsonrpc": "2.0", "id": 1, "result": None})
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.NOT_FOUND


def test_receipt_for_a_different_hash_is_contradictory(opener):
    opener.json("POST", "ethereum-rpc", _receipt(tx_hash="0x" + "ab" * 32))
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.CONTRADICTORY


def test_evm_source_outage_is_unavailable(opener):
    opener.http_error("POST", "ethereum-rpc", 503, b"down")
    v = verify_origin_deposit(
        chain="eth", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.UNAVAILABLE


def test_unsupported_chain_is_unsupported(opener):
    v = verify_origin_deposit(
        chain="dogecoin", tx_hash=TX, deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.UNSUPPORTED


# -- Bitcoin -----------------------------------------------------------------

BTC_DEPOSIT = "bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm"


def _btc_tx(*, confirmed=True, address=BTC_DEPOSIT, value=12884, txid=TX, script=None):
    if script is None:
        script = "001490ece5c59554abddeb10ddbb9fec2e69617e27f5"
    return {
        "txid": txid,
        "status": {"confirmed": confirmed, "block_height": 800000},
        "vin": [],
        "vout": [{"scriptpubkey_address": address, "value": value, "scriptpubkey": script}],
        "size": 200,
        "fee": 300,
    }


def test_confirmed_btc_payment_to_the_deposit_address_is_verified(opener):
    opener.json("GET", "mempool.space/api/tx/", _btc_tx())
    v = verify_origin_deposit(
        chain="btc", tx_hash=TX, deposit_address=BTC_DEPOSIT, token_contract=None,
        expected_amount="12884", client=client_for(opener),
    )
    assert v.level is OriginVerdict.VERIFIED


def test_unconfirmed_btc_payment_is_unconfirmed(opener):
    opener.json("GET", "mempool.space/api/tx/", _btc_tx(confirmed=False))
    v = verify_origin_deposit(
        chain="btc", tx_hash=TX, deposit_address=BTC_DEPOSIT, token_contract=None,
        expected_amount="12884", client=client_for(opener),
    )
    assert v.level is OriginVerdict.UNCONFIRMED


def test_btc_payment_to_a_different_address_is_contradictory(opener):
    # A different output script, so the script-level match fails (matching is by
    # decoded script, never by the address string).
    opener.json("GET", "mempool.space/api/tx/",
                _btc_tx(address="bc1qother", script="0014" + "11" * 20))
    v = verify_origin_deposit(
        chain="btc", tx_hash=TX, deposit_address=BTC_DEPOSIT, token_contract=None,
        expected_amount="12884", client=client_for(opener),
    )
    assert v.level is OriginVerdict.CONTRADICTORY


def test_missing_btc_transaction_is_not_found(opener):
    opener.http_error("GET", "mempool.space/api/tx/", 404, b"not found")
    v = verify_origin_deposit(
        chain="btc", tx_hash=TX, deposit_address=BTC_DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.NOT_FOUND


def test_empty_hash_is_unconfirmed(opener):
    v = verify_origin_deposit(
        chain="eth", tx_hash="", deposit_address=DEPOSIT, token_contract=None,
        expected_amount=None, client=client_for(opener),
    )
    assert v.level is OriginVerdict.UNCONFIRMED
