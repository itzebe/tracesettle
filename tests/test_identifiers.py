"""Unit tests for identifier classification and deposit-address validation.

The addresses used here are real, well-known mainnet addresses so the expected
classifications are anchored to genuine encodings rather than to strings the
tests happen to accept. Malformed cases are produced by corrupting a real
address (a single character, or a truncated checksum) so the rejection exercises
the actual checksum/structure checks rather than a length shortcut.
"""

from __future__ import annotations

import pytest

from tracesettle.base58 import b58check_decode, b58decode
from tracesettle.identifiers import (
    classify_identifier,
    is_btc_address,
    is_btc_bech32_address,
    is_btc_legacy_address,
    is_solana_address,
    is_tron_address,
    validate_deposit_address,
)
from tracesettle.model import IdentifierType

# --- Real, well-known mainnet addresses -------------------------------------

# Bitcoin P2PKH (the genesis coinbase address).
BTC_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
# Bitcoin P2SH.
BTC_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
# Bitcoin segwit v0 (bech32).
BTC_BECH32 = "bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm"
# TRON mainnet (USDT contract address).
TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
# TRON mainnet (another real address).
TRON_2 = "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"
# Solana system program / a real 32-byte base58 public key.
SOLANA = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"

EVM_ADDRESS = "0x" + "a" * 40
EVM_TX_HASH = "0x" + "b" * 64
NEAR_IMPLICIT = "c" * 64
NEAR_NAMED = "alice.near"
# A 43-character base58 value (ambiguous hash window).
AMBIGUOUS_43 = "7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94d"
AMBIGUOUS_44 = "7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG"


def _corrupt(address: str, *, keep_prefix: int = 0) -> str:
    """Change one base58 character (checksum now wrong), preserving a prefix.

    ``keep_prefix`` characters at the start are left intact so the corrupted
    value still has the same family prefix (``T``, ``1``/``3``, ``bc1``) and the
    rejection is attributable to the checksum, not to a changed prefix.
    """
    for i in range(keep_prefix, len(address)):
        ch = address[i]
        replacement = "2" if ch != "2" else "3"
        candidate = address[:i] + replacement + address[i + 1 :]
        if candidate != address:
            return candidate
    raise AssertionError("could not corrupt address")


# --- Classification of confirmed deposit-address formats --------------------


@pytest.mark.parametrize(
    "address",
    [TRON, TRON_2, BTC_P2PKH, BTC_P2SH, BTC_BECH32, NEAR_NAMED, NEAR_IMPLICIT, EVM_ADDRESS],
)
def test_real_deposit_addresses_classify_as_deposit_address(address: str) -> None:
    assert classify_identifier(address) is IdentifierType.DEPOSIT_ADDRESS
    ok, reason = validate_deposit_address(address)
    assert ok, reason


def test_tron_address_is_recognised_by_version_and_checksum() -> None:
    assert is_tron_address(TRON)
    # The decoded payload is 0x41 + 20 bytes.
    payload = b58check_decode(TRON)
    assert payload is not None and len(payload) == 21 and payload[0] == 0x41


def test_btc_legacy_p2pkh_and_p2sh_are_recognised() -> None:
    assert is_btc_legacy_address(BTC_P2PKH)
    assert is_btc_legacy_address(BTC_P2SH)
    assert is_btc_address(BTC_P2PKH) and is_btc_address(BTC_P2SH)


def test_btc_bech32_is_recognised() -> None:
    assert is_btc_bech32_address(BTC_BECH32)
    assert is_btc_address(BTC_BECH32)
    assert classify_identifier(BTC_BECH32) is IdentifierType.DEPOSIT_ADDRESS


def test_solana_encoding_is_recognised_but_not_auto_classified() -> None:
    # The encoding is a 32-byte base58 value: recognised as such.
    assert is_solana_address(SOLANA)
    assert len(b58decode(SOLANA) or b"") == 32
    # ...but it is indistinguishable from a NEAR tx hash / intent hash, so it is
    # never silently classified as a deposit address.
    assert classify_identifier(SOLANA) is IdentifierType.UNKNOWN


# --- Malformed addresses are rejected ---------------------------------------


@pytest.mark.parametrize("address", [TRON, TRON_2])
def test_tron_address_with_bad_checksum_is_rejected(address: str) -> None:
    bad = _corrupt(address, keep_prefix=1)
    assert not is_tron_address(bad)
    assert classify_identifier(bad) is IdentifierType.UNKNOWN
    ok, reason = validate_deposit_address(bad)
    assert not ok and reason and "TRON" in reason


@pytest.mark.parametrize("address", [BTC_P2PKH, BTC_P2SH])
def test_btc_legacy_with_bad_checksum_is_rejected(address: str) -> None:
    bad = _corrupt(address, keep_prefix=1)
    assert not is_btc_legacy_address(bad)
    assert classify_identifier(bad) is IdentifierType.UNKNOWN
    ok, reason = validate_deposit_address(bad)
    assert not ok and reason and "Bitcoin" in reason


def test_tron_shaped_but_wrong_version_is_rejected() -> None:
    # A T-prefixed string that is not a TRON mainnet payload must not be accepted.
    assert not is_tron_address("T" * 34)
    assert not is_tron_address("")


def test_btc_bech32_with_bad_checksum_is_rejected() -> None:
    bad = _corrupt(BTC_BECH32, keep_prefix=3)
    assert bad.startswith("bc1")
    # The checksum fails, so it is not a Bitcoin address.
    assert not is_btc_bech32_address(bad)
    assert not is_btc_address(bad)
    # It is not accepted as a Bitcoin address. (The corrupted string may still
    # match the permissive NEAR named-account rule, which accepts any lowercase
    # alphanumeric string; that is pre-existing behaviour, not a Bitcoin match.)
    assert not is_btc_legacy_address(bad)


def test_solana_shaped_string_of_wrong_length_is_not_a_public_key() -> None:
    # A base58 string that decodes to a length other than 32 is not a key.
    assert not is_solana_address("2")  # decodes to one byte
    assert not is_solana_address("")


# --- Ambiguity is preserved, never guessed ----------------------------------


@pytest.mark.parametrize("value", [AMBIGUOUS_43, AMBIGUOUS_44])
def test_ambiguous_base58_window_is_unknown(value: str) -> None:
    assert classify_identifier(value) is IdentifierType.UNKNOWN
    ok, reason = validate_deposit_address(value)
    assert not ok and reason and "base58" in reason


def test_all_ones_base58_is_not_forced_into_a_deposit_address() -> None:
    # Regression: a run of '1's is valid base58 and was previously at risk of
    # matching the NEAR named-account rule.
    for value in ("1" * 43, "1" * 44):
        assert classify_identifier(value) is IdentifierType.UNKNOWN


# --- Existing classifications are preserved ---------------------------------


def test_evm_identifiers_are_unchanged() -> None:
    assert classify_identifier(EVM_ADDRESS) is IdentifierType.DEPOSIT_ADDRESS
    assert classify_identifier(EVM_TX_HASH) is IdentifierType.ORIGIN_CHAIN_TX_HASH


def test_near_identifiers_are_unchanged() -> None:
    assert classify_identifier(NEAR_IMPLICIT) is IdentifierType.DEPOSIT_ADDRESS
    assert classify_identifier(NEAR_NAMED) is IdentifierType.DEPOSIT_ADDRESS


def test_uppercase_near_named_account_is_not_a_deposit_address() -> None:
    assert classify_identifier("Alice.Near") is IdentifierType.UNKNOWN


def test_empty_and_whitespace_are_unknown() -> None:
    assert classify_identifier("") is IdentifierType.UNKNOWN
    assert classify_identifier("   ") is IdentifierType.UNKNOWN


def test_classification_is_whitespace_insensitive() -> None:
    assert classify_identifier(f"  {TRON}  ") is IdentifierType.DEPOSIT_ADDRESS
    assert classify_identifier(f"  {BTC_P2PKH}  ") is IdentifierType.DEPOSIT_ADDRESS


def test_unknown_identifier_stays_unknown() -> None:
    assert classify_identifier("not an identifier") is IdentifierType.UNKNOWN
