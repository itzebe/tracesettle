"""Identifier classification and validation.

Only formats verified in Phase 1 are recognised. Classification is deliberately
conservative: when a format is ambiguous the type is reported as UNKNOWN and the
investigation explains what it can and cannot resolve.
"""

from __future__ import annotations

import re

from .base58 import b58check_decode, b58decode
from .model import IdentifierType

#: NEAR implicit account: 64 lowercase hex characters.
_NEAR_IMPLICIT_RE = re.compile(r"^[0-9a-f]{64}$")
#: NEAR named account (2-64 chars, dot-separated, no leading/trailing separator).
_NEAR_NAMED_RE = re.compile(r"^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$")
#: EVM address.
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
#: EVM 32-byte transaction hash.
_EVM_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
#: NEAR transaction hash: base58, 43-44 characters.
_NEAR_TX_HASH_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{43,44}$")
#: Intent hash: base58, 43-44 characters (same alphabet as NEAR tx hashes).
_INTENT_HASH_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{43,44}$")

#: TRON mainnet address version byte (Base58Check payload prefix).
_TRON_VERSION = 0x41
#: Bitcoin P2PKH version byte.
_BTC_P2PKH_VERSION = 0x00
#: Bitcoin P2SH version byte.
_BTC_P2SH_VERSION = 0x05
#: A Base58Check payload for an address is exactly one version byte + 20-byte hash.
_ADDRESS_PAYLOAD_LEN = 21
#: A Solana public key is exactly 32 bytes.
_SOLANA_PUBKEY_LEN = 32


def is_near_implicit_account(value: str) -> bool:
    return bool(_NEAR_IMPLICIT_RE.match(value))


def is_near_named_account(value: str) -> bool:
    # NEAR account ids are lowercase; they cannot contain uppercase or '0x'.
    if value != value.lower():
        return False
    return 2 <= len(value) <= 64 and bool(_NEAR_NAMED_RE.match(value))


def is_evm_address(value: str) -> bool:
    return bool(_EVM_ADDRESS_RE.match(value))


def is_evm_tx_hash(value: str) -> bool:
    return bool(_EVM_TX_HASH_RE.match(value))


def is_near_tx_hash(value: str) -> bool:
    return bool(_NEAR_TX_HASH_RE.match(value))


def is_intent_hash(value: str) -> bool:
    return bool(_INTENT_HASH_RE.match(value))


def is_tron_address(value: str) -> bool:
    """A TRON mainnet address: Base58Check with the ``0x41`` version byte.

    The version byte and checksum are verified, so a mistyped address is rejected
    rather than accepted on length or a leading ``T`` alone.
    """
    if not value.startswith("T"):
        return False
    payload = b58check_decode(value)
    return (
        payload is not None
        and len(payload) == _ADDRESS_PAYLOAD_LEN
        and payload[0] == _TRON_VERSION
    )


def is_btc_legacy_address(value: str) -> bool:
    """A legacy Bitcoin address: P2PKH (``1…``) or P2SH (``3…``) Base58Check.

    Segwit (bech32/bech32m) addresses are handled by :func:`is_btc_address`.
    """
    if not (value.startswith("1") or value.startswith("3")):
        return False
    payload = b58check_decode(value)
    if payload is None or len(payload) != _ADDRESS_PAYLOAD_LEN:
        return False
    return payload[0] in (_BTC_P2PKH_VERSION, _BTC_P2SH_VERSION)


def is_btc_bech32_address(value: str) -> bool:
    """A Bitcoin mainnet segwit address (bech32 v0 / bech32m v1+)."""
    from .btc_verify import address_to_scriptpubkey

    if not value.lower().startswith("bc1"):
        return False
    return address_to_scriptpubkey(value) is not None


def is_btc_address(value: str) -> bool:
    """A Bitcoin mainnet address: legacy Base58Check or segwit bech32/bech32m."""
    return is_btc_legacy_address(value) or is_btc_bech32_address(value)


def is_solana_address(value: str) -> bool:
    """Whether ``value`` is a base58 string that decodes to exactly 32 bytes.

    This recognises the *encoding* a Solana public key uses. It cannot by itself
    prove the value is a Solana address: a NEAR transaction hash and an intent
    hash are also 32-byte base58 values, and every such value encodes to 43-44
    characters, so the three are indistinguishable from the string alone. Callers
    must combine this with external context (e.g. a user-selected chain) and must
    never treat a bare ``True`` here as proof of a Solana deposit address.
    """
    if not (32 <= len(value) <= 44):
        return False
    raw = b58decode(value)
    return raw is not None and len(raw) == _SOLANA_PUBKEY_LEN


def is_base58_string(value: str) -> bool:
    """Whether the whole string is valid base58 (any length)."""
    return b58decode(value) is not None


def classify_identifier(raw: str) -> IdentifierType:
    """Classify a user-supplied identifier.

    Classification order matters, and ambiguity is surfaced rather than guessed:

    * A ``0x`` 32-byte value is an EVM transaction hash; a ``0x`` 20-byte value is
      an EVM address.
    * A Base58Check string with a recognised version byte and a valid checksum is
      an unambiguous deposit address: TRON mainnet (``0x41``) or legacy Bitcoin
      P2PKH/P2SH (``0x00``/``0x05``).
    * A Bitcoin segwit (bech32/bech32m) address is an unambiguous deposit address.
    * A 64-hex string is a NEAR implicit account; a dotted lowercase string is a
      NEAR named account.
    * A base58 string in the 43-44 character window is genuinely ambiguous: a
      NEAR transaction hash, an intent hash, and a Solana public key are all
      32-byte base58 values, and every 32-byte base58 value encodes to 43-44
      characters, so the three are indistinguishable from the string alone. It is
      reported as ``UNKNOWN`` so it is never silently reinterpreted as a deposit
      address; callers add an explanatory note and use the explicit helpers
      (:func:`is_solana_address` recognises the encoding when a chain is known).
    """
    value = raw.strip()
    if not value:
        return IdentifierType.UNKNOWN
    if is_evm_tx_hash(value):
        return IdentifierType.ORIGIN_CHAIN_TX_HASH
    if is_evm_address(value):
        return IdentifierType.DEPOSIT_ADDRESS
    # Unambiguous Base58Check deposit addresses (version byte + checksum).
    if is_tron_address(value) or is_btc_legacy_address(value):
        return IdentifierType.DEPOSIT_ADDRESS
    if is_btc_bech32_address(value):
        return IdentifierType.DEPOSIT_ADDRESS
    if is_near_tx_hash(value) or is_intent_hash(value):
        # Base58 43-44 chars: ambiguous by construction (NEAR tx hash, intent
        # hash, or a Solana public key). Never guessed here. Checked before the
        # NEAR named-account rule, which would otherwise claim these strings.
        return IdentifierType.UNKNOWN
    if is_near_implicit_account(value) or is_near_named_account(value):
        return IdentifierType.DEPOSIT_ADDRESS
    return IdentifierType.UNKNOWN


def normalize(raw: str) -> str:
    """Trim surrounding whitespace; lowercase only EVM hex identifiers."""
    value = raw.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return "0x" + value[2:].lower()
    return value


def validate_deposit_address(raw: str) -> tuple[bool, str | None]:
    """Validate a deposit address.

    Returns ``(ok, reason)``. A deposit address is an EVM address, a NEAR
    account id, a TRON mainnet address, or a Bitcoin address. EVM and NEAR were
    verified in Phase 1; the others are recognised by their exact encoding
    (Base58Check version byte, bech32 checksum) rather than by length or a
    leading character alone.

    A Solana public key is deliberately *not* accepted here. A Solana key is a
    32-byte base58 value, which is exactly the encoding a NEAR transaction hash
    and an intent hash use, so it is indistinguishable from those by the string
    alone and must never be routed automatically. Such a value is rejected with
    a reason that names all three possibilities; :func:`is_solana_address`
    recognises the encoding for callers that already know the chain.
    """
    value = normalize(raw)
    if not value:
        return False, "empty identifier"
    if is_evm_address(value):
        return True, None
    # A "0x"-prefixed value that is not a valid 40-hex EVM address is a malformed
    # address, not a NEAR account id.
    if value.startswith("0x"):
        if is_evm_tx_hash(value):
            return False, "this looks like a transaction hash, not a deposit address"
        return False, "this looks like a malformed EVM address (expected 0x + 40 hex characters)"
    if is_tron_address(value):
        return True, None
    if is_btc_address(value):
        return True, None
    # A base58 43-44 char value is ambiguous (NEAR tx hash, intent hash, or a
    # Solana public key) and is never forced into the deposit-address path.
    # Checked before the NEAR account rules, which would otherwise claim these
    # strings. This is also why no Solana branch follows: every real Solana key
    # is 43-44 characters and is captured here.
    if is_near_tx_hash(value) or is_intent_hash(value):
        return (
            False,
            "this looks like a base58 hash or Solana public key (43-44 characters), "
            "not a deposit address",
        )
    if is_near_implicit_account(value) or is_near_named_account(value):
        return True, None
    if value.startswith("T"):
        return False, "this looks like a malformed TRON address (checksum or length is wrong)"
    if value.startswith("1") or value.startswith("3"):
        return False, "this looks like a malformed legacy Bitcoin address (checksum is wrong)"
    return False, "unrecognised deposit address format"
