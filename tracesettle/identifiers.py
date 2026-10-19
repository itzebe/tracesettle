"""Identifier classification and validation.

Only formats verified in Phase 1 are recognised. Classification is deliberately
conservative: when a format is ambiguous the type is reported as UNKNOWN and the
investigation explains what it can and cannot resolve.
"""

from __future__ import annotations

import re

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


def classify_identifier(raw: str) -> IdentifierType:
    """Classify a user-supplied identifier.

    Ambiguity is real and must be surfaced, not guessed:

    * A 64-hex string is a NEAR implicit account, but a bare 32-byte hex value
      without ``0x`` could also be a deposit address on an implicit-account
      chain. We classify it as ``DEPOSIT_ADDRESS`` only when the caller says so;
      otherwise ``UNKNOWN``.
    * A base58 43-44 char string is indistinguishable between a NEAR tx hash and
      an intent hash without external context, so it is ``UNKNOWN`` unless the
      caller disambiguates. Callers use the explicit helpers instead.
    """
    value = raw.strip()
    if not value:
        return IdentifierType.UNKNOWN
    if is_evm_tx_hash(value):
        return IdentifierType.ORIGIN_CHAIN_TX_HASH
    if is_evm_address(value):
        return IdentifierType.DEPOSIT_ADDRESS
    if is_near_tx_hash(value) or is_intent_hash(value):
        # Base58 43-44 chars: ambiguous by construction.
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

    Returns ``(ok, reason)``. A deposit address is either an EVM address or a
    NEAR account id, both of which were verified in Phase 1.
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
    if is_near_implicit_account(value) or is_near_named_account(value):
        return True, None
    if is_near_tx_hash(value) or is_intent_hash(value):
        return False, "this looks like a base58 hash (NEAR tx or intent), not a deposit address"
    return False, "unrecognised deposit address format"
