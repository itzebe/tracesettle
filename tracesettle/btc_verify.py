"""Bitcoin refund verification primitives — reusable across chain refund flows.

This module holds the chain-agnostic *verification* steps that must not be buried
inside reconciliation logic:

1. **Local transaction-identity validation** — recompute the txid from the raw
   transaction bytes and compare it to the id under investigation, so a host
   cannot hand back bytes for a different transaction.
2. **Script-level address decoding** — decode a Bitcoin address to its exact
   ``scriptPubKey`` and match scripts, instead of trusting string equality.
3. **Candidate discovery and selection** — the tiered rules that decide whether a
   payout can be correlated to the investigated intent, and which explicitly
   refuse to correlate on amount, timestamp, or mere uniqueness.

Nothing here decides a stage state; that remains :mod:`tracesettle.reconcile`'s
job. Nothing here signs, submits, or mutates chain state. Every function is pure
and deterministic: identical inputs yield identical outputs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .base58 import b58check_decode, b58decode

# ---------------------------------------------------------------------------
# Verification levels (weakest -> strongest). The tool reports the level it
# actually reached; it never claims a stronger one than the evidence supports.
# ---------------------------------------------------------------------------


class VerificationLevel(str, Enum):
    """How strongly a Bitcoin transaction fact was established.

    The tool reports the level it actually reached; it never claims a stronger
    one than the evidence supports. Each level is a conjunction of facts the tool
    itself checked, not a capability it might have used:

    * ``EXPLORER_REPORTED`` — a host stated the fact; TRACESETTLE did not check it.
    * ``IDENTITY_LOCALLY_VALIDATED`` — the raw bytes were fetched and the txid was
      recomputed locally and matched.
    * ``SCRIPT_VALIDATED`` — identity was validated *and* the recipient's
      ``scriptPubKey`` was decoded and matched to an output's script.

    There is deliberately no level above ``SCRIPT_VALIDATED``. A second Esplora
    host is only an availability fallback serving the same chain state, so it is
    never counted as independent corroboration (see ``docs/REFUND_VERIFICATION.md``).
    """

    #: The source could not be queried.
    UNAVAILABLE = "UNAVAILABLE"
    #: A source reported the fact; TRACESETTLE did not check it.
    EXPLORER_REPORTED = "EXPLORER_REPORTED"
    #: Raw bytes were retrieved and the txid was recomputed and matched locally.
    IDENTITY_LOCALLY_VALIDATED = "IDENTITY_LOCALLY_VALIDATED"
    #: Identity validated *and* the recipient script was decoded and matched.
    SCRIPT_VALIDATED = "SCRIPT_VALIDATED"


def verification_level_for(
    *, identity_validated: bool, recipient_script_verified: bool
) -> VerificationLevel:
    """The strongest level the tool actually reached, from the facts it checked.

    This is a pure function of the two independent checks so the reported level
    can never drift from what was done: script validation requires identity
    validation, because a script match on unvalidated bytes proves nothing about
    *which* transaction was matched.
    """
    if identity_validated and recipient_script_verified:
        return VerificationLevel.SCRIPT_VALIDATED
    if identity_validated:
        return VerificationLevel.IDENTITY_LOCALLY_VALIDATED
    return VerificationLevel.EXPLORER_REPORTED


# ---------------------------------------------------------------------------
# Base58 / bech32 decoding -> scriptPubKey
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_HRP = "bc"  # mainnet
_BECH32M_CONST = 0x2BC830A3


def _b58decode(s: str) -> bytes | None:
    return b58decode(s)


def _b58check(address: str) -> bytes | None:
    return b58check_decode(address)


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(address: str) -> tuple[str, list[int], bool] | None:
    """Return (hrp, data-words, is_bech32m) or ``None`` if invalid."""
    if not (8 <= len(address) <= 90):
        return None
    if address.lower() != address and address.upper() != address:
        return None
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address):
        return None
    hrp = address[:pos]
    data_part = address[pos + 1 :]
    data: list[int] = []
    for ch in data_part:
        idx = _BECH32_CHARSET.find(ch)
        if idx < 0:
            return None
        data.append(idx)
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        return hrp, data[:-6], False
    if const == _BECH32M_CONST:
        return hrp, data[:-6], True
    return None


def _convert_bits(data: list[int], from_bits: int, to_bits: int) -> list[int] | None:
    acc = 0
    bits = 0
    out: list[int] = []
    maxv = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            return None
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    if bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return out


def address_to_scriptpubkey(address: str | None) -> bytes | None:
    """Decode a mainnet Bitcoin address to its ``scriptPubKey``, or ``None``.

    Supports P2PKH/P2SH (base58check) and segwit v0/v1 (bech32/bech32m). This is
    how the tool verifies a recipient by *script* rather than by string equality.
    It never raises; an unsupported or malformed address returns ``None`` so the
    caller can classify the limitation instead of guessing.
    """
    if not address or not isinstance(address, str):
        return None
    address = address.strip()

    # Segwit (bech32 / bech32m)
    if address.lower().startswith(_BECH32_HRP + "1"):
        decoded = _bech32_decode(address)
        if decoded is None:
            return None
        hrp, data, is_m = decoded
        if hrp != _BECH32_HRP or not data:
            return None
        version = data[0]
        if version > 16:
            return None
        prog = _convert_bits(data[1:], 5, 8)
        if prog is None or not (2 <= len(prog) <= 40):
            return None
        # BIP350: v0 must use bech32; v1+ must use bech32m.
        if version == 0 and is_m:
            return None
        if version >= 1 and not is_m:
            return None
        if version == 0 and len(prog) not in (20, 32):
            return None
        op = 0x00 if version == 0 else 0x50 + version
        return bytes([op, len(prog)]) + bytes(prog)

    # Legacy base58check
    payload = _b58check(address)
    if payload is None or len(payload) != 21:
        return None
    version, h160 = payload[0], payload[1:]
    if version == 0x00:  # P2PKH
        return bytes([0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC])
    if version == 0x05:  # P2SH
        return bytes([0xA9, 0x14]) + h160 + bytes([0x87])
    return None


# ---------------------------------------------------------------------------
# Local transaction-identity validation
# ---------------------------------------------------------------------------


def _read_varint(raw: bytes, i: int) -> tuple[int, int] | None:
    if i >= len(raw):
        return None
    first = raw[i]
    if first < 0xFD:
        return first, i + 1
    if first == 0xFD:
        return int.from_bytes(raw[i + 1 : i + 3], "little"), i + 3
    if first == 0xFE:
        return int.from_bytes(raw[i + 1 : i + 5], "little"), i + 5
    return int.from_bytes(raw[i + 1 : i + 9], "little"), i + 9


def _strip_witness(raw: bytes) -> bytes | None:
    """Return the non-witness serialization of a transaction, or ``None``.

    The txid is defined as ``SHA256d`` over this stripped form (BIP141), so a
    segwit transaction's witness data must be removed before hashing.
    """
    i = 0
    if len(raw) < 5:
        return None
    version = raw[0:4]
    i = 4
    segwit = len(raw) > 5 and raw[4] == 0x00 and raw[5] == 0x01
    if segwit:
        i = 6
    res = _read_varint(raw, i)
    if res is None:
        return None
    n_in, i = res
    ins_start = i
    for _ in range(n_in):
        i += 36  # outpoint (32-byte txid + 4-byte vout)
        res = _read_varint(raw, i)
        if res is None:
            return None
        script_len, i = res
        i += script_len + 4  # scriptSig + sequence
        if i > len(raw):
            return None
    ins = raw[ins_start:i]
    res = _read_varint(raw, i)
    if res is None:
        return None
    n_out, i = res
    outs_start = i
    for _ in range(n_out):
        i += 8  # value
        res = _read_varint(raw, i)
        if res is None:
            return None
        script_len, i = res
        i += script_len
        if i > len(raw):
            return None
    outs = raw[outs_start:i]
    if segwit:
        for _ in range(n_in):
            res = _read_varint(raw, i)
            if res is None:
                return None
            n_items, i = res
            for _ in range(n_items):
                res = _read_varint(raw, i)
                if res is None:
                    return None
                item_len, i = res
                i += item_len
                if i > len(raw):
                    return None
    if i + 4 > len(raw):
        return None
    locktime = raw[i : i + 4]
    if i + 4 != len(raw):
        # Trailing bytes mean we did not parse this transaction cleanly.
        return None
    return version + bytes([n_in]) + ins + bytes([n_out]) + outs + locktime


def compute_txid(raw: bytes | None) -> str | None:
    """Recompute a Bitcoin txid from raw transaction bytes, or ``None``.

    The result is the big-endian hex form used by explorers and the RPC. A
    ``None`` return means the bytes could not be parsed as a transaction; the
    caller must treat that as *unvalidated*, never as a match.
    """
    if not raw:
        return None
    stripped = _strip_witness(raw)
    if stripped is None:
        return None
    return hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex()


@dataclass(frozen=True)
class TxIdentity:
    """Result of validating raw transaction bytes against an expected txid."""

    level: VerificationLevel
    validated: bool
    computed_txid: str | None
    expected_txid: str | None
    reason: str


def verify_tx_identity(raw_hex: str | None, expected_txid: str | None) -> TxIdentity:
    """Validate that ``raw_hex`` really hashes to ``expected_txid``."""
    if not raw_hex or not isinstance(raw_hex, str):
        return TxIdentity(
            VerificationLevel.UNAVAILABLE,
            False,
            None,
            expected_txid,
            "raw transaction bytes were not retrieved, so the transaction identity could not be validated locally",
        )
    try:
        raw = bytes.fromhex(raw_hex.strip())
    except ValueError:
        return TxIdentity(
            VerificationLevel.UNAVAILABLE,
            False,
            None,
            expected_txid,
            "the raw transaction was not valid hex, so its identity could not be validated",
        )
    computed = compute_txid(raw)
    if computed is None:
        return TxIdentity(
            VerificationLevel.UNAVAILABLE,
            False,
            None,
            expected_txid,
            "the raw transaction could not be parsed, so its identity could not be validated",
        )
    if not expected_txid:
        return TxIdentity(
            VerificationLevel.IDENTITY_LOCALLY_VALIDATED,
            False,
            computed,
            None,
            "the raw transaction parsed, but there was no expected txid to compare it against",
        )
    if computed.lower() == expected_txid.lower():
        return TxIdentity(
            VerificationLevel.IDENTITY_LOCALLY_VALIDATED,
            True,
            computed,
            expected_txid,
            "the raw transaction bytes hash to the requested txid, so the bytes match the identifier under investigation",
        )
    return TxIdentity(
        VerificationLevel.EXPLORER_REPORTED,
        False,
        computed,
        expected_txid,
        "the raw transaction bytes hash to a different txid than requested; the returned bytes do not match the identifier and must not be trusted",
    )


# ---------------------------------------------------------------------------
# Candidate discovery and selection
# ---------------------------------------------------------------------------


class CandidateTier(str, Enum):
    """How a refund candidate was discovered, strongest evidence first."""

    #: The provider named the transaction hash explicitly.
    EXPLICIT_IDENTIFIER = "A_EXPLICIT_IDENTIFIER"
    #: A single address-history payout matches the correlation criteria.
    UNIQUE_ADDRESS_MATCH = "B_UNIQUE_ADDRESS_MATCH"
    #: Several payouts match and nothing distinguishes them.
    AMBIGUOUS = "C_AMBIGUOUS"
    #: The address history could not be shown to be complete, so no uniqueness claim.
    INCOMPLETE_SEARCH = "C_INCOMPLETE_SEARCH"
    #: No payout matched within a demonstrably complete search scope.
    NONE = "D_NONE"


@dataclass(frozen=True)
class Candidate:
    """One possible refund transaction, with what was checked about it."""

    txid: str
    confirmed: bool
    pays_recipient: bool
    recipient_script_matched: bool
    observed_sats: int | None
    block_height: int | None
    block_time: int | None
    identity_validated: bool
    discovery: str  # "explicit" | "address_history"
    limitations: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SelectionResult:
    """Outcome of candidate selection, with a machine-readable reason."""

    tier: CandidateTier
    selected: Candidate | None
    candidates: tuple[Candidate, ...]
    reason: str
    correlation_method: str
    verification_level: VerificationLevel


def select_refund_candidate(
    explicit: Iterable[Candidate],
    history: Iterable[Candidate],
    *,
    history_complete: bool,
) -> SelectionResult:
    """Choose at most one refund candidate, or refuse to.

    Rules, in order:

    * **Tier A** — exactly one provider-named candidate that pays the expected
      recipient script and is confirmed. An explicit identifier is strong
      correlation; if several provider-named candidates match, that is ambiguous.
    * **Tier B** — with no provider-named candidate, exactly one confirmed
      address-history payout whose recipient *script* matches. Uniqueness is
      necessary but never sufficient on its own: the caller must still have the
      on-chain withdrawal recipient as the correlation anchor.
    * **Tier C** — several matching payouts, or several provider-named matches,
      with nothing to distinguish them.
    * **Tier D** — no matching candidate.

    Amount and timestamp are never used to choose between candidates.
    """
    explicit_list = tuple(explicit)
    history_list = tuple(history)

    def usable(c: Candidate) -> bool:
        return c.confirmed and c.pays_recipient

    def level_for(c: Candidate) -> VerificationLevel:
        return verification_level_for(
            identity_validated=c.identity_validated,
            recipient_script_verified=c.recipient_script_matched,
        )

    named_ok = [c for c in explicit_list if usable(c)]
    if len(named_ok) == 1:
        return SelectionResult(
            CandidateTier.EXPLICIT_IDENTIFIER,
            named_ok[0],
            explicit_list,
            "the provider named exactly one confirmed transaction paying the expected recipient",
            "provider-named transaction hash",
            level_for(named_ok[0]),
        )
    if len(named_ok) > 1:
        return SelectionResult(
            CandidateTier.AMBIGUOUS,
            None,
            explicit_list,
            f"the provider named {len(named_ok)} confirmed transactions paying the expected "
            "recipient, and nothing distinguishes them",
            "none",
            VerificationLevel.EXPLORER_REPORTED,
        )

    history_ok = [c for c in history_list if usable(c)]

    if len(history_ok) == 1:
        # Uniqueness is necessary but not sufficient: it can only be asserted on a
        # demonstrably complete history.
        if not history_complete:
            return SelectionResult(
                CandidateTier.INCOMPLETE_SEARCH,
                None,
                history_list,
                "one address-history payout matches, but the history could not be shown to be "
                "complete, so uniqueness cannot be established",
                "none",
                VerificationLevel.UNAVAILABLE,
            )
        c = history_ok[0]
        return SelectionResult(
            CandidateTier.UNIQUE_ADDRESS_MATCH,
            c,
            history_list,
            "exactly one confirmed address-history payout pays the expected recipient",
            "on-chain withdrawal recipient address",
            level_for(c),
        )
    if len(history_ok) > 1:
        return SelectionResult(
            CandidateTier.AMBIGUOUS,
            None,
            history_list,
            f"{len(history_ok)} confirmed address-history payouts pay the expected recipient, and "
            "nothing distinguishes them",
            "none",
            VerificationLevel.EXPLORER_REPORTED,
        )
    if not history_complete:
        # No match found, but the search was not complete, so we cannot say the
        # payout is absent — only that it was not found in what we could see.
        return SelectionResult(
            CandidateTier.INCOMPLETE_SEARCH,
            None,
            history_list,
            "no matching payout was found, but the address history could not be shown to be "
            "complete, so absence cannot be established",
            "none",
            VerificationLevel.UNAVAILABLE,
        )
    return SelectionResult(
        CandidateTier.NONE,
        None,
        history_list,
        "no confirmed address-history payout pays the expected recipient within the searched scope",
        "none",
        VerificationLevel.EXPLORER_REPORTED,
    )
