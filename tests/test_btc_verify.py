"""Unit tests for the reusable Bitcoin verification primitives.

These exercise the real code paths in :mod:`tracesettle.btc_verify` — address
decoding, local txid recomputation, and candidate selection. Raw transaction bytes
and addresses are the real captured ones from ``evidence/raw/``.
"""

from __future__ import annotations

import pytest

from tracesettle.btc_verify import (
    Candidate,
    CandidateTier,
    VerificationLevel,
    address_to_scriptpubkey,
    compute_txid,
    select_refund_candidate,
    verify_tx_identity,
)

from conftest import RAW_DIR

# Real captured bytes; the txids are the real on-chain identifiers.
DEPOSIT_TXID = "9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226"
REFUND_TXID = "377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f"
REFUND_ADDRESS = "bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw"
# The scriptPubKey the refund transaction actually pays.
REFUND_SCRIPT = "0014f79d4fd137b0e00f6df4c92dc450b6878675a741"


def _raw(name: str) -> str:
    return (RAW_DIR / name).read_text().strip()


# --- address decoding -------------------------------------------------------


def test_p2wpkh_address_decodes_to_expected_script():
    assert address_to_scriptpubkey(REFUND_ADDRESS) == bytes.fromhex(REFUND_SCRIPT)


def test_p2pkh_and_p2sh_addresses_decode():
    # The Bitcoin genesis coinbase address and a well-known P2SH address.
    assert (
        address_to_scriptpubkey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").hex()
        == "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"
    )
    assert (
        address_to_scriptpubkey("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").hex()
        == "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87"
    )


def test_p2tr_address_uses_bech32m():
    # BIP341 test vector: a taproot address must decode to an OP_1 witness program.
    spk = address_to_scriptpubkey("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
    assert spk is not None
    assert spk.hex() == "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "notanaddress",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",  # bad bech32 checksum
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNaX",  # bad base58 checksum
    ],
)
def test_malformed_addresses_return_none(bad):
    assert address_to_scriptpubkey(bad) is None


# --- local txid recomputation ----------------------------------------------


def test_compute_txid_matches_real_deposit_bytes():
    assert compute_txid(bytes.fromhex(_raw("btc_tx_deposit.hex"))) == DEPOSIT_TXID


def test_compute_txid_matches_real_refund_bytes():
    assert compute_txid(bytes.fromhex(_raw("btc_tx_refund.hex"))) == REFUND_TXID


def test_compute_txid_rejects_unparseable_bytes():
    assert compute_txid(b"") is None
    assert compute_txid(b"\x02\x00\x00") is None
    assert compute_txid(bytes.fromhex("00" * 3)) is None


def test_verify_tx_identity_confirms_match():
    result = verify_tx_identity(_raw("btc_tx_refund.hex"), REFUND_TXID)
    assert result.validated is True
    assert result.level is VerificationLevel.IDENTITY_LOCALLY_VALIDATED
    assert result.computed_txid == REFUND_TXID


def test_verify_tx_identity_flags_mismatch():
    # Real refund bytes, but claiming they are the deposit transaction.
    result = verify_tx_identity(_raw("btc_tx_refund.hex"), DEPOSIT_TXID)
    assert result.validated is False
    assert result.computed_txid == REFUND_TXID
    assert "different txid" in result.reason


def test_verify_tx_identity_unavailable_when_bytes_missing():
    result = verify_tx_identity(None, REFUND_TXID)
    assert result.validated is False
    assert result.level is VerificationLevel.UNAVAILABLE


def test_verify_tx_identity_rejects_non_hex():
    result = verify_tx_identity("zzzz", REFUND_TXID)
    assert result.validated is False
    assert result.level is VerificationLevel.UNAVAILABLE


# --- candidate selection ----------------------------------------------------


def _cand(txid: str, *, confirmed=True, pays=True, script=True, validated=True, discovery="history"):
    return Candidate(
        txid=txid,
        confirmed=confirmed,
        pays_recipient=pays,
        recipient_script_matched=script,
        observed_sats=12884,
        block_height=972263,
        block_time=1792472756,
        identity_validated=validated,
        discovery=discovery,
    )


def test_explicit_named_candidate_is_selected():
    result = select_refund_candidate([_cand("a", discovery="explicit")], [], history_complete=True)
    assert result.tier is CandidateTier.EXPLICIT_IDENTIFIER
    assert result.selected is not None and result.selected.txid == "a"
    # With identity validated and the script matched, the level is SCRIPT_VALIDATED.
    assert result.verification_level is VerificationLevel.SCRIPT_VALIDATED


def test_explicit_candidate_level_reflects_checks_actually_performed():
    # Identity validated but script not matched: the level is IDENTITY_LOCALLY_VALIDATED,
    # never SCRIPT_VALIDATED.
    result = select_refund_candidate(
        [_cand("a", script=False, discovery="explicit")], [], history_complete=True
    )
    assert result.verification_level is VerificationLevel.IDENTITY_LOCALLY_VALIDATED
    # Script matched but identity not validated: the level cannot exceed
    # EXPLORER_REPORTED, because a script match on unvalidated bytes proves nothing
    # about which transaction was matched.
    result2 = select_refund_candidate(
        [_cand("a", validated=False, discovery="explicit")], [], history_complete=True
    )
    assert result2.verification_level is VerificationLevel.EXPLORER_REPORTED


def test_multiple_explicit_candidates_are_ambiguous():
    result = select_refund_candidate(
        [_cand("a", discovery="explicit"), _cand("b", discovery="explicit")], [], history_complete=True
    )
    assert result.tier is CandidateTier.AMBIGUOUS
    assert result.selected is None


def test_unique_history_candidate_requires_complete_history():
    # One match but an incomplete history: uniqueness cannot be asserted.
    result = select_refund_candidate([], [_cand("a")], history_complete=False)
    assert result.tier is CandidateTier.INCOMPLETE_SEARCH
    assert result.selected is None
    # Same single match on a complete history: selected.
    result2 = select_refund_candidate([], [_cand("a")], history_complete=True)
    assert result2.tier is CandidateTier.UNIQUE_ADDRESS_MATCH
    assert result2.selected is not None


def test_multiple_history_candidates_are_ambiguous():
    result = select_refund_candidate([], [_cand("a"), _cand("b")], history_complete=True)
    assert result.tier is CandidateTier.AMBIGUOUS
    assert result.selected is None


def test_no_candidate_on_complete_history_is_none():
    result = select_refund_candidate([], [], history_complete=True)
    assert result.tier is CandidateTier.NONE
    assert result.selected is None


def test_no_candidate_on_incomplete_history_is_not_none():
    result = select_refund_candidate([], [], history_complete=False)
    assert result.tier is CandidateTier.INCOMPLETE_SEARCH
    assert "absence cannot be established" in result.reason


def test_unconfirmed_or_nonpaying_candidates_are_not_usable():
    result = select_refund_candidate(
        [], [_cand("a", confirmed=False), _cand("b", pays=False)], history_complete=True
    )
    assert result.tier is CandidateTier.NONE


def test_selection_is_deterministic():
    args = ([_cand("a")], [_cand("b")])
    first = select_refund_candidate(*args, history_complete=True)
    second = select_refund_candidate(*args, history_complete=True)
    assert first == second
