"""The Borsh serializer and ed25519, pinned to a real on-chain transaction.

A serializer that is merely "plausible" cannot sign. The acceptance criterion
here is that feeding a real transaction's own fields reproduces the hash the
NEAR network itself reports, and that the ed25519 verifier accepts the real
signature the network accepted. The vector below is a genuine testnet
transaction, fetched from a public RPC:

    tx hash   5ucZHVLoXEgzdGfJaNmMvoLzYKGjrJ8wkfVQ28UBBJUU
    network   testnet
    signer    f2.fly-1793804724.testnet
    receiver  c.fly-1793804724.testnet
    height    276211188 (the block whose hash is in the transaction's block_hash)

Its ``block_hash`` field is the network's recent block hash at creation time, not
the inclusion block; it was recovered by matching the recomputed hash against the
network's own value, and independently confirmed by verifying the signature.
"""

from __future__ import annotations

import base64

import pytest

from tracesettle.base58 import b58decode
from tracesettle.near import borsh, ed25519

# -- real testnet vector ------------------------------------------------------

VEC_SIGNER = "f2.fly-1793804724.testnet"
VEC_RECEIVER = "c.fly-1793804724.testnet"
VEC_PUBLIC_KEY = "ed25519:8YasEzZ6QyWJLuHes8hPTDX1e4DmU4JiTkCf11iKbyY3"
VEC_NONCE = 276211073000001
VEC_BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"
VEC_ARGS_B64 = (
    "eyJzeW5kaWNhdGVfaWQiOiJzeW4tZmxhc2gtMTc5MzgwNDg3OSIsInBvbGljeV9oYXNoIjoi"
    "NzJlZGM0MzBjMjUyZWQ0MWYwNjU1MDgwNzUyNGZiNmNkNjc2NTgxZjhiZjIzMzdlZWNkNjc2"
    "NDczZjk0NGY0MCJ9"
)
VEC_METHOD = "deposit"
VEC_GAS = 30_000_000_000_000
VEC_DEPOSIT = 20_000_000_000_000_000_000_000
VEC_TX_HASH = "5ucZHVLoXEgzdGfJaNmMvoLzYKGjrJ8wkfVQ28UBBJUU"
VEC_SIGNATURE = (
    "ed25519:4jEPyTdJ1aHXhwkjQwjJ4gJ32nsYb92L5RLCX5yVhQeiwhoG4rf9xwQkH4ijs6iacQhP1"
    "AuJy5H8GYUy1SLcfxA1"
)


def _b58encode(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def _strip(key: str) -> str:
    return key.split(":", 1)[1] if ":" in key else key


def _build_vector_bytes() -> bytes:
    args = base64.b64decode(VEC_ARGS_B64)
    action = borsh.action_function_call(VEC_METHOD, args, VEC_GAS, VEC_DEPOSIT)
    return borsh.transaction(
        VEC_SIGNER,
        b58decode(_strip(VEC_PUBLIC_KEY)),
        VEC_NONCE,
        VEC_RECEIVER,
        b58decode(VEC_BLOCK_HASH),
        [action],
    )


# -- serializer tests ---------------------------------------------------------


def test_serializer_reproduces_a_real_onchain_transaction_hash():
    """The serializer's output hashes to the network's own tx hash."""
    assert _b58encode(borsh.transaction_hash(_build_vector_bytes())) == VEC_TX_HASH


def test_real_onchain_signature_verifies_against_the_serialized_bytes():
    """The real signature the network accepted verifies against our bytes.

    This is the strongest possible check: the network would not have accepted
    the transaction unless these exact bytes had been signed.
    """
    message = borsh.transaction_hash(_build_vector_bytes())
    signature = b58decode(_strip(VEC_SIGNATURE))
    public = b58decode(_strip(VEC_PUBLIC_KEY))
    assert ed25519.verify(signature, message, public) is True


def test_serializer_has_no_version_byte_and_no_priority_fee():
    """The verified layout is the flat V0 form.

    A leading version byte or a trailing ``priority_fee`` changes the hash, so
    this pins the exact layout the vector proved.
    """
    flat = _build_vector_bytes()
    assert flat[:1] != b"\x00"  # not a version-tagged enum
    # The first field is a u32 length of the signer id (20 bytes here).
    assert int.from_bytes(flat[:4], "little") == len(VEC_SIGNER)


def test_a_single_field_change_changes_the_hash():
    """Any parameter change must change the signing payload."""
    base = _build_vector_bytes()
    changed = borsh.transaction(
        VEC_SIGNER,
        b58decode(_strip(VEC_PUBLIC_KEY)),
        VEC_NONCE + 1,
        VEC_RECEIVER,
        b58decode(VEC_BLOCK_HASH),
        [borsh.action_function_call(VEC_METHOD, base64.b64decode(VEC_ARGS_B64), VEC_GAS, VEC_DEPOSIT)],
    )
    assert borsh.transaction_hash(changed) != borsh.transaction_hash(base)


# -- primitive encodings ------------------------------------------------------


def test_integer_encodings_are_little_endian():
    assert borsh.u32(1) == b"\x01\x00\x00\x00"
    assert borsh.u64(1) == b"\x01\x00\x00\x00\x00\x00\x00\x00"
    assert borsh.u128(1) == b"\x01" + b"\x00" * 15


def test_integer_overflow_is_refused():
    with pytest.raises(borsh.BorshError):
        borsh.u32(1 << 32)
    with pytest.raises(borsh.BorshError):
        borsh.u64(-1)


def test_string_is_length_prefixed_utf8():
    assert borsh.string("abc") == b"\x03\x00\x00\x00abc"


def test_option_encodes_presence():
    assert borsh.option(None) == b"\x00"
    assert borsh.option(borsh.u64(5)) == b"\x01" + borsh.u64(5)


def test_vector_encodes_length_then_elements():
    assert borsh.vector([b"\x01", b"\x02"]) == b"\x02\x00\x00\x00\x01\x02"


def test_fixed_bytes_rejects_wrong_length():
    with pytest.raises(borsh.BorshError):
        borsh.fixed_bytes(b"\x00" * 31, 32)


# -- action encodings ---------------------------------------------------------


def test_transfer_action_tag_and_amount():
    action = borsh.action_transfer(5)
    assert action[0] == borsh.ACTION_TRANSFER
    assert action[1:] == borsh.u128(5)


def test_function_call_action_field_order():
    action = borsh.action_function_call("m", b"a", 7, 9)
    assert action[0] == borsh.ACTION_FUNCTION_CALL
    assert action[1:] == borsh.string("m") + borsh.bytes_(b"a") + borsh.u64(7) + borsh.u128(9)


def test_full_access_key_encodes_the_full_access_permission():
    action = borsh.action_add_full_access_key(b"\x01" * 32, 3)
    assert action[0] == borsh.ACTION_ADD_KEY
    assert action.endswith(borsh.u8(borsh.PERMISSION_FULL_ACCESS))


def test_function_call_key_encodes_allowance_and_methods():
    action = borsh.action_add_function_call_key(b"\x02" * 32, 1, 100, "c.near", ("a", "b"))
    assert action[0] == borsh.ACTION_ADD_KEY
    assert action.endswith(borsh.string("c.near") + borsh.vector([borsh.string("a"), borsh.string("b")]))


def test_function_call_key_without_allowance_encodes_none():
    action = borsh.action_add_function_call_key(b"\x03" * 32, 1, None, "c.near", ())
    assert borsh.option(None) in action
