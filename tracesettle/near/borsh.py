"""Minimal Borsh serialization for NEAR transaction signing.

NEAR signs ``sha256(borsh(Transaction))``. This module implements exactly the
subset of Borsh the NEAR transaction format needs, so a transaction's signing
payload can be produced from validated inputs *without* pulling in a third-party
SDK. That keeps the runtime dependency-free, which the project requires.

The encoding is verified against real on-chain transactions in
``tests/test_near_txbuild.py``: the serializer is fed the exact fields of a
transaction fetched from a public RPC and the recomputed hash must equal the
hash the network reports. A serializer that is merely "plausible" is worthless
for signing, so the test vector is the acceptance criterion.

Spec (https://borsh.io):
* integers are little-endian, fixed width;
* ``u32``/``u64`` are 4/8 bytes;
* a string/vector is a ``u32`` length followed by its bytes/elements;
* an ``Option<T>`` is a ``u8`` (0/1) then the value when present;
* an enum variant is a ``u8`` tag then the variant's fields.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

#: The NEAR signature domain prefix. A transaction hash is
#: ``sha256(borsh(tx))``; the *signature* is over that 32-byte digest directly.
#: NEAR also hashes messages for ``NEP-413`` with a different prefix, not used
#: here because this module only signs whole transactions.


class BorshError(ValueError):
    """A value could not be serialized as the requested Borsh type."""


def u8(value: int) -> bytes:
    return _int(value, 1)


def u32(value: int) -> bytes:
    return _int(value, 4)


def u64(value: int) -> bytes:
    return _int(value, 8)


def u128(value: int) -> bytes:
    return _int(value, 16)


def _int(value: int, size: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BorshError(f"expected an integer, got {type(value).__name__}")
    if value < 0:
        raise BorshError("Borsh unsigned integers cannot be negative")
    if value >= 1 << (8 * size):
        raise BorshError(f"integer {value} does not fit in {size} bytes")
    return value.to_bytes(size, "little")


def string(value: str) -> bytes:
    if not isinstance(value, str):
        raise BorshError("expected a string")
    raw = value.encode("utf-8")
    return u32(len(raw)) + raw


def bytes_(value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise BorshError("expected bytes")
    return u32(len(value)) + bytes(value)


def fixed_bytes(value: bytes, size: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != size:
        raise BorshError(f"expected exactly {size} bytes")
    return bytes(value)


def vector(items: Iterable[bytes]) -> bytes:
    items = list(items)
    return u32(len(items)) + b"".join(items)


def option(encoded: bytes | None) -> bytes:
    if encoded is None:
        return u8(0)
    return u8(1) + encoded


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def public_key_ed25519(raw32: bytes) -> bytes:
    """Borsh ``PublicKey`` for an ed25519 key: tag 0 then the 32 key bytes."""
    return u8(0) + fixed_bytes(raw32, 32)


def signature_ed25519(raw64: bytes) -> bytes:
    """Borsh ``Signature`` for ed25519: tag 0 then the 64 signature bytes."""
    return u8(0) + fixed_bytes(raw64, 64)


# -- NEAR action variants -----------------------------------------------------
#
# NEAR ``Action`` enum tags (near-primitives):
#   0 CreateAccount, 1 DeployContract, 2 FunctionCall, 3 Transfer,
#   4 Stake, 5 AddKey, 6 DeleteKey, 7 DeleteAccount, 8 Delegate,
#   9 DeployGlobalContract, 10 UseGlobalContract, 11 DeterministicStateInit.

ACTION_CREATE_ACCOUNT = 0
ACTION_FUNCTION_CALL = 2
ACTION_TRANSFER = 3
ACTION_ADD_KEY = 5
ACTION_DELETE_KEY = 6
ACTION_DELETE_ACCOUNT = 7

#: ``AccessKeyPermission`` tags: 0 FunctionCall, 1 FullAccess.
PERMISSION_FUNCTION_CALL = 0
PERMISSION_FULL_ACCESS = 1

#: ``AccessKeyPermission`` for a full-access key.
FULL_ACCESS = u8(PERMISSION_FULL_ACCESS)


def action_transfer(deposit: int) -> bytes:
    """``Action::Transfer(TransferAction { deposit: u128 })``."""
    return u8(ACTION_TRANSFER) + u128(deposit)


def action_function_call(
    method_name: str, args: bytes, gas: int, deposit: int
) -> bytes:
    """``Action::FunctionCall(FunctionCallAction { method_name, args, gas, deposit })``.

    Field order is the struct order NEAR serializes: ``method_name`` (string),
    ``args`` (Vec<u8>), ``gas`` (u64), ``deposit`` (u128).
    """
    return (
        u8(ACTION_FUNCTION_CALL)
        + string(method_name)
        + bytes_(args)
        + u64(gas)
        + u128(deposit)
    )


def action_create_account() -> bytes:
    return u8(ACTION_CREATE_ACCOUNT)


def action_delete_account(beneficiary_id: str) -> bytes:
    return u8(ACTION_DELETE_ACCOUNT) + string(beneficiary_id)


def action_delete_key(public_key_raw32: bytes) -> bytes:
    return u8(ACTION_DELETE_KEY) + public_key_ed25519(public_key_raw32)


def action_add_full_access_key(public_key_raw32: bytes, nonce: int) -> bytes:
    """``Action::AddKey`` with a full-access permission.

    ``AccessKey`` is ``{ nonce: u64, permission: AccessKeyPermission }``.
    """
    return (
        u8(ACTION_ADD_KEY)
        + public_key_ed25519(public_key_raw32)
        + u64(nonce)
        + FULL_ACCESS
    )


def action_add_function_call_key(
    public_key_raw32: bytes,
    nonce: int,
    allowance: int | None,
    receiver_id: str,
    method_names: tuple[str, ...],
) -> bytes:
    """``Action::AddKey`` with a function-call permission.

    ``allowance`` is ``Option<u128>``. ``method_names`` is a ``Vec<String>``;
    an empty vector means "all methods", which is the contract the access-key
    analysis relies on.
    """
    return (
        u8(ACTION_ADD_KEY)
        + public_key_ed25519(public_key_raw32)
        + u64(nonce)
        + u8(PERMISSION_FUNCTION_CALL)
        + option(None if allowance is None else u128(allowance))
        + string(receiver_id)
        + vector(string(m) for m in method_names)
    )


def transaction(
    signer_id: str,
    public_key_raw32: bytes,
    nonce: int,
    receiver_id: str,
    block_hash32: bytes,
    actions: Iterable[bytes],
) -> bytes:
    """Borsh-encode a NEAR ``Transaction`` (the V0 wire form).

    The struct order (near-primitives ``TransactionV0``) is::

        signer_id: AccountId,
        public_key: PublicKey,
        nonce: u64,
        receiver_id: AccountId,
        block_hash: Hash,
        actions: Vec<Action>,

    The hash that is signed is ``sha256`` of the bytes this returns.

    Verified against a real on-chain transaction
    (``5ucZHVLoXEgzdGfJaNmMvoLzYKGjrJ8wkfVQ28UBBJUU``): feeding the network's
    own fields reproduces the network's own hash exactly, with **no leading
    version byte and no trailing ``priority_fee``**. The protocol-80
    ``priority_fee`` field is therefore *not* serialized in the form this
    network accepted for that transaction; TraceSettle does not set a priority
    fee, so the V0 form is the one it emits. ``tests/test_near_txbuild.py``
    pins this vector, so a change to the layout breaks the build rather than
    silently producing an unsignable transaction.
    """
    return (
        string(signer_id)
        + public_key_ed25519(public_key_raw32)
        + u64(nonce)
        + string(receiver_id)
        + fixed_bytes(block_hash32, 32)
        + vector(actions)
    )


def transaction_hash(signed_transaction_bytes: bytes) -> bytes:
    """The 32-byte hash NEAR signs: ``sha256(borsh(Transaction))``."""
    return sha256(signed_transaction_bytes)
