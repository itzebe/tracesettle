"""A strict, round-trip-checked decoder for a NEAR ``SignedTransaction``.

The execution pipeline stores the exact signed bytes it broadcast (the ledger's
``signed_b64``). Recovery can therefore re-establish *what was actually signed*
without re-running the build, which is what lets a recovered transaction be
verified to the same standard as one still in memory - amount, receiver and
actions - instead of being capped at "the hash and finality match".

The decoder is deliberately conservative. It only accepts the forms TraceSettle
itself emits (the V0 ``Transaction`` wire form and the action variants the
builders use). Anything it does not fully understand raises
:class:`TransactionDecodeError` rather than returning a best-effort object, so a
caller can never mistake a partial parse for a faithful one.

Two independent guarantees are enforced before the result is trusted:

* **Re-serialization is byte-identical.** The parsed fields are fed back through
  the same encoders used to build the transaction; if the bytes differ, the
  decode is rejected. A transaction with an action the decoder mis-ordered or a
  field it dropped would not survive this check.
* **The signature verifies.** The ed25519 signature is checked over
  ``sha256(unsigned_bytes)`` under the transaction's own public key, so the bytes
  are proven to be a signed transaction for that key and not a stray blob.

Neither check trusts the caller: both are recomputed from the bytes.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from . import borsh, ed25519
from .assets import AssetError, NearAsset, resolve_asset
from .networks import NearNetwork
from .txbuild import (
    OP_FT_TRANSFER,
    OP_TRANSFER,
    NearTransaction,
    _b58encode,
)


class TransactionDecodeError(ValueError):
    """The bytes are not a NEAR ``SignedTransaction`` this tool can trust."""


class _Cursor:
    """A bounds-checked reader over a byte string."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise TransactionDecodeError(
                f"unexpected end of input: needed {n} bytes at offset {self.pos}"
            )
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return int.from_bytes(self.take(1), "little")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def u128(self) -> int:
        return int.from_bytes(self.take(16), "little")

    def string(self) -> str:
        length = self.u32()
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TransactionDecodeError(f"a string field is not valid UTF-8: {exc}") from exc

    def bytes_(self) -> bytes:
        return self.take(self.u32())

    def fixed(self, size: int) -> bytes:
        return self.take(size)

    @property
    def exhausted(self) -> bool:
        return self.pos == len(self.data)


@dataclass(frozen=True)
class DecodedTransaction:
    """A NEAR transaction decoded from its exact signed bytes."""

    network: NearNetwork
    signer_id: str
    public_key_raw: bytes
    nonce: int
    receiver_id: str
    block_hash_raw: bytes
    actions: tuple[bytes, ...]
    signature_raw: bytes
    unsigned_bytes: bytes
    signed_bytes: bytes
    #: A human-facing description of the first action, when it is one TraceSettle
    #: builds. Never used for a security decision.
    operation: str
    asset: NearAsset
    amount_base: int
    destination: str
    notes: list[str] = field(default_factory=list)

    @property
    def tx_hash_bytes(self) -> bytes:
        return borsh.transaction_hash(self.unsigned_bytes)

    @property
    def tx_hash(self) -> str:
        return _b58encode(self.tx_hash_bytes)

    @property
    def public_key(self) -> str:
        return "ed25519:" + _b58encode(self.public_key_raw)

    @property
    def block_hash(self) -> str:
        return _b58encode(self.block_hash_raw)

    def to_transaction(self) -> NearTransaction:
        """Rebuild the :class:`NearTransaction` the bytes describe.

        The result is only as trustworthy as the decode that produced it; the
        caller should treat it as evidence of what was signed, not as a fresh
        authorization to sign.
        """
        from .assets import from_base_units

        return NearTransaction(
            network=self.network,
            signer_id=self.signer_id,
            public_key=self.public_key,
            nonce=self.nonce,
            receiver_id=self.receiver_id,
            block_hash=self.block_hash,
            actions=self.actions,
            operation=self.operation,
            asset=self.asset,
            amount_base=self.amount_base,
            amount_human=from_base_units(self.amount_base, self.asset),
            destination=self.destination,
            guard_chain=f"near-{self.network.value}",
            guard_asset=self.asset.identifier.upper(),
            extra={"decoded": True, "notes": list(self.notes)},
        )


def decode_signed_transaction(
    signed_bytes: bytes,
    *,
    network: NearNetwork,
    verify_signature: bool = True,
) -> DecodedTransaction:
    """Decode ``signed_bytes`` into a :class:`DecodedTransaction`, or raise.

    ``network`` is required and used only for the asset registry and the
    ``near-<network>`` chain label; the bytes themselves carry no network. The
    caller must therefore pass the network the ledger recorded, not a guess.
    """
    if not isinstance(signed_bytes, (bytes, bytearray)) or not signed_bytes:
        raise TransactionDecodeError("signed transaction bytes are empty")
    raw = bytes(signed_bytes)
    cur = _Cursor(raw)

    signer_id = cur.string()
    pub_tag = cur.u8()
    if pub_tag != 0:
        raise TransactionDecodeError(f"unsupported public-key tag {pub_tag} (only ed25519)")
    public_key_raw = cur.fixed(32)
    nonce = cur.u64()
    receiver_id = cur.string()
    block_hash_raw = cur.fixed(32)

    action_count = cur.u32()
    actions: list[bytes] = []
    for _ in range(action_count):
        start = cur.pos
        _skip_action(cur)
        actions.append(raw[start : cur.pos])

    if cur.pos + 1 + 64 != len(raw):
        raise TransactionDecodeError(
            "trailing bytes after the transaction (expected a 65-byte signature)"
        )
    sig_tag = cur.u8()
    if sig_tag != 0:
        raise TransactionDecodeError(f"unsupported signature tag {sig_tag} (only ed25519)")
    signature_raw = cur.fixed(64)
    if not cur.exhausted:
        raise TransactionDecodeError("trailing bytes after the signature")

    unsigned = raw[: len(raw) - 65]

    # Re-serialize from the parsed fields. A mismatch means the decode is not
    # faithful, so it is refused rather than used.
    reencoded = borsh.transaction(
        signer_id, public_key_raw, nonce, receiver_id, block_hash_raw, actions
    )
    if reencoded != unsigned:
        raise TransactionDecodeError(
            "the decoded transaction does not re-serialize to the same bytes; refusing to trust it"
        )

    if verify_signature:
        # NEAR signs ``sha256(borsh(Transaction))``, i.e. the transaction hash,
        # not the raw bytes.
        if not ed25519.verify(signature_raw, borsh.transaction_hash(unsigned), public_key_raw):
            raise TransactionDecodeError(
                "the ed25519 signature does not verify over the transaction's own bytes"
            )

    operation, asset, amount_base, destination, notes = _describe(
        network=network, receiver_id=receiver_id, actions=actions
    )

    return DecodedTransaction(
        network=network,
        signer_id=signer_id,
        public_key_raw=public_key_raw,
        nonce=nonce,
        receiver_id=receiver_id,
        block_hash_raw=block_hash_raw,
        actions=tuple(actions),
        signature_raw=signature_raw,
        unsigned_bytes=unsigned,
        signed_bytes=raw,
        operation=operation,
        asset=asset,
        amount_base=amount_base,
        destination=destination,
        notes=notes,
    )


def decode_signed_b64(
    signed_b64: str, *, network: NearNetwork, verify_signature: bool = True
) -> DecodedTransaction:
    """Decode a base64 ``SignedTransaction`` (the ledger's storage form)."""
    try:
        raw = base64.b64decode(signed_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise TransactionDecodeError("the stored signed transaction is not valid base64") from exc
    return decode_signed_transaction(raw, network=network, verify_signature=verify_signature)


def _skip_action(cur: _Cursor) -> None:
    """Advance the cursor past exactly one action, validating its shape."""
    tag = cur.u8()
    if tag == borsh.ACTION_TRANSFER:
        cur.u128()
    elif tag == borsh.ACTION_FUNCTION_CALL:
        cur.string()  # method_name
        cur.bytes_()  # args
        cur.u64()  # gas
        cur.u128()  # deposit
    elif tag == borsh.ACTION_CREATE_ACCOUNT:
        pass
    elif tag == borsh.ACTION_DELETE_ACCOUNT:
        cur.string()  # beneficiary_id
    elif tag == borsh.ACTION_DELETE_KEY:
        if cur.u8() != 0:
            raise TransactionDecodeError("unsupported delete-key public-key tag")
        cur.fixed(32)
    elif tag == borsh.ACTION_ADD_KEY:
        if cur.u8() != 0:
            raise TransactionDecodeError("unsupported add-key public-key tag")
        cur.fixed(32)  # public key
        cur.u64()  # access key nonce
        permission = cur.u8()
        if permission == borsh.PERMISSION_FULL_ACCESS:
            pass
        elif permission == borsh.PERMISSION_FUNCTION_CALL:
            if cur.u8() == 1:  # Option<allowance> = Some
                cur.u128()
            cur.string()  # receiver_id
            for _ in range(cur.u32()):  # method_names
                cur.string()
        else:
            raise TransactionDecodeError(f"unsupported access-key permission {permission}")
    else:
        raise TransactionDecodeError(f"unsupported action tag {tag}")


def _describe(
    *, network: NearNetwork, receiver_id: str, actions: tuple[bytes, ...]
) -> tuple[str, NearAsset, int, str, list[str]]:
    """Best-effort human description of the action(s), for evidence only.

    An action set the descriptor does not recognise is *not* an error - the
    decode itself is already validated - but it yields ``operation="UNKNOWN"``
    with a note, so the pipeline never claims to verify an amount it did not
    understand.
    """
    notes: list[str] = []
    native = resolve_asset(network, "native")

    if len(actions) != 1:
        notes.append(f"{len(actions)} actions; only single-action transfers are described")
        return "UNKNOWN", native, 0, receiver_id, notes

    cur = _Cursor(actions[0])
    tag = cur.u8()
    if tag == borsh.ACTION_TRANSFER:
        deposit = cur.u128()
        return OP_TRANSFER, native, deposit, receiver_id, notes
    if tag == borsh.ACTION_FUNCTION_CALL:
        method = cur.string()
        args_raw = cur.bytes_()
        if method != "ft_transfer":
            notes.append(f"function call method {method!r} is not described")
            return "UNKNOWN", native, 0, receiver_id, notes
        import json

        try:
            args = json.loads(args_raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            notes.append(f"ft_transfer args could not be read: {exc}")
            return "UNKNOWN", native, 0, receiver_id, notes
        recipient = args.get("receiver_id")
        amount = args.get("amount")
        try:
            asset = resolve_asset(network, receiver_id)
        except AssetError:
            notes.append(f"the contract {receiver_id!r} is not a registered asset")
            return "UNKNOWN", native, 0, str(recipient or ""), notes
        if not isinstance(recipient, str) or amount is None:
            notes.append("ft_transfer args are missing receiver_id or amount")
            return "UNKNOWN", asset, 0, str(recipient or ""), notes
        try:
            amount_base = int(amount)
        except (TypeError, ValueError):
            notes.append("the ft_transfer amount is not an integer")
            return "UNKNOWN", asset, 0, recipient, notes
        return OP_FT_TRANSFER, asset, amount_base, recipient, notes

    notes.append(f"action tag {tag} is not a described transfer")
    return "UNKNOWN", native, 0, receiver_id, notes


def describe(decoded: DecodedTransaction) -> dict[str, Any]:
    """A serializable summary, for evidence and the UI."""
    return {
        "network": decoded.network.value,
        "signer_id": decoded.signer_id,
        "public_key": decoded.public_key,
        "nonce": decoded.nonce,
        "receiver_id": decoded.receiver_id,
        "operation": decoded.operation,
        "asset": decoded.asset.identifier,
        "amount_base": str(decoded.amount_base),
        "destination": decoded.destination,
        "tx_hash": decoded.tx_hash,
        "action_count": len(decoded.actions),
        "notes": list(decoded.notes),
    }
