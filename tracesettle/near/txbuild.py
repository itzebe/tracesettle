"""Construction of real, signable NEAR transactions.

This is where a validated operation becomes the exact bytes a NEAR wallet will
sign. Everything here is deterministic and derived from validated inputs: the
account, the asset's verified decimals, the network's current block hash, and
the account's current access-key nonce.

The design rule that matters most: **the transaction is built first, and the
authorization is bound to the transaction that was built** - never to the
request that preceded it. ``NearTransaction.canonical_fields()`` returns the
exact parameter set the guard's HMAC covers, and the signing boundary re-derives
it from the final transaction and refuses to proceed if anything moved. A
destination, amount, asset, network, operation or account change between
authorization and signing therefore cannot be signed, because the re-derived
fields will not equal the authorized ones.

Nothing in this module holds a key or signs. It produces bytes and a hash; the
wallet supplies the signature.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from . import borsh
from .assets import NearAsset, to_base_units
from .networks import NearNetwork

#: Default gas attached to an NEP-141 ``ft_transfer`` (30 TGas is the standard
#: allowance for a simple FT transfer; the extra headroom covers the storage
#: check). Never invented per-call: a fixed, documented value.
DEFAULT_FT_TRANSFER_GAS = 30_000_000_000_000

#: The storage-deposit requirement of a NEP-141 transfer, in yoctoNEAR. ``1``
#: yoctoNEAR is the conventional "attach one yocto" that proves the caller is a
#: full-access/function-call key holder without transferring value.
ONE_YOCTO = 1

#: NEAR operation kinds this module can build.
OP_TRANSFER = "TRANSFER"
OP_FT_TRANSFER = "FT_TRANSFER"


class TransactionBuildError(ValueError):
    """A transaction could not be built from the supplied inputs."""


@dataclass(frozen=True)
class NearTransaction:
    """An unsigned NEAR transaction, plus everything needed to describe it."""

    network: NearNetwork
    signer_id: str
    public_key: str  # ed25519:<base58>
    nonce: int
    receiver_id: str
    block_hash: str  # base58
    actions: tuple[bytes, ...]
    #: Human-facing description, used in the UI and the report. Never used for a
    #: security decision.
    operation: str
    asset: NearAsset
    amount_base: int
    amount_human: Decimal
    destination: str
    #: The service identity the operation is bound to.
    service_id: str = ""
    #: The guard's operation vocabulary (e.g. ``WITHDRAWAL``), which differs from
    #: the on-chain action name (``TRANSFER``). Carried explicitly so the binding
    #: is rebuilt in exactly the guard's convention.
    guard_operation: str = "WITHDRAWAL"
    #: The guard's chain vocabulary, scoped to the network (``near-testnet``), so
    #: a cross-network authorization is a binding mismatch.
    guard_chain: str = ""
    #: The guard's canonical asset id (``NEAR:NATIVE``).
    guard_asset: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def unsigned_bytes(self) -> bytes:
        return borsh.transaction(
            self.signer_id,
            _pub_raw(self.public_key),
            self.nonce,
            self.receiver_id,
            _hash_raw(self.block_hash),
            self.actions,
        )

    @property
    def tx_hash_bytes(self) -> bytes:
        return borsh.transaction_hash(self.unsigned_bytes())

    @property
    def tx_hash(self) -> str:
        return _b58encode(self.tx_hash_bytes)

    def signed_bytes(self, signature_raw64: bytes) -> bytes:
        """Borsh ``SignedTransaction``: the transaction, then the signature.

        Verified by broadcast in the testnet demonstration: the network accepts
        exactly these bytes and reports back the same hash ``tx_hash`` predicts.
        """
        return self.unsigned_bytes() + borsh.signature_ed25519(signature_raw64)

    def signed_b64(self, signature_raw64: bytes) -> str:
        return base64.b64encode(self.signed_bytes(signature_raw64)).decode("ascii")

    def guard_amount(self) -> Decimal:
        """The transfer amount the authorization is bound to.

        Derived from ``amount_base`` - the exact integer that goes into the
        on-chain action - not from a separately-stored human amount. Deriving it
        here means the bound amount can never drift from the amount the
        transaction actually moves, so a tampered ``amount_base`` changes the
        binding and is refused.
        """
        from .assets import from_base_units

        return from_base_units(self.amount_base, self.asset)

    def guard_canonical_fields(self) -> dict[str, str]:
        """The parameter set the guard authorization is bound to.

        Built with :func:`tracesettle.guard.model.canonical_fields`, i.e. exactly
        the convention the guard used to mint the authorization. The signing
        boundary recomputes this from the *final* transaction and passes it to
        the authorization authority as the expected fingerprint, so any change to
        the destination, amount, asset, chain/network, operation or service is a
        ``WRONG_PARAMETERS`` refusal. The chain is network-scoped, so a
        cross-network replay is also a mismatch.

        ``transaction_digest`` is the digest of the exact unsigned bytes that
        will be signed. Binding it means the authorization covers the *bytes*,
        not merely a summary of them: a swapped action, a substituted token
        contract, or forged call arguments change the digest and are refused,
        even when the human-readable parameters are unchanged.
        """
        from ..guard.model import canonical_fields

        return canonical_fields(
            service_id=self.service_id,
            operation=self.guard_operation,
            chain=self.guard_chain or f"near-{self.network.value}",
            asset=self.guard_asset or self.asset.identifier.upper(),
            amount=self.guard_amount(),
            destination=self.destination,
            transaction_digest=self.payload_fingerprint(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "signer_id": self.signer_id,
            "public_key": self.public_key,
            "nonce": self.nonce,
            "receiver_id": self.receiver_id,
            "block_hash": self.block_hash,
            "operation": self.operation,
            "asset": self.asset.to_dict(),
            "amount_base_units": str(self.amount_base),
            "amount_human": str(self.amount_human),
            "destination": self.destination,
            "tx_hash": self.tx_hash,
            "payload_fingerprint": self.payload_fingerprint(),
        }

    def payload_fingerprint(self) -> str:
        """A stable digest of the exact unsigned bytes (the signing payload).

        Two transactions with the same fingerprint sign the same bytes; any
        change to a nonce, block hash, receiver, action or amount changes it.
        """
        import hashlib

        return "sha256:" + hashlib.sha256(self.unsigned_bytes()).hexdigest()


def _b58encode(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def _pub_raw(public_key: str) -> bytes:
    from ..base58 import b58decode

    key = public_key.strip()
    if key.startswith("ed25519:"):
        key = key[len("ed25519:") :]
    raw = b58decode(key)
    if raw is None or len(raw) != 32:
        raise TransactionBuildError("public key must be an ed25519 key of 32 bytes")
    return raw


def _hash_raw(block_hash: str) -> bytes:
    from ..base58 import b58decode

    raw = b58decode(block_hash.strip())
    if raw is None or len(raw) != 32:
        raise TransactionBuildError("block hash must be 32 bytes of base58")
    return raw


def next_nonce(access_key_nonce: int) -> int:
    """The nonce to use for the next transaction on an access key.

    NEAR requires a strictly increasing nonce; the access key's stored nonce is
    the last one used, so the next transaction uses ``stored + 1``. A nonce must
    be positive.
    """
    if not isinstance(access_key_nonce, int) or access_key_nonce < 0:
        raise TransactionBuildError("access key nonce must be a non-negative integer")
    return access_key_nonce + 1


def build_transfer(
    *,
    network: NearNetwork,
    signer_id: str,
    public_key: str,
    nonce: int,
    receiver_id: str,
    block_hash: str,
    amount_human: Decimal | str,
    service_id: str = "",
    guard_operation: str = "WITHDRAWAL",
) -> NearTransaction:
    """Build a native NEAR transfer. The amount is in whole NEAR."""
    asset = NearAsset(network=network, contract=None, symbol="NEAR", decimals=24, name="NEAR")
    base = to_base_units(amount_human, asset)
    action = borsh.action_transfer(base)
    return NearTransaction(
        network=network,
        signer_id=signer_id,
        public_key=public_key,
        nonce=nonce,
        receiver_id=receiver_id,
        block_hash=block_hash,
        actions=(action,),
        operation=OP_TRANSFER,
        asset=asset,
        amount_base=base,
        amount_human=Decimal(amount_human),
        destination=receiver_id,
        service_id=service_id,
        guard_operation=guard_operation,
        guard_chain=f"near-{network.value}",
        guard_asset=asset.identifier.upper(),
        extra={"service_id": service_id},
    )


def build_ft_transfer(
    *,
    network: NearNetwork,
    signer_id: str,
    public_key: str,
    nonce: int,
    block_hash: str,
    asset: NearAsset,
    receiver_id: str,
    amount_human: Decimal | str,
    service_id: str = "",
    guard_operation: str = "WITHDRAWAL",
    gas: int = DEFAULT_FT_TRANSFER_GAS,
    memo: str | None = None,
) -> NearTransaction:
    """Build a NEP-141 ``ft_transfer``.

    The receiver of the transaction is the **token contract**; the recipient of
    the funds is the ``receiver_id`` argument. That distinction is why the
    destination bound into the authorization is the recipient, and the contract
    is carried separately: a caller must not be able to change the recipient by
    changing the contract, or the reverse.
    """
    if asset.is_native:
        raise TransactionBuildError("use build_transfer for native NEAR, not ft_transfer")
    base = to_base_units(amount_human, asset)
    args: dict[str, Any] = {"receiver_id": receiver_id, "amount": str(base)}
    if memo is not None:
        args["memo"] = memo
    import json

    action = borsh.action_function_call(
        "ft_transfer", json.dumps(args).encode("utf-8"), gas, ONE_YOCTO
    )
    return NearTransaction(
        network=network,
        signer_id=signer_id,
        public_key=public_key,
        nonce=nonce,
        receiver_id=asset.contract or "",
        block_hash=block_hash,
        actions=(action,),
        operation=OP_FT_TRANSFER,
        asset=asset,
        amount_base=base,
        amount_human=Decimal(amount_human),
        destination=receiver_id,
        service_id=service_id,
        guard_operation=guard_operation,
        guard_chain=f"near-{network.value}",
        guard_asset=asset.identifier.upper(),
        extra={"service_id": service_id, "contract": asset.contract, "gas": gas},
    )
