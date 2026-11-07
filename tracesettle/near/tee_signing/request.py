"""The canonical signing request the enclave is asked to sign.

A signing request is the *only* thing the TEE provider is ever allowed to sign.
It is built from an **authorized** transaction and nothing else, and it is
canonicalised so its digest is stable and its commitment is checkable.

The whole security argument rests on one rule, taken from OutLayer's own signing
rules: *never sign caller-supplied bytes verbatim*. So the request does **not**
carry "please sign these bytes". It carries the structured fields of the
authorized transaction, and the guest module recomputes the NEAR signing digest
from those fields itself. What crosses the boundary is the *description* of the
transaction plus the authorization that permits it — not a raw digest handed in
by the caller.

Fields (all explicit identifiers; none inferred from amount or timestamp):

* ``network`` — the NEAR network the transaction targets;
* ``signer_account`` / ``public_key`` — whose key signs;
* ``receiver_account`` — the destination account;
* ``nonce`` / ``block_hash`` — the transaction's one-time inputs;
* ``actions`` — the ordered action list, each a canonical dict;
* ``transfer_amount_yocto`` — the transferred amount, exact, as a decimal string;
* ``gas`` — the attached gas, exact;
* ``authorization`` — the guard decision id, its digest, its expiry, and the
  policy version that produced it;
* ``transaction_digest`` — the digest of the exact unsigned transaction bytes
  (``sha256`` of the Borsh-encoded transaction), which the guest must reproduce;
* ``provider`` — the provider identity the request is addressed to;
* ``approved_build`` — the approved WASM/build identity (the operator pins it).

``digest_for`` returns ``sha256`` of the canonical encoding. That value is what
the attestation's input/task hash must commit to, and what the authorization
binds to.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

#: Domain separator, so a signing-request digest can never be confused with any
#: other digest the product computes.
SIGNING_DOMAIN = b"TRACESETTLE-TEE-SIGNING-REQUEST-V1\x00"


@dataclass(frozen=True)
class TeeSigningRequest:
    """The structured, authorized description of the transaction to be signed."""

    network: str
    signer_account: str
    public_key: str
    receiver_account: str
    nonce: int
    block_hash: str
    actions: tuple[Mapping[str, Any], ...]
    transfer_amount_yocto: str
    gas: int
    transaction_digest: str
    authorization_id: str
    authorization_digest: str
    authorization_expiry: str
    policy_version: str
    provider: str
    approved_build: str
    asset: str = "NEAR:NATIVE"
    operation: str = "TRANSFER"

    def canonical(self) -> dict[str, Any]:
        """The exact structure that is hashed. Order and types are fixed."""
        return {
            "v": "1",
            "domain": "tracesettle.tee.signing-request",
            "network": self.network,
            "signer_account": self.signer_account,
            "public_key": self.public_key,
            "receiver_account": self.receiver_account,
            "nonce": int(self.nonce),
            # Base58 is case-sensitive: the block hash is carried verbatim, so the
            # enclave recomposes the exact transaction bytes. Lowercasing it (a
            # latent defect) would make the base58 undecodable and no correct
            # signature could ever be produced.
            "block_hash": self.block_hash,
            "actions": [dict(a) for a in self.actions],
            "transfer_amount_yocto": str(self.transfer_amount_yocto),
            "gas": int(self.gas),
            "asset": self.asset,
            "operation": self.operation,
            "transaction_digest": self.transaction_digest.lower(),
            "authorization": {
                "id": self.authorization_id,
                "digest": self.authorization_digest,
                "expiry": self.authorization_expiry,
                "policy_version": self.policy_version,
            },
            "provider": self.provider,
            "approved_build": self.approved_build,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def digest(self) -> str:
        """``sha256`` of the canonical encoding, hex, prefixed for clarity."""
        return "sha256:" + hashlib.sha256(SIGNING_DOMAIN + self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = self.canonical()
        d["request_digest"] = self.digest()
        return d


def digest_for(request: TeeSigningRequest) -> str:
    """Convenience wrapper so callers do not re-implement the domain prefix."""
    return request.digest()


def action_summaries(transaction: Any) -> tuple[dict[str, Any], ...]:
    """The ordered actions of a built transaction, as canonical dicts.

    Read from the transaction object itself (its operation, asset, amount and
    destination), never from a caller-supplied description, so the request cannot
    describe an action the transaction does not carry.
    """
    from ..txbuild import OP_FT_TRANSFER

    amount = str(transaction.amount_base)
    if getattr(transaction, "operation", "") == OP_FT_TRANSFER:
        contract = (transaction.extra or {}).get("contract") or transaction.receiver_id
        args = {"receiver_id": transaction.destination, "amount": amount}
        return (
            {
                "type": "FunctionCall",
                "method_name": "ft_transfer",
                "receiver_id": transaction.destination,
                "amount": amount,
                "contract": contract,
                "args": args,
                "gas": gas_of(transaction),
                "deposit": "1",
            },
        )
    return ({"type": "Transfer", "deposit": amount},)


def gas_of(transaction: Any) -> int:
    """The gas attached to the transaction's action, exact. Zero for a transfer."""
    extra = getattr(transaction, "extra", None) or {}
    try:
        return int(extra.get("gas", 0))
    except (TypeError, ValueError):
        return 0


def build_signing_request(
    *,
    transaction: Any,
    authorization: Mapping[str, Any],
    provider: str,
    approved_build: str,
) -> TeeSigningRequest:
    """Build a signing request from an **authorized** transaction.

    ``transaction`` is a :class:`tracesettle.near.txbuild.NearTransaction`; its
    ordered actions, gas and digest are read from the object itself so the
    request cannot describe something other than what will be signed.
    ``authorization`` must carry an explicit id/digest/expiry; an authorization
    that is not ALLOW is refused by the boundary before this is ever called.
    """
    asset = getattr(transaction, "guard_asset", "") or "NEAR:NATIVE"
    return TeeSigningRequest(
        network=getattr(transaction.network, "value", str(transaction.network)),
        signer_account=transaction.signer_id,
        public_key=transaction.public_key,
        receiver_account=transaction.receiver_id,
        nonce=int(transaction.nonce),
        block_hash=str(transaction.block_hash),
        actions=action_summaries(transaction),
        transfer_amount_yocto=str(transaction.amount_base),
        gas=gas_of(transaction),
        transaction_digest=transaction.payload_fingerprint(),
        authorization_id=str(authorization["id"]),
        authorization_digest=str(authorization["digest"]),
        authorization_expiry=str(authorization["expiry"]),
        policy_version=str(authorization.get("policy_version", "unknown")),
        provider=provider,
        approved_build=approved_build,
        asset=asset.upper(),
        operation=str(getattr(transaction, "operation", "TRANSFER")),
    )
