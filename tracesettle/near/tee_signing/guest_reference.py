"""A reference implementation of the guest module's digest logic, in Python.

The Rust guest (`guest/signing-module/src/lib.rs`) is what runs inside the
enclave, but it cannot be compiled in this repository's offline CI (that needs
the Rust + WASI-P2 toolchain and a network fetch). So the *logic that matters* —
recomputing the NEAR signing digest ``sha256(borsh(Transaction))`` from the
structured signing request and refusing anything that is not that structure — is
mirrored here and tested against the product's own serializer.

The test that gives this its weight asserts that
:func:`guest_signing_digest` returns exactly
``NearTransaction.payload_fingerprint()`` for the same transaction. If the guest
and the product disagreed about the bytes, the enclave would sign a digest the
network rejects — or, worse, one that is not the authorized transaction. That
test is the acceptance criterion for this file, exactly as the txbuild test
vector is for :mod:`tracesettle.near.borsh`.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .. import borsh
from ...base58 import b58decode
from .request import TeeSigningRequest

#: The only request domain this module will sign for.
EXPECTED_DOMAIN = "tracesettle.tee.signing-request"
EXPECTED_VERSION = "1"


class GuestRefusal(ValueError):
    """The guest refused to compose a digest. No signature would be produced."""


def _pub_raw(public_key: str) -> bytes:
    key = public_key.split(":")[-1]
    raw = b58decode(key)
    if len(raw) != 32:
        raise GuestRefusal("the public key is not 32 bytes")
    return raw


def _hash_raw(block_hash: str) -> bytes:
    raw = b58decode(block_hash)
    if len(raw) != 32:
        raise GuestRefusal("the block hash is not 32 bytes")
    return raw


def _action_bytes(action: Mapping[str, Any]) -> bytes:
    """Encode one action with the product's own Borsh encoders."""
    kind = str(action.get("type", ""))
    if kind == "Transfer":
        return borsh.action_transfer(int(action["deposit"]))
    if kind == "FunctionCall":
        args = action.get("args")
        import json

        # Match `txbuild.build_ft_transfer` exactly: compact JSON, the same
        # `receiver_id`/`amount`(/`memo`) object in insertion order. The digest
        # test is what proves the guest and the product agree on these bytes.
        encoded = json.dumps(args, separators=(",", ":")).encode("utf-8")
        return borsh.action_function_call(
            str(action["method_name"]),
            encoded,
            int(action.get("gas", 0)),
            int(action.get("deposit", "1")),
        )
    raise GuestRefusal(f"unsupported action type {kind!r}; refusing")


def guest_unsigned_bytes(request: TeeSigningRequest) -> bytes:
    """The exact Borsh ``Transaction`` bytes, recomposed in the guest."""
    return borsh.transaction(
        request.signer_account,
        _pub_raw(request.public_key),
        int(request.nonce),
        request.receiver_account,
        _hash_raw(request.block_hash),
        tuple(_action_bytes(a) for a in request.actions),
    )


def guest_signing_digest(request: TeeSigningRequest) -> bytes:
    """``sha256(borsh(Transaction))`` — the 32 bytes NEAR signs."""
    return hashlib.sha256(guest_unsigned_bytes(request)).digest()


def guest_accepts(request: TeeSigningRequest) -> None:
    """Refuse a request that is not the fixed structure this module signs.

    Mirrors the guest's own guard: a wrong domain/version, or any attempt to
    smuggle a raw message or digest, is refused before a digest is composed.
    """
    canonical = request.canonical()
    if canonical.get("domain") != EXPECTED_DOMAIN:
        raise GuestRefusal("unexpected request domain; refusing")
    if str(canonical.get("v")) != EXPECTED_VERSION:
        raise GuestRefusal("unsupported request version; refusing")
    for forbidden in ("raw_message", "raw_digest", "message"):
        if forbidden in canonical:
            raise GuestRefusal("this module never signs caller-supplied bytes; refusing")
