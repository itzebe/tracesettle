"""Live OutLayer TEE signing, run only when a payment key is supplied.

This is the one test that reaches the real ``outlayer:signing-keys`` route — the
only documented way to have a remote Intel TDX enclave sign a caller-computed
digest. It is skipped by default: the route is **paid**, so with no credential the
correct outcome is "skipped", never a fabricated pass.

When a credential *is* supplied, the test asserts the properties that matter and
cannot pass vacuously:

* the provider reports itself available;
* the enclave is asked to sign a **structured description** of the authorized
  transaction, never raw caller bytes;
* the returned signature verifies over the exact NEAR transaction digest under
  the key the provider reports.

It never signs for mainnet, never broadcasts, and never logs the payment key.
Set ``TRACESETTLE_TEST_OUTLAYER_PAYMENT_KEY`` (plus
``TRACESETTLE_TEST_OUTLAYER_OWNER``, ``TRACESETTLE_TEST_OUTLAYER_PROJECT`` and
``TRACESETTLE_TEST_OUTLAYER_APPROVED_BUILD``) to run it.
"""

from __future__ import annotations

import base64
import os
from decimal import Decimal

import pytest

from tracesettle.near import ed25519
from tracesettle.near.networks import NearNetwork
from tracesettle.near.tee_signing import (
    OutLayerSigningProvider,
    TeeSigningBoundary,
    TeeSigningRefusal,
    build_signing_request,
)
from tracesettle.near.txbuild import build_transfer

_PAYMENT_KEY = os.environ.get("TRACESETTLE_TEST_OUTLAYER_PAYMENT_KEY", "").strip()
_OWNER = os.environ.get("TRACESETTLE_TEST_OUTLAYER_OWNER", "").strip()
_PROJECT = os.environ.get("TRACESETTLE_TEST_OUTLAYER_PROJECT", "").strip()
_BUILD = os.environ.get("TRACESETTLE_TEST_OUTLAYER_APPROVED_BUILD", "").strip()

pytestmark = pytest.mark.skipif(
    not (_PAYMENT_KEY and _OWNER and _PROJECT and _BUILD),
    reason=(
        "no OutLayer signing credential supplied; set "
        "TRACESETTLE_TEST_OUTLAYER_PAYMENT_KEY, _OWNER, _PROJECT and _APPROVED_BUILD"
    ),
)

# A well-known testnet public key. The enclave signs *a description*; it holds the
# private key, so the account the signature would belong to is the enclave's, not
# this value. The value is only used to build a well-formed transaction.
_AGENT_PUBLIC_KEY = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
_BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"


class _Allow:
    outcome = "ALLOW"


def test_live_outlayer_tee_signing_produces_a_verifiable_signature():
    from tracesettle.httpclient import HttpClient

    tx = build_transfer(
        network=NearNetwork.TESTNET,
        signer_id="agent.testnet",
        public_key=_AGENT_PUBLIC_KEY,
        nonce=1,
        receiver_id="merchant.testnet",
        block_hash=_BLOCK_HASH,
        amount_human=Decimal("0.01"),
        service_id="svc",
    )
    provider = OutLayerSigningProvider(
        client=HttpClient(),
        network="testnet",
        owner=_OWNER,
        project=_PROJECT,
        payment_key=_PAYMENT_KEY,
        approved_build=_BUILD,
    )
    assert provider.capability().available is True, "the credential was not accepted"

    boundary = TeeSigningBoundary(provider=provider, approved_build=_BUILD)
    record = {
        "authorization_id": "live",
        "execution_digest": "sha256:" + "ab" * 32,
        "expires_at": "2999-01-01T00:00:00+00:00",
        "policy_version": "v1",
        "transaction_digest": tx.payload_fingerprint(),
    }
    evidence = boundary.sign(tx, decision=_Allow(), authorization_record=record)

    # The signature must verify over the exact digest under the reported key.
    public_raw = _b58_decode_public(evidence.public_key)
    signature = base64.b64decode(evidence.signature_b64)
    assert ed25519.verify(signature, tx.tx_hash_bytes, public_raw), (
        "the enclave signature did not verify over the exact NEAR digest"
    )
    # With no attestation supplied, no TEE claim may be made.
    assert evidence.state == "SIGNATURE_VERIFIED"
    assert not evidence.tee_signing_verified

    # The enclave is asked to sign a structured request, never raw bytes.
    request = build_signing_request(
        transaction=tx,
        authorization=record,
        provider=provider.name,
        approved_build=_BUILD,
    )
    assert "raw_message" not in request.canonical()


def test_live_outlayer_refuses_a_build_that_is_not_the_approved_one():
    from tracesettle.httpclient import HttpClient

    tx = build_transfer(
        network=NearNetwork.TESTNET,
        signer_id="agent.testnet",
        public_key=_AGENT_PUBLIC_KEY,
        nonce=1,
        receiver_id="merchant.testnet",
        block_hash=_BLOCK_HASH,
        amount_human=Decimal("0.01"),
        service_id="svc",
    )
    provider = OutLayerSigningProvider(
        client=HttpClient(),
        network="testnet",
        owner=_OWNER,
        project=_PROJECT,
        payment_key=_PAYMENT_KEY,
        approved_build=_BUILD,
    )
    # A boundary pinning a *different* build must refuse the attestation.
    boundary = TeeSigningBoundary(provider=provider, approved_build="sha256:" + "ff" * 32)
    record = {
        "authorization_id": "live",
        "execution_digest": "sha256:" + "ab" * 32,
        "expires_at": "2999-01-01T00:00:00+00:00",
        "policy_version": "v1",
        "transaction_digest": tx.payload_fingerprint(),
    }
    with pytest.raises(TeeSigningRefusal):
        boundary.sign(
            tx,
            decision=_Allow(),
            authorization_record=record,
            attestation={"wasm_hash": "sha256:" + "ff" * 32},
        )


def _b58_decode_public(public_key: str) -> bytes:
    from tracesettle.base58 import b58decode

    assert public_key.startswith("ed25519:")
    return b58decode(public_key.split(":", 1)[1])
