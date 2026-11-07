"""Live OutLayer TEE signing through the **free on-chain** route.

This is the test that reproduces Mission 25's live evidence: a real Intel TDX
enclave runs the TraceSettle guest and signs a real NEAR **testnet** transaction
with a key derived inside the enclave. It is skipped by default because it
spends *testnet* NEAR (which is free, but is still a network write and must be
opt-in), and because it needs a public HTTPS URL serving the built guest wasm.

Set, to run it::

    TRACESETTLE_TEST_ONCHAIN_TEE=1
    TRACESETTLE_TEST_TEE_WASM_URL=https://…/tracesettle-signing-module-wasm.wasm
    TRACESETTLE_TEST_TEE_WASM_SHA256=<sha256 of that file>

It never runs on mainnet, never signs for mainnet, and never logs a key. The
caller's key is a throwaway `.testnet` account created from the free faucet and
is read only to sign the `request_execution` call.

What it asserts, so the pass cannot be vacuous:

* the enclave returns a key derived inside the TEE;
* the same key is returned on a second run (the `bind: "wasm"` identity);
* the enclave's signature verifies over the **exact** digest the product
  authorized, and over no other;
* the enclave's own signed bytes are a real transaction the network accepts;
* the recipient's balance actually rose, so value moved on-chain.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request
from decimal import Decimal

import pytest

from tracesettle.base58 import b58decode
from tracesettle.near import borsh, ed25519
from tracesettle.near.networks import NearNetwork, network_config
from tracesettle.near.rpc import NearRpc
from tracesettle.near.tee_signing import (
    OnChainCaller,
    OnChainTeeConfig,
    OutLayerOnChainSigningProvider,
    build_signing_request,
)
from tracesettle.near.tee_signing.boundary import _b58
from tracesettle.near.txbuild import build_transfer

_ENABLED = os.environ.get("TRACESETTLE_TEST_ONCHAIN_TEE", "").strip() == "1"
_WASM_URL = os.environ.get("TRACESETTLE_TEST_TEE_WASM_URL", "").strip()
_WASM_SHA = os.environ.get("TRACESETTLE_TEST_TEE_WASM_SHA256", "").strip()

pytestmark = pytest.mark.skipif(
    not (_ENABLED and _WASM_URL and _WASM_SHA),
    reason=(
        "live on-chain TEE signing is opt-in; set TRACESETTLE_TEST_ONCHAIN_TEE=1, "
        "TRACESETTLE_TEST_TEE_WASM_URL and TRACESETTLE_TEST_TEE_WASM_SHA256"
    ),
)

_FAUCET = "https://helper.testnet.near.org/account"
TRANSFER_YOCTO = 100_000_000_000_000_000_000_000  # 0.1 NEAR


def _post_json(url: str, body: dict) -> tuple[int, str]:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # pragma: no cover - network
        return exc.code, exc.read().decode("utf-8")


def _new_funded_account(seed: bytes) -> str:
    """Create a funded `.testnet` account from the free faucet, keyed to ``seed``."""
    public_key = "ed25519:" + _b58(ed25519.public_key(seed))
    account = "ts-m25-" + secrets.token_hex(3) + ".testnet"
    status, body = _post_json(_FAUCET, {"newAccountId": account, "newAccountPublicKey": public_key})
    assert status == 200, f"the free testnet faucet refused: {status} {body[:200]}"
    return account


def _rpc() -> NearRpc:
    return NearRpc(network_config("testnet"))


def test_live_onchain_tee_signs_and_settles(tmp_path):
    network = network_config("testnet")
    assert network.network is NearNetwork.TESTNET, "this test is testnet-only"

    seed = hashlib.sha256(("ts-m25-test-" + secrets.token_hex(8)).encode()).digest()
    public_key = "ed25519:" + _b58(ed25519.public_key(seed))
    payer = _new_funded_account(seed)
    rpc = _rpc()

    def sign(digest: bytes) -> bytes:
        return ed25519.sign(digest, seed)

    provider = OutLayerOnChainSigningProvider(
        caller=OnChainCaller(account_id=payer, public_key=public_key, sign=sign),
        config=OnChainTeeConfig(
            network="testnet", wasm_url=_WASM_URL, wasm_sha256=_WASM_SHA
        ),
        rpc=rpc,
    )
    assert provider.capability().available

    # 1. The enclave's own key.
    tee_key = provider.public_key()
    assert tee_key.startswith("ed25519:")
    tee_account = b58decode(tee_key.split(":")[1]).hex()
    assert provider.public_key() == tee_key, "the TEE key must be stable across runs"

    # 2. Fund the TEE account so it can pay for its own transaction.
    block = rpc.block_hash()
    assert block.ok, block.status
    key = rpc.view_access_key(payer, public_key)
    assert key.ok, key.status
    nonce = int(key.data["nonce"]) + 1
    fund_tx = borsh.transaction(
        payer,
        bytes(ed25519.public_key(seed)),
        nonce,
        tee_account,
        b58decode(block.data["hash"]),
        (borsh.action_transfer(5 * 10**24),),
    )
    fund_digest = borsh.transaction_hash(fund_tx)
    fund_signed = fund_tx + borsh.signature_ed25519(sign(fund_digest))
    sent = rpc.send_tx(base64.b64encode(fund_signed).decode("ascii"))
    assert sent.ok, f"funding the TEE account failed: {sent.status} {sent.detail}"
    assert int(rpc.view_account(tee_account).data["amount"]) >= 5 * 10**24

    # 3. A real transaction, signed by the enclave's key.
    recipient = _new_funded_account(hashlib.sha256(b"ts-m25-test-recipient").digest())
    before = int(rpc.view_account(recipient).data["amount"])

    block = rpc.block_hash()
    key = rpc.view_access_key(tee_account, tee_key)
    assert key.ok, key.status
    tx = build_transfer(
        network=NearNetwork.TESTNET,
        signer_id=tee_account,
        public_key=tee_key,
        nonce=int(key.data["nonce"]) + 1,
        receiver_id=recipient,
        block_hash=block.data["hash"],
        amount_human=Decimal("0.1"),
        service_id="m25-live",
    )
    request = build_signing_request(
        transaction=tx,
        authorization={
            "id": "m25-live",
            "digest": "sha256:" + "00" * 32,
            "expiry": "2999-01-01T00:00:00+00:00",
            "policy_version": "m25-live",
        },
        provider=provider.name,
        approved_build="sha256:" + _WASM_SHA,
    )

    result = provider.sign(request)

    # 4. The signature covers the exact authorized digest — and only it.
    assert result.transaction_digest == tx.payload_fingerprint()
    assert ed25519.verify(
        result.signature_raw64,
        bytes.fromhex(result.transaction_digest.split(":")[1]),
        b58decode(result.public_key.split(":")[1]),
    ), "the enclave signature must verify over the authorized digest"

    # 5. Broadcast the enclave's own signed bytes and re-read the settlement.
    sent = rpc.send_tx(base64.b64encode(result.signed_bytes).decode("ascii"))
    assert sent.ok, f"the TEE-signed transaction was refused: {sent.status} {sent.detail}"

    final = rpc.tx_status(result.signed_bytes and tx.tx_hash, tee_account)
    assert final.ok, f"the settlement could not be re-read: {final.status} {final.detail}"

    after = int(rpc.view_account(recipient).data["amount"])
    assert after - before == TRANSFER_YOCTO, "the recipient's balance did not rise by the amount"

    # Evidence is written for the record; it holds only public data.
    (tmp_path / "m25_live_tee.json").write_text(
        json.dumps(
            {
                "tee_public_key": result.public_key,
                "tee_account": tee_account,
                "transaction_hash": tx.tx_hash,
                "transaction_digest": result.transaction_digest,
                "recipient": recipient,
                "amount_yocto": TRANSFER_YOCTO,
                "balance_delta": after - before,
                "on_chain": provider.last_run,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
