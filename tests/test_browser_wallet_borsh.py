"""The browser-wallet demonstration's transaction layout stays correct.

The browser-wallet emulator (``demo/browser_wallet/wallet.mjs``) builds the NEAR
transaction a wallet signs. If its Borsh layout drifted from the repository's own
serializer, the demonstration would sign bytes the network (and the guard's
binding) would not agree with, and the on-chain result would silently stop
matching the authorized intent.

This test pins the two together. It runs the emulator's Borsh builder under Node
against a fixed vector produced here by ``tracesettle.near.borsh``. Node is a
demonstration dependency, not a runtime one, so the test skips when Node is
absent; it never skips when Node is present.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest

from tracesettle import base58
from tracesettle.near import borsh, ed25519
from tests.near_helpers import b58encode

DEMO = pathlib.Path(__file__).resolve().parents[1] / "demo" / "browser_wallet"
WALLET_JS = DEMO / "wallet.mjs"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node.js is not installed (a demo-only dependency)"
)

SEED = bytes(range(32))
BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"


def _vector() -> dict:
    public_key = "ed25519:" + b58encode(ed25519.public_key(SEED))
    deposit = 10**24
    tx = borsh.transaction(
        "alice.testnet",
        ed25519.public_key(SEED),
        42,
        "bob.testnet",
        base58.b58decode(BLOCK_HASH),
        [borsh.action_transfer(deposit)],
    )
    return {
        "signerId": "alice.testnet",
        "receiverId": "bob.testnet",
        "publicKey": public_key,
        "nonce": 42,
        "blockHashB58": BLOCK_HASH,
        "deposit": str(deposit),
        "unsignedHex": tx.hex(),
        "txHashHex": borsh.transaction_hash(tx).hex(),
    }


def _run_emulator_borsh(vector: dict) -> dict:
    script = (
        'import { buildTransferBytes } from "./wallet.mjs";\n'
        'import crypto from "node:crypto";\n'
        f"const v = {json.dumps(vector)};\n"
        "const tx = buildTransferBytes(v);\n"
        "console.log(JSON.stringify({\n"
        '  unsignedHex: tx.toString("hex"),\n'
        '  txHashHex: crypto.createHash("sha256").update(tx).digest("hex"),\n'
        "}));\n"
    )
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=str(DEMO),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_emulator_borsh_matches_the_repository_serializer():
    vector = _vector()
    out = _run_emulator_borsh(vector)
    assert out["unsignedHex"] == vector["unsignedHex"]
    assert out["txHashHex"] == vector["txHashHex"]


def test_a_changed_amount_changes_the_emulator_transaction():
    vector = _vector()
    tampered = dict(vector, deposit=str(2 * 10**24))
    base = _run_emulator_borsh(vector)
    other = _run_emulator_borsh(tampered)
    assert base["unsignedHex"] != other["unsignedHex"]
    assert base["txHashHex"] != other["txHashHex"]
