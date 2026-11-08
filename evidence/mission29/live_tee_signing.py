"""Mission 29 — one fresh, free, live TEE signing with full provenance evidence.

This drives a genuine Intel TDX enclave (OutLayer's *on-chain* route, paid in
free testnet NEAR) to sign a real NEAR testnet transaction, then captures and
verifies the complete chain from the Intel quote to the signature, persists the
signed bytes, and re-verifies them after closing and reopening the durable store.

Zero cost: the caller account comes from the free NEAR testnet faucet and the
enclave's own fund comes from the same faucet-created account. Testnet only.

Run:

    python3 evidence/mission29/live_tee_signing.py \
        --wasm-url https://.../tracesettle-signing-module-wasm.wasm

It prints a redacted JSON summary (no key material) and, when ``--out`` is given,
writes the evidence there. It never logs a private key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tracesettle.base58 import b58decode  # noqa: E402
from tracesettle.near import borsh, ed25519  # noqa: E402
from tracesettle.near.execution import NearExecutionBoundary  # noqa: E402
from tracesettle.near.ledger import SubmissionLedger, SubmissionRecord  # noqa: E402
from tracesettle.near.networks import network_config, parse_network  # noqa: E402
from tracesettle.near.pipeline import NearExecutionPipeline  # noqa: E402
from tracesettle.near.rpc import NearRpc  # noqa: E402
from tracesettle.near.tee_signing import (  # noqa: E402
    OnChainCaller,
    OnChainTeeConfig,
    OutLayerOnChainSigningProvider,
    build_signing_request,
)
from tracesettle.near.tee_signing.boundary import _b58  # noqa: E402
from tracesettle.near.tee_signing.outlayer_attestation import (  # noqa: E402
    fetch_attestation,
    measurements_from_quote,
    worker_is_approved,
)
from tracesettle.near.tee_signing.signing_provenance import verify_attested_signing  # noqa: E402
from tracesettle.near.txbuild import build_transfer  # noqa: E402

_FAUCET = "https://helper.testnet.near.org/account"
TRANSFER_YOCTO = 100_000_000_000_000_000_000_000  # 0.1 NEAR
_BUILD_IDENTITY = ROOT / "tracesettle/near/tee_signing/guest/signing-module/build_identity.json"


def _post_json(url: str, body: dict) -> tuple[int, str]:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _new_funded_account(seed: bytes) -> str:
    public_key = "ed25519:" + _b58(ed25519.public_key(seed))
    account = "ts-m29-" + secrets.token_hex(3) + ".testnet"
    status, body = _post_json(_FAUCET, {"newAccountId": account, "newAccountPublicKey": public_key})
    if status != 200:
        raise SystemExit(f"the free testnet faucet refused: {status} {body[:200]}")
    return account


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wasm-url", required=True)
    parser.add_argument("--wasm-sha256", default="")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    approved_sha = json.loads(_BUILD_IDENTITY.read_text(encoding="utf-8"))["artifacts"]["wasm"]["sha256"]
    with urllib.request.urlopen(args.wasm_url, timeout=60) as response:
        served = response.read()
    served_sha = hashlib.sha256(served).hexdigest()
    wasm_sha = args.wasm_sha256 or served_sha
    if wasm_sha != served_sha:
        raise SystemExit(f"served wasm sha {served_sha} != requested {wasm_sha}")
    if served_sha != approved_sha:
        raise SystemExit(f"served wasm sha {served_sha} != approved build {approved_sha}")

    rpc = NearRpc(network_config("testnet"))
    seed = hashlib.sha256(("ts-m29-" + secrets.token_hex(8)).encode()).digest()
    public_key = "ed25519:" + _b58(ed25519.public_key(seed))
    payer = _new_funded_account(seed)

    def sign_caller(digest: bytes) -> bytes:
        return ed25519.sign(digest, seed)

    provider = OutLayerOnChainSigningProvider(
        caller=OnChainCaller(account_id=payer, public_key=public_key, sign=sign_caller),
        config=OnChainTeeConfig(network="testnet", wasm_url=args.wasm_url, wasm_sha256=wasm_sha),
        rpc=rpc,
    )
    assert provider.capability().available

    # 1. The enclave's own key (derived inside the TEE).
    tee_key = provider.public_key()
    tee_account = b58decode(tee_key.split(":")[1]).hex()

    # 2. Fund the TEE account so it can pay for its own signed transaction.
    block = rpc.block_hash()
    key = rpc.view_access_key(payer, public_key)
    nonce = int(key.data["nonce"]) + 1
    fund_tx = borsh.transaction(
        payer, bytes(ed25519.public_key(seed)), nonce, tee_account,
        b58decode(block.data["hash"]), (borsh.action_transfer(5 * 10**24),),
    )
    fund_signed = fund_tx + borsh.signature_ed25519(sign_caller(borsh.transaction_hash(fund_tx)))
    sent = rpc.send_tx(base64.b64encode(fund_signed).decode("ascii"))
    if not sent.ok:
        raise SystemExit(f"funding the TEE account failed: {sent.status} {sent.detail}")

    recipient = _new_funded_account(hashlib.sha256(b"ts-m29-recipient").digest())
    before = int(rpc.view_account(recipient).data["amount"])

    # 3. The real transaction, signed by the enclave's key.
    block = rpc.block_hash()
    key = rpc.view_access_key(tee_account, tee_key)
    tx = build_transfer(
        network=parse_network("testnet"),
        signer_id=tee_account,
        public_key=tee_key,
        nonce=int(key.data["nonce"]) + 1,
        receiver_id=recipient,
        block_hash=block.data["hash"],
        amount_human=Decimal("0.1"),
        service_id="m29-live",
    )
    request = build_signing_request(
        transaction=tx,
        authorization={
            "id": "m29-live",
            "digest": "sha256:" + "00" * 32,
            "expiry": "2999-01-01T00:00:00+00:00",
            "policy_version": "m29-live",
        },
        provider=provider.name,
        approved_build="sha256:" + wasm_sha,
    )

    captured: dict[str, str] = {}
    original_submit = provider._submit

    def _submit_capture(input_data: str):
        data = original_submit(input_data)
        h = (data.get("transaction") or {}).get("hash")
        if isinstance(h, str):
            captured["execution_tx"] = h
        return data

    provider._submit = _submit_capture  # type: ignore[assignment]
    result = provider.sign(request)
    provider._submit = original_submit  # type: ignore[assignment]
    execution_tx = captured.get("execution_tx", "")

    # 4. The returned signature verifies over the exact authorized digest.
    signature_ok = ed25519.verify(
        result.signature_raw64,
        bytes.fromhex(result.transaction_digest.split(":")[1]),
        b58decode(result.public_key.split(":")[1]),
    )

    # 5. Broadcast the enclave's own signed bytes and independently re-read.
    sent = rpc.send_tx(base64.b64encode(result.signed_bytes).decode("ascii"))
    if not sent.ok:
        raise SystemExit(f"the TEE-signed transaction was refused: {sent.status} {sent.detail}")
    final = rpc.tx_status(tx.tx_hash, tee_account)
    after = int(rpc.view_account(recipient).data["amount"])

    # 6. Fetch the attestation for this exact execution and verify the chain.
    att = fetch_attestation(execution_tx, network="testnet") if execution_tx else None
    tx_result = rpc.tx_status(execution_tx, payer).data if execution_tx else None
    approval = None
    if att:
        try:
            measurements = measurements_from_quote(base64.b64decode(att["tdx_quote"]))
            approval = worker_is_approved(measurements, network="testnet", rpc=rpc)
        except Exception as exc:  # noqa: BLE001
            approval = (None, f"measurement read failed: {type(exc).__name__}")

    run_record = {
        "wasm_sha256": wasm_sha,
        "sign_transaction": {"output": {
            "status": "ok",
            "public_key": result.public_key,
            "signature": base64.b64encode(result.signature_raw64).decode("ascii"),
            "signed_transaction": base64.b64encode(result.signed_bytes).decode("ascii"),
            "transaction_digest": result.transaction_digest,
            "tx_hash": tx.tx_hash,
        }},
    }
    provenance = None
    if att is not None and tx_result is not None:
        provenance = verify_attested_signing(
            run_record, att, network="testnet", tx_result=tx_result,
            expected_wasm_sha256=wasm_sha,
        ).to_dict()

    # 7. Persist, close, reopen, re-verify after "restart".
    tmp = ROOT / "evidence/mission29/.tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    ledger_path = str(tmp / "live_ledger.db")
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    ledger = SubmissionLedger(ledger_path)
    ledger.put(SubmissionRecord(
        tx_hash=tx.tx_hash, state="BROADCAST", network="testnet",
        signer_id=tee_account, receiver_id=recipient, amount_base=str(TRANSFER_YOCTO),
        destination=recipient, signed_b64=base64.b64encode(result.signed_bytes).decode("ascii"),
        signature_algorithm="ed25519",
    ))
    ledger.close()
    reopened = SubmissionLedger(ledger_path)
    boundary = NearExecutionBoundary.__new__(NearExecutionBoundary)
    boundary.config = network_config("testnet")
    pipeline = NearExecutionPipeline(boundary, ledger=reopened)
    restart_verdict = pipeline.verify_recorded_signature(tx.tx_hash)
    reopened.close()

    evidence = {
        "network": "testnet",
        "mainnet": False,
        "fresh_signing_performed": True,
        "cost_usd": 0,
        "tee_public_key": result.public_key,
        "tee_account": tee_account,
        "approved_wasm_sha256": wasm_sha,
        "served_wasm_sha256": served_sha,
        "execution_tx": execution_tx,
        "transaction_hash": tx.tx_hash,
        "transaction_digest": result.transaction_digest,
        "recipient": recipient,
        "amount_yocto": TRANSFER_YOCTO,
        "balance_delta": after - before,
        "signature_verifies_over_authorized_digest": signature_ok,
        "submission_ok": sent.ok,
        "settlement_ok": final.ok,
        "attestation_fetched": att is not None,
        "worker_approved": approval[0] if approval else None,
        "worker_approval_detail": approval[1] if approval else "no attestation",
        "provenance": provenance,
        "restart_reverification": restart_verdict,
    }
    summary = json.dumps(evidence, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(summary + "\n", encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
