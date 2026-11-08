"""The independent reviewer CLI.

These run the real commands over the real captured evidence, in a subprocess, so
the exit codes and the human-readable output are exercised exactly as a reviewer
would see them. A pass must mean the evidence verified; a tampered record must
exit non-zero.
"""

from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tracesettle/near/fixtures/onchain_tee_attestation.json"
RUN_FIXTURE = ROOT / "tracesettle/near/fixtures/onchain_tee_run.json"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "tracesettle", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_guest_verify_passes_on_the_committed_guest():
    proc = _run("guest", "verify")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: PASS" in proc.stdout
    assert "eb705a61554fc982" in proc.stdout


def test_attestation_verify_passes_on_the_real_capture():
    proc = _run("attestation", "verify", "--record", str(FIXTURE))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "INDEPENDENTLY_VERIFIED" in proc.stdout
    assert "RESULT: PASS" in proc.stdout


def test_attestation_verify_rejects_a_tampered_capture(tmp_path):
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw = bytearray(base64.b64decode(record["attestation"]["tdx_quote"]))
    raw[48 + 520] ^= 0x01
    record["attestation"]["tdx_quote"] = base64.b64encode(bytes(raw)).decode()
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    proc = _run("attestation", "verify", "--record", str(path))
    assert proc.returncode != 0
    assert "RESULT: PASS" not in proc.stdout


def test_signature_verify_recomputes_the_onchain_hash(tmp_path):
    record = json.loads(RUN_FIXTURE.read_text(encoding="utf-8"))["sign_transaction"]["output"]
    path = tmp_path / "signing.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    proc = _run("signature", "verify", str(path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "signature_verified_over_the_digest: True" in proc.stdout
    assert "recomputed_tx_hash: F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj" in proc.stdout


def test_signature_verify_rejects_a_flipped_signature(tmp_path):
    record = json.loads(RUN_FIXTURE.read_text(encoding="utf-8"))["sign_transaction"]["output"]
    raw = bytearray(base64.b64decode(record["signature"]))
    raw[0] ^= 0x01
    record["signature"] = base64.b64encode(bytes(raw)).decode()
    path = tmp_path / "bad_sig.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    proc = _run("signature", "verify", str(path))
    assert proc.returncode != 0


def test_chain_verify_passes_on_a_consistent_record(tmp_path):
    from tracesettle.near.tee_signing.evidence_chain import build_evidence_chain

    digest = "sha256:" + "a" * 64
    chain = build_evidence_chain(
        transaction_digest=digest,
        network="testnet",
        tx_hash="HASH1",
        authorization={
            "network": "testnet",
            "transaction_digest": digest,
            "receiver_account": "r.testnet",
            "amount_base": "1000",
        },
        transaction={"receiver_id": "r.testnet", "amount_base": "1000", "network": "testnet"},
        signing={"tx_hash": "HASH1"},
        settlement={"tx_hash": "HASH1", "receiver": "r.testnet", "amount_base": "1000"},
    )
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(chain.to_dict()), encoding="utf-8")
    proc = _run("chain", "verify", str(path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: PASS" in proc.stdout


def test_chain_verify_fails_on_a_broken_binding(tmp_path):
    from tracesettle.near.tee_signing.evidence_chain import build_evidence_chain

    digest = "sha256:" + "a" * 64
    chain = build_evidence_chain(
        transaction_digest=digest,
        network="testnet",
        tx_hash="HASH1",
        authorization={
            "network": "testnet",
            "transaction_digest": digest,
            "receiver_account": "r.testnet",
            "amount_base": "1000",
        },
        signing={"receiver_account": "attacker.testnet", "tx_hash": "HASH1"},
    )
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(chain.to_dict()), encoding="utf-8")
    proc = _run("chain", "verify", str(path))
    assert proc.returncode != 0
    assert "receiver_agrees" in proc.stdout
