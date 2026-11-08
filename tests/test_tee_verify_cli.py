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


def _run_env(env: dict, *args: str) -> subprocess.CompletedProcess:
    """Run with a clean environment plus ``env`` so ambient vars cannot leak in."""
    import os

    base = {k: v for k, v in os.environ.items() if not k.startswith(("TRACESETTLE_", "NEAR_INTENTS_"))}
    base.update(env)
    return subprocess.run(
        [sys.executable, "-m", "tracesettle", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=base,
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


def test_signing_provenance_passes_on_the_real_tee_capture():
    proc = _run(
        "signing-provenance",
        "verify",
        "--run",
        str(RUN_FIXTURE),
        "--attestation",
        str(FIXTURE),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TEE_SIGNING_VERIFIED" in proc.stdout
    assert "RESULT: PASS" in proc.stdout


def test_provider_auth_fails_closed_without_configuration():
    proc = _run_env({}, "provider", "auth", "--json")
    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert payload["authenticated"] is False
    assert payload["base_url_configured"] is False
    assert "No Agent API base URL" in payload["detail"]


def test_provider_auth_fails_closed_without_a_key():
    proc = _run_env(
        {"TRACESETTLE_NEAR_AGENT_API_URL": "https://api.agentsonintents.com"},
        "provider", "auth", "--json",
    )
    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert payload["authenticated"] is False
    assert payload["base_url_configured"] is True
    assert payload["key_configured"] is False
    assert "No Agent API key" in payload["detail"]


def test_provider_auth_accepts_the_providers_documented_env_names():
    """The provider's own env names (NEAR_INTENTS_AGENT_*) must be honoured."""
    proc = _run_env(
        {"NEAR_INTENTS_AGENT_API_URL": "https://api.agentsonintents.com"},
        "provider", "auth", "--json",
    )
    payload = json.loads(proc.stdout)
    # No key supplied, but the base URL from the documented name was read.
    assert payload["base_url_configured"] is True
    assert payload["authenticated"] is False


def test_provider_auth_never_prints_the_key():
    # An unreachable local address, so this never makes an external call: the
    # point is only that the key is never echoed, whatever the transport does.
    proc = _run_env(
        {
            "NEAR_INTENTS_AGENT_API_URL": "http://127.0.0.1:1",
            "NEAR_INTENTS_AGENT_API_KEY": "super-secret-value-xyz",
        },
        "provider", "auth", "--json",
    )
    assert "super-secret-value-xyz" not in proc.stdout
    assert "super-secret-value-xyz" not in proc.stderr


def test_signing_provenance_refuses_a_swapped_transaction(tmp_path):
    run = json.loads(RUN_FIXTURE.read_text(encoding="utf-8"))
    signed = bytearray(base64.b64decode(run["sign_transaction"]["output"]["signed_transaction"]))
    signed[-1] ^= 0x01
    run["sign_transaction"]["output"]["signed_transaction"] = base64.b64encode(bytes(signed)).decode()
    path = tmp_path / "swapped.json"
    path.write_text(json.dumps(run), encoding="utf-8")
    proc = _run("signing-provenance", "verify", "--run", str(path), "--attestation", str(FIXTURE))
    assert proc.returncode != 0
    assert "RESULT: PASS" not in proc.stdout
    assert "TEE_SIGNING_VERIFIED" not in proc.stdout
