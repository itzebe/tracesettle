"""Independent, cross-process post-restart signature verification (Mission 27).

This driver answers the acceptance question with a *real* process boundary, not a
close/reopen inside one interpreter:

  Phase 1 (process A) builds a real NEAR transaction through the real guard and
  pipeline against a durable SQLite ledger, signs it with a real ed25519 key,
  broadcasts (substituted RPC transport) and closes. The ledger file is the only
  thing that survives.

  Phase 2 (process B, a fresh ``python -c``) opens the same ledger file, reads the
  recorded signed bytes, recomputes the NEAR digest and re-verifies the ed25519
  signature - without any in-memory object, without re-signing, without a network
  call.

  Phase 3 tampers the recorded bytes on disk and requires a fail-closed refusal,
  so the check is not vacuous.

Run: ``python3 evidence/mission27/independent_restart_verification.py``
It prints the JSON evidence to stdout and writes ``independent_restart_verification.json``
next to itself. No network, no key material, testnet-only, no cost.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))

HERE = pathlib.Path(__file__).resolve().parent


def _phase_a(ledger_path: str) -> dict:
    from near_helpers import RECIPIENT, SIGNER, make_boundary, result_for
    from near_helpers import TEST_SEED, public_key_for_test
    from tracesettle.near.ed25519 import sign as ed_sign
    from tracesettle.near.ledger import SubmissionLedger, SubmissionState
    from tracesettle.near.pipeline import NearExecutionPipeline

    boundary, rpc = make_boundary()
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger(ledger_path))
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key=public_key_for_test(),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )

    class _Signer:
        public_key = prepared.transaction.public_key

        def sign(self, message: bytes) -> bytes:
            return ed_sign(message, TEST_SEED)

    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    result = pipeline.execute(prepared, _Signer())
    assert result.state == SubmissionState.SETTLED, result.state
    pipeline.ledger.close()
    return {"tx_hash": result.tx_hash, "signer": SIGNER, "receiver": RECIPIENT}


_PHASE_B = r"""
import json, sys
sys.path.insert(0, {repo!r})
sys.path.insert(0, {tests!r})
from near_helpers import make_boundary
from tracesettle.near.ledger import SubmissionLedger
from tracesettle.near.pipeline import NearExecutionPipeline
boundary, _rpc = make_boundary()
pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger({ledger!r}))
verdict = pipeline.verify_recorded_signature({tx!r})
pipeline.ledger.close()
print("VERDICT:" + json.dumps(verdict))
"""


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="m27-restart-")
    ledger_path = str(pathlib.Path(tmp) / "ledger.db")

    a = _phase_a(ledger_path)

    # Phase 2: a genuinely fresh interpreter reads only the ledger file.
    proc = subprocess.run(
        [sys.executable, "-c", _PHASE_B.format(repo=str(REPO), tests=str(REPO / "tests"), ledger=ledger_path, tx=a["tx_hash"])],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    line = [ln for ln in proc.stdout.splitlines() if ln.startswith("VERDICT:")][-1]
    verdict = json.loads(line[len("VERDICT:"):])

    # Phase 3: tamper the recorded signed bytes on disk; the fresh process must refuse.
    import sqlite3

    conn = sqlite3.connect(ledger_path)
    row = conn.execute("SELECT record FROM submissions WHERE tx_hash = ?", (a["tx_hash"],)).fetchone()
    rec = json.loads(row[0])
    import base64

    raw = bytearray(base64.b64decode(rec["signed_b64"]))
    raw[60] ^= 0x01
    rec["signed_b64"] = base64.b64encode(bytes(raw)).decode()
    conn.execute("UPDATE submissions SET record = ? WHERE tx_hash = ?", (json.dumps(rec), a["tx_hash"]))
    conn.commit()
    conn.close()

    proc2 = subprocess.run(
        [sys.executable, "-c", _PHASE_B.format(repo=str(REPO), tests=str(REPO / "tests"), ledger=ledger_path, tx=a["tx_hash"])],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc2.returncode == 0, proc2.stderr
    line2 = [ln for ln in proc2.stdout.splitlines() if ln.startswith("VERDICT:")][-1]
    tampered = json.loads(line2[len("VERDICT:"):])

    evidence = {
        "mission": 27,
        "method": "cross-process restart: sign in process A, verify in a fresh python -c process B",
        "network": "testnet",
        "mainnet": False,
        "network_calls": 0,
        "phase_a": a,
        "phase_b_fresh_process": {
            "verified": verdict["verified"],
            "state": verdict["state"],
            "transaction_digest": verdict.get("transaction_digest"),
            "digest_source": verdict.get("digest_source"),
            "public_key": verdict.get("public_key"),
            "checks": {c["name"]: c["holds"] for c in verdict["checks"]},
        },
        "phase_c_tampered_bytes_fail_closed": {
            "verified": tampered["verified"],
            "state": tampered["state"],
            "failures": tampered.get("failures"),
        },
    }
    (HERE / "independent_restart_verification.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(evidence, indent=2))

    ok = (
        verdict["verified"] is True
        and verdict["state"] == "VERIFIED"
        and verdict.get("digest_source") == "recomputed_from_persisted_signed_bytes"
        and all(verdict["checks"][i]["holds"] for i in range(len(verdict["checks"])))
        and tampered["verified"] is False
    )
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
