"""The NEAR endpoints must work in a container that copies only the package.

The production image runs ``COPY tracesettle/ ./tracesettle/`` and nothing else
(tests, demo, docs and evidence are excluded by ``.dockerignore``). Any runtime
code that reads a fixture from ``tests/fixtures/`` therefore works in the test
tree and fails in the image: the route raises ``FileNotFoundError`` and the
connection is dropped with no HTTP response.

These tests copy the package alone into a temporary directory and exercise the
real code paths there, so a fixture that is reachable only from the test tree
fails here instead of in production.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from tracesettle.guard.invariants import INVARIANTS

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "tracesettle"


def _package_only_copy(tmp_path: Path) -> Path:
    """A copy of the repository as the production image sees it."""
    dest = tmp_path / "app"
    dest.mkdir()
    shutil.copytree(PACKAGE_ROOT, dest / "tracesettle", dirs_exist_ok=True)
    return dest


def test_near_attack_fixtures_live_inside_the_package():
    """The fixtures the runtime reads must be shipped with the package."""
    from tracesettle.near import attacks

    assert attacks.FIXTURE_DIR.is_dir()
    assert attacks.FIXTURE_DIR == PACKAGE_ROOT / "near" / "fixtures"
    assert (attacks.FIXTURE_DIR / "policy_in_force.json").is_file()


def test_all_scenarios_run_from_a_package_only_copy(tmp_path):
    root = _package_only_copy(tmp_path)
    script = (
        "import sys, json;"
        f"sys.path.insert(0, {str(root)!r});"
        "from tracesettle.near.attacks import run_all;"
        "r = run_all();"
        "print(json.dumps({'n': len(r), 'passed': all(x.passed for x in r)}))"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["n"] == 9
    assert result["passed"] is True


def test_near_guard_routes_answer_from_a_package_only_copy(tmp_path):
    """Every NEAR GET route must answer, not drop the connection."""
    root = _package_only_copy(tmp_path)
    script = f"""
import sys, threading, json, urllib.request
sys.path.insert(0, {str(root)!r})
from tracesettle.ui import InvestigationServer

server = InvestigationServer(("127.0.0.1", 0), timeout_seconds=5.0, max_attempts=1)
host, port = server.server_address[:2]
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
try:
    out = {{}}
    for path in (
        "/api/guard/near/scenarios",
        "/api/guard/near/access-keys",
        "/api/guard/near/policy-scope",
        "/api/guard/near/settlement-demo",
        "/api/guard/invariants",
    ):
        try:
            with urllib.request.urlopen(f"http://{{host}}:{{port}}{{path}}", timeout=10) as r:
                out[path] = r.status
        except Exception as exc:
            out[path] = type(exc).__name__
    print("RESULT:" + json.dumps(out))
finally:
    server.shutdown()
    server.server_close()
    t.join(timeout=5)
"""
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=180
    )
    assert out.returncode == 0, out.stderr
    line = [ln for ln in out.stdout.splitlines() if ln.startswith("RESULT:")][-1]
    results = json.loads(line[len("RESULT:") :])
    assert results == {
        "/api/guard/near/scenarios": 200,
        "/api/guard/near/access-keys": 200,
        "/api/guard/near/policy-scope": 200,
        "/api/guard/near/settlement-demo": 200,
        "/api/guard/invariants": 200,
    }, results


def test_settlement_assurance_runs_from_a_package_only_copy(tmp_path):
    """The assurance vocabulary and its rules must not depend on test-only files."""
    root = _package_only_copy(tmp_path)
    script = (
        "import sys, json;"
        f"sys.path.insert(0, {str(root)!r});"
        "from tracesettle.model import OverallOutcome, ReconciliationResult, Stage,"
        " StageAssessment, StageState;"
        "from tracesettle.near.settlement import AssuranceLevel, settlement_assurance_from_result;"
        "refund = ReconciliationResult(stages=(StageAssessment(stage=Stage.REFUND,"
        " state=StageState.CONFIRMED, summary='payout'),), last_confirmed_stage=Stage.REFUND,"
        " outcome=OverallOutcome.REFUND_VERIFIED, summary='refund');"
        "a = settlement_assurance_from_result(refund);"
        "print(json.dumps({'levels': sorted(x.value for x in AssuranceLevel),"
        " 'refund_level': a.level.value, 'verified': a.independently_verified}))"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert {"SETTLEMENT_VERIFIED", "DESTINATION_DELIVERY_VERIFIED", "ORIGIN_DEPOSIT_VERIFIED",
            "REFUNDED", "FAILED", "PARTIAL", "PENDING", "REPORTED_ONLY", "UNKNOWN",
            "UNAVAILABLE", "CONTRADICTORY"} <= set(
        result["levels"]
    )
    assert result["refund_level"] == "REFUNDED"
    assert result["verified"] is False


def test_all_invariants_hold_from_a_package_only_copy(tmp_path):
    """Every structural invariant must be checkable with only the shipped package."""
    root = _package_only_copy(tmp_path)
    script = (
        "import sys, json;"
        f"sys.path.insert(0, {str(root)!r});"
        "from tracesettle.guard.invariants import check_all;"
        "r = check_all();"
        "print(json.dumps({'n': len(r), 'all_hold': all(x.holds for x in r)}))"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["n"] == len(INVARIANTS)
    assert result["all_hold"] is True


def test_origin_verifier_is_shipped_and_importable_from_the_package(tmp_path):
    """The origin verifier must live in the shipped package, not the test tree."""
    root = _package_only_copy(tmp_path)
    script = (
        "import sys;"
        f"sys.path.insert(0, {str(root)!r});"
        "from tracesettle.near.origin_verify import origin_contract_address, OriginVerdict;"
        "assert origin_contract_address('nep141:eth-0x' + 'a'*40 + '.omft.near') == '0x' + 'a'*40;"
        "assert origin_contract_address('nep141:eth.omft.near') is None;"
        "print('ok')"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().endswith("ok")


def test_near_execution_boundary_runs_from_a_package_only_copy(tmp_path):
    """The execution boundary and its imports must resolve without the test tree.

    The boundary is built with an inline fake RPC (no test helper, no network) and
    driven to a BLOCK decision, so every runtime import the route needs is
    exercised in a package-only copy.
    """
    root = _package_only_copy(tmp_path)
    script = r'''
import sys, json
sys.path.insert(0, sys.argv[1])
from decimal import Decimal
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.policy import PolicyConfig, ServicePolicy
from tracesettle.guard.service import GuardService
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519
from tracesettle.near.execution import NearExecutionBoundary
from tracesettle.near.networks import NETWORKS, NearNetwork
from tracesettle.near.rpc import RpcResult

class Rpc:
    def __init__(self, c): self.c = c
    def status(self): return RpcResult(SourceStatus.OK, {"chain_id": self.c.chain_id, "genesis_hash": self.c.genesis_hash})
    def block_hash(self, *, finality="final"): return RpcResult(SourceStatus.OK, {"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1})
    def view_access_key(self, a, p): return RpcResult(SourceStatus.OK, {"nonce": 1, "permission": "FullAccess"})
    def call_function(self, a, m, args=None, *, finality="final"): return RpcResult(SourceStatus.OK, {"decimals": 24})
    def send_tx(self, s, *, wait_until="INCLUDED_FINAL"): return RpcResult(SourceStatus.OK, {})
    def tx_status(self, h, a): return RpcResult(SourceStatus.OK, {})

cfg = NETWORKS[NearNetwork.TESTNET]
policy = PolicyConfig(policy_id="p", name="p", version="1",
    approved_destinations=frozenset({"ok.testnet"}),
    services={"svc": ServicePolicy(service_id="svc", allowed_operations=frozenset({"WITHDRAWAL"}),
        allowed_chains=frozenset({"near-testnet"}), allowed_assets=frozenset({"NEAR:NATIVE"}),
        max_amount_per_transaction=Decimal("100"), approval_threshold=Decimal("1000"))},
    per_transaction_limit=Decimal("100"), approval_threshold=Decimal("1000"),
    allow_unlisted_destinations=False)
g = GuardService(policy=policy, authority=AuthorizationAuthority(key=bytes(range(32)), key_id="k", ephemeral=False, replay_store=InMemoryReplayStore()))
b = NearExecutionBoundary(g, cfg, rpc=Rpc(cfg))
pk = "ed25519:" + __import__("base64").b64encode(b"").decode()  # placeholder, replaced below
seed = bytes(range(32))
alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = int.from_bytes(ed25519.public_key(seed), "big"); out = ""
while n:
    n, r = divmod(n, 58); out = alpha[r] + out
pk = "ed25519:" + out
prepared = b.prepare(service_id="svc", account_id="agent.testnet", public_key=pk,
    receiver_id="attacker.testnet", asset_identifier="near:native", amount_human="1")
print(json.dumps({"authorized": prepared.authorized, "decision": prepared.decision.decision.value}))
'''
    out = subprocess.run(
        [sys.executable, "-c", script, str(root)], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["authorized"] is False
    assert result["decision"] == "BLOCK"


def test_wallet_asset_is_inside_the_package():
    """The bundled wallet connector must ship with the package, not the test tree."""
    from tracesettle import ui

    asset = PACKAGE_ROOT / "static" / "near-connect.js"
    assert asset.is_file()
    assert asset.stat().st_size > 10_000
    assert "/assets/near-connect.js" in ui._STATIC_FILES


def test_wallet_routes_answer_from_a_package_only_copy(tmp_path):
    """The wallet info route and its asset must work with only the package shipped.

    The execution boundary is enabled in-process (no test helper, no network) so
    the wallet routes are exercised against the real handler.
    """
    root = _package_only_copy(tmp_path)
    script = f"""
import sys, threading, json, urllib.request
sys.path.insert(0, {str(root)!r})
import os
os.environ["TRACESETTLE_NEAR_EXECUTION"] = "1"
from tracesettle.ui import InvestigationServer

server = InvestigationServer(("127.0.0.1", 0), timeout_seconds=5.0, max_attempts=1)
host, port = server.server_address[:2]
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
try:
    out = {{}}
    for path in ("/api/guard/near/wallet", "/assets/near-connect.js"):
        try:
            with urllib.request.urlopen(f"http://{{host}}:{{port}}{{path}}", timeout=10) as r:
                out[path] = r.status
        except Exception as exc:
            out[path] = type(exc).__name__
    print("RESULT:" + json.dumps(out))
finally:
    server.shutdown()
    server.server_close()
    t.join(timeout=5)
"""
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=180
    )
    assert out.returncode == 0, out.stderr
    line = [ln for ln in out.stdout.splitlines() if ln.startswith("RESULT:")][-1]
    results = json.loads(line[len("RESULT:") :])
    assert results == {"/api/guard/near/wallet": 200, "/assets/near-connect.js": 200}, results
