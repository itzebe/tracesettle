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
