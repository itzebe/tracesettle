"""Console and guard HTTP tests: a real server, real sockets, real request handling.

Only the outbound investigation network is substituted. The guard endpoints make
no outbound calls, so they run entirely against real code.

The two properties that matter most here are checked over HTTP, not in-process:

* the console page is served and requests the guard endpoints it needs;
* the guard routes enforce the API key and the per-client rate limit, and a
  refused signing attempt returns a refusal rather than an execution.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from tracesettle import config
from tracesettle.ratelimit import TokenBucketLimiter
from tracesettle.ui import InvestigationServer

from guard_helpers import (
    APPROVED_DESTINATION,
    UNAPPROVED_DESTINATION,
    make_authority,
    make_service,
)


@contextmanager
def running_server(*, api_key: str | None = None, guard_limiter=None, guard_service=None, **kwargs):
    """Start the real server with a real guard service.

    ``config.API_KEY`` is always restored to its previous value, including when it
    was unset, so a test that configures a key cannot leak it into a later test.
    """
    original = config.API_KEY
    config.API_KEY = api_key
    server = InvestigationServer(
        ("127.0.0.1", 0),
        timeout_seconds=2.0,
        max_attempts=1,
        guard_service=guard_service or make_service(authority=make_authority()),
        guard_limiter=guard_limiter,
        **kwargs,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        config.API_KEY = original


def _request(method, url, payload=None, key=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-API-Key"] = key
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read()
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = body
            return resp.status, parsed, dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return e.code, parsed, dict(e.headers)


LEGIT = {
    "service_id": "treasury-agent",
    "operation": "WITHDRAWAL",
    "chain": "eth",
    "asset": "USDC",
    "amount": "1250.50",
    "destination": APPROVED_DESTINATION,
    "request_id": "ui-1",
}
SUSPICIOUS = dict(LEGIT, amount="480000", destination=UNAPPROVED_DESTINATION, request_id="ui-2")


def _html(response_body) -> str:
    """Decode an HTML response body to text (a JSON error body stays JSON text)."""
    if isinstance(response_body, bytes):
        return response_body.decode("utf-8", "replace")
    return json.dumps(response_body)


# --- console page ---------------------------------------------------------


def test_console_page_is_served():
    with running_server() as base:
        status, body, headers = _request("GET", base + "/console")
    html = _html(body)
    assert status == 200
    assert "TRACESETTLE" in html
    assert "Security Operations Console" in html
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'none'" in headers.get("Content-Security-Policy", "")


def test_console_declares_every_required_section():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    for section in (
        "Security Overview",
        "Transaction Guard",
        "NEAR Agent Security",
        "Investigations",
        "Security Incidents",
        "Policies &amp; Controls",
        "Integrations",
        "Audit Logs",
        "Settings",
    ):
        assert section in html, section


def test_console_is_accessible_and_responsive():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert 'width=device-width' in html
    assert 'role="tablist"' in html
    assert 'role="tab"' in html
    assert 'role="tabpanel"' in html
    assert "aria-selected" in html
    assert "Skip to main content" in html
    # Status is text, never colour alone.
    assert "status s-" in html
    # Reduced motion is respected.
    assert "prefers-reduced-motion" in html
    # Long identifiers must wrap rather than scroll the page sideways on a
    # narrow viewport (verified in a real 375px browser; a CSS-only guard here).
    assert "overflow-wrap: anywhere" in html
    assert "word-break: break-word" in html


def test_console_requests_only_same_origin_endpoints():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert "/api/guard/evaluate" in html
    assert "/api/guard/sign" in html
    assert "/api/guard/incidents" in html
    assert "/api/guard/audit" in html
    assert "/api/guard/policy" in html
    assert "/api/guard/near/scenarios" in html
    assert "/api/guard/near/access-keys" in html
    assert "/api/guard/near/policy-scope" in html
    assert "/api/guard/near/behaviours" in html
    assert "/api/guard/near/prompt-injection" in html
    assert "/api/guard/near/agent-evaluate" in html
    assert "api/investigate?format=full" in html
    # No third-party origins: the wallet connector is bundled and served from
    # this origin, so no external script is ever loaded.
    assert "https://cdn" not in html
    assert "http://cdn" not in html


def test_console_loads_its_wallet_connector_same_origin():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert '<script src="/assets/near-connect.js"></script>' in html
    assert "/api/guard/near/wallet/prepare" in html
    assert "/api/guard/near/wallet/verify" in html
    assert "/api/guard/near/wallet" in html


def test_wallet_panel_offers_the_complete_operation_controls():
    """The wallet panel exposes asset choice, preview, disconnect and confirm.

    A transfer UI that can only pick NEAR, cannot disconnect, and asks the wallet
    to sign without a final confirmation is an incomplete product. These are the
    controls that make the flow usable and safe; their absence is a regression.
    """
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert 'id="w-asset"' in html
    assert 'id="w-receiver"' in html
    assert 'id="w-amount"' in html
    assert 'id="w-preview"' in html
    assert 'id="w-disconnect"' in html
    # The JS implements the new behaviour, not just the markup.
    assert "function populateWalletAssets" in html
    assert "function renderWalletPreview" in html
    assert "function disconnectWallet" in html
    assert "function confirmWalletOperation" in html
    assert "supported_assets" in html


def test_wallet_panel_has_no_third_party_script_or_fake_state():
    """The wallet controls stay same-origin and never fabricate a connected state."""
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    # No external script origin is introduced by the wallet controls.
    assert "https://cdn" not in html
    # The account starts disconnected; the UI must not claim a connection.
    assert 'id="w-account" class="small muted"' in html
    assert "not connected" in html


def test_wallet_asset_is_served_and_is_the_bundled_connector():
    with running_server() as base:
        status, body, headers = _request("GET", base + "/assets/near-connect.js")
    assert status == 200
    assert headers.get("Content-Type", "").startswith("text/javascript")
    assert isinstance(body, bytes) and len(body) > 10_000
    # It is the near-connect bundle, not an arbitrary payload.
    assert b"NearConnector" in body


def test_wallet_asset_path_traversal_is_refused():
    with running_server() as base:
        for path in ("/assets/../ui.py", "/assets/near-connect.js/../ui.py", "/assets/%2e%2e/ui.py"):
            status, _, _ = _request("GET", base + path)
            assert status == 404, path


def test_console_csp_allows_the_wallet_connector_but_not_arbitrary_scripts():
    with running_server() as base:
        _, _, headers = _request("GET", base + "/console")
    csp = headers.get("Content-Security-Policy", "")
    # The bundled script is same-origin; the manifest/iframe origins are named.
    assert "script-src 'self'" in csp
    assert "https://cdn.jsdelivr.net" in csp
    assert "https://raw.githubusercontent.com" in csp
    # No wildcard origin is ever allowed.
    assert "*" not in csp


def test_console_csp_allows_the_near_rpc_the_wallet_connector_must_reach():
    """The wallet integration builds and broadcasts through a NEAR JSON-RPC.

    Without these origins in ``connect-src`` the browser blocks the fetch and the
    wallet can never sign, so the wallet-mediated flow silently dies. Each host is
    an explicit literal; the policy must never widen to a wildcard to fix this.
    """
    with running_server() as base:
        _, _, headers = _request("GET", base + "/console")
    csp = headers.get("Content-Security-Policy", "")
    connect = csp.split("connect-src", 1)[1].split(";", 1)[0]
    for host in (
        "https://rpc.testnet.near.org",
        "https://test.rpc.fastnear.com",
        "https://rpc.mainnet.near.org",
        "https://free.rpc.fastnear.com",
    ):
        assert host in connect, host
    # A stale provider (served an old chain head) must not be re-added.
    assert "rpc.near.nightly.app" not in connect
    assert "*" not in csp


def test_api_responses_keep_the_strict_default_csp():
    with running_server() as base:
        _, _, headers = _request("GET", base + "/api/health")
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "cdn.jsdelivr.net" not in csp



def test_console_does_not_fabricate_a_live_badge():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert ">LIVE<" not in html


def test_console_script_is_valid_javascript():
    """The console's inline script must parse as JavaScript.

    A syntax error anywhere in the script makes the whole page non-functional
    (no panel ever loads), yet every string-substring assertion still passes. A
    real parse is the only check that catches a broken string literal.
    """
    import re

    from tracesettle.guard.console import CONSOLE_HTML

    scripts = re.findall(r"<script[^>]*>(.*?)</script>", CONSOLE_HTML, re.S)
    assert scripts, "the console must ship an inline script"
    for index, script in enumerate(scripts):
        assert _js_parses(script), f"inline script {index} does not parse"


def _js_parses(script: str) -> bool:
    """True when ``node --check`` accepts ``script``.

    ``node`` is a dev/CI tool, not a runtime dependency; when it is absent the
    check is skipped rather than reported as passing.
    """
    import shutil
    import subprocess
    import tempfile

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available to validate the console script")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(script)
        path = handle.name
    try:
        completed = subprocess.run(
            [node, "--check", path], capture_output=True, text=True, timeout=30
        )
        return completed.returncode == 0
    finally:
        import os

        os.unlink(path)


def test_legacy_investigation_page_links_to_the_console():
    with running_server() as base:
        status, body, _ = _request("GET", base + "/")
    html = _html(body)
    assert status == 200
    assert 'href="console"' in html


# --- guard GET routes -----------------------------------------------------


def test_policy_endpoint_over_http():
    with running_server() as base:
        status, payload, _ = _request("GET", base + "/api/guard/policy")
    assert status == 200
    assert payload["policy"]["policy_id"]


def test_metrics_endpoint_over_http():
    with running_server() as base:
        status, payload, _ = _request("GET", base + "/api/guard/metrics")
    assert status == 200
    assert "counts" in payload
    assert payload["authorization"]["key_id"]


def test_invariants_endpoint_reports_every_guarantee_holds():
    with running_server() as base:
        status, payload, _ = _request("GET", base + "/api/guard/invariants")
    assert status == 200
    assert payload["all_hold"] is True
    names = {i["name"] for i in payload["invariants"]}
    assert "refusal_never_reaches_the_executor" in names
    assert "authorization_is_single_use" in names
    assert all(i["statement"] for i in payload["invariants"])


# --- guard POST routes ----------------------------------------------------


def test_evaluate_and_sign_over_http():
    with running_server() as base:
        status, decision, _ = _request(
            "POST",
            base + "/api/guard/evaluate",
            {"transaction": LEGIT, "return_authorization": True},
        )
        assert status == 200
        assert decision["decision"] == "ALLOW"
        token = decision["authorization"]
        status, result, _ = _request(
            "POST", base + "/api/guard/sign", {"transaction": LEGIT, "authorization": token}
        )
    assert result["outcome"] == "EXECUTED"
    assert result["simulated"] is True


def test_replay_is_refused_over_http():
    with running_server() as base:
        _, decision, _ = _request(
            "POST", base + "/api/guard/evaluate", {"transaction": LEGIT, "return_authorization": True}
        )
        token = decision["authorization"]
        _, first, _ = _request(
            "POST", base + "/api/guard/sign", {"transaction": LEGIT, "authorization": token}
        )
        _, second, _ = _request(
            "POST", base + "/api/guard/sign", {"transaction": LEGIT, "authorization": token}
        )
    assert first["outcome"] == "EXECUTED"
    assert second["outcome"] == "REFUSED"
    assert second["state"] == "REPLAYED"


def test_blocked_transaction_is_refused_over_http():
    with running_server() as base:
        _, decision, _ = _request("POST", base + "/api/guard/evaluate", {"transaction": SUSPICIOUS})
        _, result, _ = _request(
            "POST", base + "/api/guard/sign", {"transaction": SUSPICIOUS, "authorization": None}
        )
    assert decision["decision"] == "BLOCK"
    assert result["outcome"] == "REFUSED"


def test_oversized_body_is_rejected_before_it_is_read():
    with running_server() as base:
        status, payload, _ = _request(
            "POST", base + "/api/guard/evaluate", {"transaction": LEGIT, "pad": "x" * (config.GUARD_MAX_BODY_BYTES + 100)}
        )
    assert status == 413


def test_malformed_json_is_rejected():
    with running_server() as base:
        req = urllib.request.Request(
            base + "/api/guard/evaluate",
            data=b"{not json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            status = 200
        except urllib.error.HTTPError as e:
            status = e.code
    assert status == 400


# --- authentication -------------------------------------------------------


def test_guard_requires_the_key_when_configured():
    with running_server(api_key="s3cret-key") as base:
        assert _request("GET", base + "/api/guard/policy")[0] == 401
        assert _request("GET", base + "/api/guard/policy", key="wrong")[0] == 401
        assert _request("GET", base + "/api/guard/policy", key="s3cret-key")[0] == 200
        assert _request("POST", base + "/api/guard/evaluate", {"transaction": LEGIT})[0] == 401
        assert (
            _request("POST", base + "/api/guard/evaluate", {"transaction": LEGIT}, key="s3cret-key")[0]
            == 200
        )


def test_console_page_stays_open_when_a_key_is_configured():
    with running_server(api_key="s3cret-key") as base:
        assert _request("GET", base + "/console")[0] == 200
        assert _request("GET", base + "/api/health")[0] == 200


def test_guard_rate_limit_returns_429_with_retry_after():
    limiter = TokenBucketLimiter(1, 2)
    with running_server(guard_limiter=limiter) as base:
        statuses = [_request("GET", base + "/api/guard/metrics")[0] for _ in range(5)]
    assert 200 in statuses
    assert 429 in statuses
    with running_server(guard_limiter=TokenBucketLimiter(1, 1)) as base:
        _request("GET", base + "/api/guard/metrics")
        status, _, headers = _request("GET", base + "/api/guard/metrics")
    assert status == 429
    assert int(headers.get("Retry-After", "0")) >= 1


def test_guard_routes_do_not_leak_the_signing_key():
    service = make_service(authority=make_authority())
    with running_server(guard_service=service) as base:
        _request("POST", base + "/api/guard/evaluate", {"transaction": LEGIT, "return_authorization": True})
        bodies = [
            _request("GET", base + "/api/guard/metrics")[1],
            _request("GET", base + "/api/guard/policy")[1],
            _request("GET", base + "/api/guard/audit")[1],
        ]
    key_hex = bytes(range(32)).hex()
    for body in bodies:
        assert key_hex not in json.dumps(body)


def test_unknown_guard_route_is_404():
    with running_server() as base:
        assert _request("GET", base + "/api/guard/does-not-exist")[0] == 404
        assert _request("POST", base + "/api/guard/does-not-exist", {})[0] == 404


def test_console_near_tab_states_the_scope_gap_and_the_simulation_label():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert "NEAR Agent Security" in html
    assert "Policy scope" in html
    assert "Access-key permissions" in html
    assert "cannot transfer NEAR" in html
    # The panel never claims a real transaction.
    assert "nothing is broadcast" in html


def test_near_agent_evaluate_over_http_allows_and_blocks():
    with running_server() as base:
        status, body, _ = _request(
            "POST",
            base + "/api/guard/near/agent-evaluate",
            {
                "transaction": {
                    "service_id": "treasury-agent",
                    "operation": "WITHDRAWAL",
                    "chain": "eth",
                    "asset": "USDC",
                    "amount": "100",
                    "destination": APPROVED_DESTINATION,
                    "scope": "INTENTS",
                    "policy_action": "withdraw",
                }
            },
        )
    assert status == 200
    assert body["outcome"] == "ALLOW"

    with running_server() as base:
        status, body, _ = _request(
            "POST",
            base + "/api/guard/near/agent-evaluate",
            {
                "transaction": {
                    "service_id": "treasury-agent",
                    "operation": "WITHDRAWAL",
                    "chain": "eth",
                    "asset": "USDC",
                    "amount": "100",
                    "destination": UNAPPROVED_DESTINATION,
                    "scope": "INTENTS",
                    "policy_action": "withdraw",
                }
            },
        )
    assert status == 200
    assert body["outcome"] == "BLOCK"
    assert body["permits_signing"] is False


def test_near_scenarios_endpoint_over_http():
    with running_server() as base:
        status, body, _ = _request("GET", base + "/api/guard/near/scenarios")
    assert status == 200
    assert body["all_passed"] is True
    assert len(body["results"]) == 9


def test_safeguards_endpoint_reports_the_learning_loop_state():
    """With no safeguard store configured, the loop is honestly reported disabled."""
    with running_server() as base:
        status, body, _ = _request("GET", base + "/api/guard/safeguards")
    assert status == 200
    assert body["enabled"] is False
    assert body["safeguards"] == []
    assert "tighten" in body["note"]


def test_console_near_tab_has_a_learning_loop_panel():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert "Learning loop" in html
    assert "durable safeguard" in html.lower()
    assert "never overrides the operator" in html


def test_console_near_demo_destinations_match_the_real_default_policy():
    """The console's one-click demo must use a destination the real policy approves.

    A hardcoded demo address that the policy does not approve would make the
    "approved payment" button return BLOCK, which is a false demonstration.
    """
    from tracesettle.guard.policy import DEFAULT_POLICY
    from tracesettle.guard.console import CONSOLE_HTML

    approved = {d.lower() for d in DEFAULT_POLICY.approved_destinations}
    # The legitimate demo address is the one on the ternary's true branch.
    assert "0x4e6d3a556e485188e9c9a528bc72c88bd92bd735" in CONSOLE_HTML
    assert "0x4e6d3a556e485188e9c9a528bc72c88bd92bd735" in approved
    # The attack demo address must not be approved by the policy.
    assert "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" not in approved


def test_console_lifecycle_submit_is_not_double_bound():
    """A single submit must not create two intents.

    The bug: the Authorize button had both an ``onclick`` and the form an
    ``onsubmit``, so one click fired two POSTs and created two intent records.
    The button must be bound once, through the form only.
    """
    from tracesettle.guard.console import CONSOLE_HTML

    # The button must not carry its own click handler for creating an intent.
    assert 'getElementById("i-submit").onclick' not in CONSOLE_HTML
    assert 'getElementById("intents-create").onsubmit' in CONSOLE_HTML
    # An in-flight guard and a derived idempotency key make a resend idempotent.
    assert "IN.busy" in CONSOLE_HTML
    assert "payloadKey" in CONSOLE_HTML
    assert "idempotency_key" in CONSOLE_HTML


def test_console_lifecycle_has_a_wallet_handoff_and_deposit_step():
    """The user journey must expose the wallet handoff and the deposit record step."""
    from tracesettle.guard.console import CONSOLE_HTML

    assert "Fund this deposit address" in CONSOLE_HTML
    assert 'id="i-deposit-hash"' in CONSOLE_HTML
    assert 'id="i-deposit"' in CONSOLE_HTML
    assert 'id="i-handoff"' in CONSOLE_HTML
    # The handoff states plainly that the transfer is the user's own. The JS
    # source splits the sentence across two concatenated string literals, so
    # assert both fragments rather than the joined prose.
    assert "never signs, " in CONSOLE_HTML
    assert "sends, or holds funds" in CONSOLE_HTML
    # Quote fees/expiry are shown to the user.
    assert "Minimum received" in CONSOLE_HTML
    assert "Quote expires" in CONSOLE_HTML


def test_console_lifecycle_exposes_independent_destination_verification():
    """The user journey must expose an independent destination-delivery check.

    A provider SUCCESS is a claim; the destination leg is verified from the chain
    alone. The console must offer the action and render the verdict.
    """
    from tracesettle.guard.console import CONSOLE_HTML

    assert 'id="i-verify-destination"' in CONSOLE_HTML
    assert "Verify delivery on destination chain" in CONSOLE_HTML
    assert "renderDestinationVerification" in CONSOLE_HTML
    assert '"verify-destination"' in CONSOLE_HTML


def test_console_lifecycle_exposes_a_resume_affordance():
    """A durable record must be resumable after a reload.

    The store exists so a lifecycle survives a restart, but the list was a
    dead-end: it named the intents and offered no way to act on one, so a reload
    abandoned an in-flight transaction. The list must render a per-intent Resume
    control that re-selects the record through the real ``/get`` action.
    """
    from tracesettle.guard.console import CONSOLE_HTML

    assert "renderIntentResumeList" in CONSOLE_HTML
    assert "resumeIntent" in CONSOLE_HTML
    # The Resume control carries the intent id and re-selects that record.
    assert 'data-intent-id=' in CONSOLE_HTML
    assert '"/get"' in CONSOLE_HTML
    # The handler is delegated to the container, which survives the innerHTML
    # rewrite the render performs; a per-row binding would be discarded.
    assert 'getElementById("intents-create-output").onclick' in CONSOLE_HTML
    # Resuming must not create a new intent.
    assert "no new intent is created" in CONSOLE_HTML


def test_console_declares_an_inline_favicon():
    """No external origin, and no 404 for a missing favicon."""
    from tracesettle.guard.console import CONSOLE_HTML

    assert 'rel="icon"' in CONSOLE_HTML
    assert "data:image/svg+xml" in CONSOLE_HTML


# --- durable settlement-investigation history -----------------------------


def test_history_is_disabled_when_no_store_is_configured():
    with running_server() as base:
        status, body, _ = _request("GET", base + "/api/guard/investigations")
    assert status == 200
    assert body["enabled"] is False
    assert body["investigations"] == []


def test_a_stored_report_is_retrievable_over_http(tmp_path):
    from tracesettle.investigation_store import InvestigationStore

    store = InvestigationStore(tmp_path / "investigations.db")
    store.save(
        {
            "investigation_id": "ts-1",
            "input": {"identifier": "0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"},
            "outcome": "SETTLED_VERIFIED",
            "created_at": "2026-11-03T00:00:00Z",
            "evidence": [{"classification": "CONFIRMED"}],
        }
    )
    try:
        with running_server(investigation_store=store) as base:
            status, listing, _ = _request("GET", base + "/api/guard/investigations")
            assert status == 200
            assert listing["enabled"] is True
            assert listing["investigations"][0]["investigation_id"] == "ts-1"

            status, detail, _ = _request("GET", base + "/api/guard/investigations/ts-1")
            assert status == 200
            assert detail["investigation"]["outcome"] == "SETTLED_VERIFIED"

            status, _, _ = _request("GET", base + "/api/guard/investigations/nope")
            assert status == 404
    finally:
        store.close()


def test_history_is_gated_by_the_api_key_when_one_is_configured(tmp_path):
    # Guard reads expose operational state, so history is gated by the same API
    # key as the other guard routes: missing key -> 401, correct key -> 200.
    from tracesettle.investigation_store import InvestigationStore

    store = InvestigationStore(tmp_path / "investigations.db")
    try:
        with running_server(api_key="secret", investigation_store=store) as base:
            status, _, _ = _request("GET", base + "/api/guard/investigations")
            assert status == 401
            status, body, _ = _request(
                "GET", base + "/api/guard/investigations", key="secret"
            )
            assert status == 200
            assert body["enabled"] is True
    finally:
        store.close()


def test_console_near_tab_exposes_real_tee_attestation_verification():
    with running_server() as base:
        _, body, _ = _request("GET", base + "/console")
    html = _html(body)
    assert "Verifiable execution (Intel TDX attestation)" in html
    assert "/api/guard/near/tee/attest" in html
    # The panel states what is not checked, so it cannot over-claim.
    assert "not</strong> checked" in html or "not checked" in html
    assert "not a TEE-integrated execution path" in html
