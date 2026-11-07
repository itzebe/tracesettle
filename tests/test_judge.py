"""The independent evaluation path: the scenario matrix and its two surfaces.

TRACESETTLE's core claim is that an unsafe payment is stopped before a signer is
reached. This module tests that claim the way a judge would check it: by running
the real scenario matrix and asserting the *behavioural* facts, not the prose.

What is real here: the authorization boundary, the guard controls, the reference
signer, the replay store, the approval authority and the settlement verifier.
The only substitution is the executor, which records what it was asked to do and
never touches a chain. That is the same boundary the product itself draws, so the
tests assert "the executor was never called" rather than "a mock was not called".
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from tracesettle import config, judge
from tracesettle.markdown import render
from tracesettle.ui import InvestigationServer

from guard_helpers import make_authority, make_service


# --- the scenario matrix: behavioural facts --------------------------------


def _by_id() -> dict[str, judge.JudgeScenario]:
    return {s.id: s for s in judge.run_all()}


def test_every_enforcement_scenario_matches_its_expectation():
    """The nine simulated scenarios must all behave as specified."""
    results = [s for s in judge.run_all() if not s.real]
    assert len(results) == 9
    for s in results:
        assert s.passed, f"{s.id} did not match: {s.observed}"


def test_a_refused_scenario_never_reaches_the_signer():
    """The headline property: a refusal is proven by a zero signer-call count.

    This is the whole product in one assertion. It is written against the real
    executor counter, so a regression that lets a refused transaction through
    fails here rather than in prose.
    """
    by_id = _by_id()
    for scenario_id in (
        "unauthorized_receiver",
        "manipulated_amount",
        "tampered_after_authorization",
        "expired_authorization",
        "missing_service_identity",
    ):
        s = by_id[scenario_id]
        assert s.decision in {"BLOCK", "WRONG_PARAMETERS", "EXPIRED"}, scenario_id
        assert s.signer_calls == 0, f"{scenario_id} reached the signer"
        assert not s.broadcast


def test_nothing_is_ever_broadcast_in_the_simulated_matrix():
    """No simulated scenario may claim a broadcast; the executor touches no chain."""
    for s in judge.run_all():
        if s.real:
            continue
        assert s.broadcast is False
        assert s.simulated is True


def test_the_legitimate_path_is_allowed_not_blocked():
    """A boundary that blocks everything is not a security product.

    The legitimate scenario must be ALLOW and must reach the signer exactly once.
    This is the counterpart to the refusal tests: it stops a fix that simply
    refuses everything from passing the suite.
    """
    s = _by_id()["legitimate_authorized"]
    assert s.passed
    assert s.decision == "ALLOW"
    assert s.signer_calls == 1


def test_approval_is_required_then_honoured():
    """An above-threshold payment signs only after a bound human approval."""
    s = _by_id()["approval_required"]
    assert s.passed
    assert s.decision == "REQUIRE_APPROVAL"
    assert s.evidence["without_approval_executed"] is False
    assert s.evidence["with_approval_executed"] is True
    # Exactly one execution: the unapproved attempt never ran.
    assert s.signer_calls == 1


def test_a_replayed_authorization_executes_only_once():
    s = _by_id()["replayed_authorization"]
    assert s.passed
    assert s.decision in {"REPLAYED", "MISSING"}
    assert s.signer_calls == 1


def test_malformed_input_is_rejected_with_a_typed_error():
    """Hostile input must never raise an unhandled exception."""
    s = _by_id()["malformed_input"]
    assert s.passed
    for case in s.evidence["cases"]:
        assert case["rejected"], case
        assert not case["error"].startswith("UNHANDLED"), case


def test_report_summary_is_consistent_with_the_scenarios():
    report = judge.to_report()
    scenarios = report["scenarios"]
    assert report["summary"]["total"] == len(scenarios)
    assert report["summary"]["passed"] == sum(1 for s in scenarios if s["passed"])
    assert report["summary"]["broadcast_occurred"] is False
    # The enforcement half is the part that must always pass.
    assert report["summary"]["enforcement_passed"] == report["summary"]["enforcement_total"]


def test_run_one_returns_a_single_scenario():
    s = judge.run_one("unauthorized_receiver")
    assert s.id == "unauthorized_receiver"
    with pytest.raises(KeyError):
        judge.run_one("no-such-scenario")


def test_the_matrix_is_deterministic_across_runs():
    """Identical evidence must produce an identical result."""
    first = json.dumps(judge.to_report()["summary"], sort_keys=True)
    second = json.dumps(judge.to_report()["summary"], sort_keys=True)
    assert first == second


def test_every_scenario_labels_whether_it_is_real():
    for s in judge.run_all():
        assert s.real is (not s.simulated), s.id


def test_an_environmental_live_outage_is_skipped_not_failed():
    """A live check that could not reach the chain is a limitation, not a defect.

    The distinction matters: a judge must never read a network outage as an
    unexpected product result. Only a live *contradiction* is a failure.
    """
    report = judge.to_report()
    live = [s for s in report["scenarios"] if s["real"]]
    assert len(live) == 1
    s = live[0]
    assert "skipped" in s
    if s["decision"] in {"UNAVAILABLE", "UNSUPPORTED"}:
        assert s["skipped"] is True
        assert s["passed"] is False
    else:
        # On a host with network the live check must have a definite verdict.
        assert s["skipped"] is False


def test_skipped_is_false_for_every_enforcement_scenario():
    for s in judge.run_all():
        if s.real:
            continue
        assert s.skipped is False, s.id


# --- the served endpoint ----------------------------------------------------


@contextmanager
def running_server(*, api_key: str | None = None, public_demo: bool = False, **kwargs):
    original_key = config.API_KEY
    original_demo = config.PUBLIC_DEMO_ENABLED
    config.API_KEY = api_key
    config.PUBLIC_DEMO_ENABLED = public_demo
    server = InvestigationServer(
        ("127.0.0.1", 0),
        timeout_seconds=2.0,
        max_attempts=1,
        guard_service=make_service(authority=make_authority()),
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
        config.API_KEY = original_key
        config.PUBLIC_DEMO_ENABLED = original_demo


def _get(url: str, key: str | None = None):
    req = urllib.request.Request(url, method="GET")
    if key is not None:
        req.add_header("X-API-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = body
            return resp.status, parsed, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return exc.code, parsed, dict(exc.headers)


def test_judge_endpoint_serves_the_matrix_keylessly_when_enabled():
    with running_server(api_key="s3cret", public_demo=True) as base:
        status, payload, _ = _get(base + "/api/guard/judge/scenarios")
    assert status == 200
    assert isinstance(payload, dict)
    assert len(payload["scenarios"]) == 10
    assert payload["summary"]["enforcement_passed"] == 9
    assert payload["summary"]["broadcast_occurred"] is False


def test_judge_endpoint_is_gated_when_the_demo_is_off():
    with running_server(api_key="s3cret", public_demo=False) as base:
        status, _, _ = _get(base + "/api/guard/judge/scenarios")
    assert status == 401


def test_evaluate_page_is_served_only_with_the_demo_enabled():
    with running_server(public_demo=True) as base:
        status, body, headers = _get(base + "/evaluate")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert "Independent evaluation" in body
    assert "api/guard/judge/scenarios" in body
    with running_server(public_demo=False) as base:
        status, _, _ = _get(base + "/evaluate")
    assert status == 404


def test_evaluate_page_has_no_third_party_origin():
    """The evaluation page is same-origin only; the favicon is a data: URI."""
    with running_server(public_demo=True) as base:
        _, body, _ = _get(base + "/evaluate")
    without_icon = body.split('rel="icon"', 1)[-1].split(">", 1)[-1]
    assert "http://" not in without_icon and "https://" not in without_icon


def test_judge_guide_is_rendered_and_only_with_the_demo_enabled():
    with running_server(public_demo=True) as base:
        status, body, headers = _get(base + "/JUDGE_GUIDE")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert "<h1>" in body
    # A table in the guide must have rendered as a real table, not raw pipes.
    assert "<table>" in body
    with running_server(public_demo=False) as base:
        status, _, _ = _get(base + "/JUDGE_GUIDE")
    assert status == 404


def test_landing_page_links_to_evaluate_when_the_demo_is_enabled():
    with running_server(public_demo=True) as base:
        _, body, _ = _get(base + "/")
    assert 'href="evaluate"' in body
    assert "Test TRACESETTLE" in body


def test_evaluate_page_offers_the_agent_integration_when_the_demo_is_enabled():
    """The connect-an-agent section points at the real sandbox surface."""
    with running_server(public_demo=True) as base:
        _, body, _ = _get(base + "/evaluate")
    assert "Connect your own agent" in body
    assert 'id="connect-run"' in body
    assert "api/agent/connect" in body
    assert "api/agent/evaluate" in body
    assert "api/agent/openapi.json" in body
    # It must not claim to sign or broadcast.
    assert "Nothing is broadcast" in body


def test_landing_nav_links_to_connect_an_agent_when_the_demo_is_enabled():
    with running_server(public_demo=True) as base:
        _, body, _ = _get(base + "/")
    assert "evaluate#connect" in body


# --- the Markdown renderer --------------------------------------------------


def test_markdown_renderer_escapes_html():
    """A document must never be able to inject script."""
    html = render("# Title\n\n<script>alert(1)</script>\n")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_markdown_renderer_drops_unsafe_link_targets():
    html = render("[click](javascript:alert(1))")
    assert "javascript:" not in html
    assert "click" in html


def test_markdown_renderer_keeps_safe_links():
    html = render("[guide](https://example.com/x) and [top](#main)")
    assert 'href="https://example.com/x"' in html
    assert 'href="#main"' in html


def test_markdown_renderer_renders_the_structures_the_guide_uses():
    html = render(
        "# H1\n\n## H2\n\n- a\n- b\n\n1. one\n\n> quote\n\n`code` and **bold**\n\n"
        "| a | b |\n| --- | --- |\n| 1 | 2 |\n"
    )
    for tag in ("<h1>", "<h2>", "<ul>", "<li>", "<ol>", "<blockquote>", "<code>",
                "<strong>", "<table>", "<th>", "<td>"):
        assert tag in html, tag


def test_markdown_renderer_handles_a_fenced_code_block():
    html = render("```bash\npython3 -m tracesettle judge\n```")
    assert "<pre>" in html
    assert "python3 -m tracesettle judge" in html


def test_the_shipped_judge_guide_renders_without_raw_markers():
    """The guide in the repository must render cleanly, with no leftover markup."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    text = (root / "JUDGE_GUIDE.md").read_text(encoding="utf-8")
    html = render(text)
    assert "<h1>" in html
    assert "<table>" in html
    # No unrendered heading or table marker leaked into the output.
    assert "\n## " not in html
    assert "| ---" not in html
