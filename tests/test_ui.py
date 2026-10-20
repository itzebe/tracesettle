"""Interface tests: a real HTTP server on a real socket, real request handling.

Only the outbound network is substituted. The server, routing, validation,
serialization, and HTML rendering are the real code paths.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from tracesettle import __version__
from tracesettle import ui as ui_module
from tracesettle.httpclient import HttpClient
from tracesettle.model import OverallOutcome
from tracesettle.ui import InvestigationServer

from conftest import (
    FakeOpener,
    REAL_DEPOSIT_ADDRESS,
    client_for,
    load_raw,
)


@contextmanager
def running_server(opener: FakeOpener | None = None, max_attempts: int = 1):
    """Start the real server; patch only the outbound HTTP opener."""
    server = InvestigationServer(("127.0.0.1", 0), timeout_seconds=2.0, max_attempts=max_attempts)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    original = ui_module.HttpClient

    if opener is not None:
        def patched(timeout=None, max_attempts=None, **kwargs):
            return client_for(opener, attempts=max_attempts or 1)

        ui_module.HttpClient = patched  # type: ignore[assignment]
    try:
        yield f"http://{host}:{port}"
    finally:
        ui_module.HttpClient = original  # type: ignore[assignment]
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(url: str) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _post(url: str, payload, raw: bytes | None = None) -> tuple[int, bytes]:
    body = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# --- Page and health --------------------------------------------------------


def test_index_page_renders():
    with running_server() as base:
        status, body, headers = _get(base + "/")
    html = body.decode()
    assert status == 200
    assert "TRACESETTLE" in html
    assert __version__ in html
    assert "read-only" in html
    # Security headers present.
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'none'" in headers.get("Content-Security-Policy", "")
    # Responsive viewport declared.
    assert "width=device-width" in html
    # No fabricated live-status badges.
    assert "LIVE" not in html
    # The result summary surfaces the supplied identifier and its type, so a
    # judge can see exactly what was investigated and under what interpretation.
    assert "Supplied identifier" in html
    assert "Identifier type" in html
    assert "Supported path" in html


def test_health_endpoint():
    with running_server() as base:
        status, body, _ = _get(base + "/api/health")
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "ok"
    assert data["read_only"] is True


def test_unknown_path_404():
    with running_server() as base:
        status, body, _ = _get(base + "/nope")
    assert status == 404


# --- Investigation endpoint -------------------------------------------------


def test_investigate_success_end_to_end():
    opener = FakeOpener()
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), once=True)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"), once=True)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx_omft.json"))

    with running_server(opener) as base:
        status, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
    assert status == 200
    payload = json.loads(body)
    assert payload["data"]["outcome"] == OverallOutcome.SETTLED_VERIFIED.value
    # Both export formats are returned.
    assert "TRACESETTLE investigation report" in payload["markdown"]
    assert json.loads(payload["json"])["outcome"] == OverallOutcome.SETTLED_VERIFIED.value
    # No credential material.
    blob = body.decode().lower()
    for needle in ("x-api-key", "api_key", "authorization", "bearer ", "private_key"):
        assert needle not in blob


def test_investigate_not_found_is_graceful():
    opener = FakeOpener()
    opener.http_error("GET", "/v0/status", 404, b"{}")
    with running_server(opener) as base:
        status, body = _post(base + "/api/investigate", {"identifier": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
    assert status == 200
    data = json.loads(body)["data"]
    assert data["outcome"] == OverallOutcome.NOT_FOUND.value


def test_investigate_upstream_timeout_still_returns_report():
    opener = FakeOpener()
    opener.timeout("GET", "/v0/status")
    with running_server(opener) as base:
        status, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
    assert status == 200
    data = json.loads(body)["data"]
    assert data["outcome"] != OverallOutcome.SETTLED_VERIFIED.value
    assert data["sources"][0]["status"] == "TIMEOUT"


# --- Input validation -------------------------------------------------------


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({}, 400),
        ({"identifier": 123}, 400),
        ({"identifier": ""}, 400),
        ({"identifier": "   "}, 400),
        ({"identifier": "a" * 129}, 400),
        ({"identifier": "abc\u0000def"}, 400),
    ],
)
def test_investigate_rejects_bad_input(payload, expected):
    with running_server() as base:
        status, body = _post(base + "/api/investigate", payload)
    assert status == expected
    assert "error" in json.loads(body)


def test_investigate_rejects_malformed_json():
    with running_server() as base:
        status, body = _post(base + "/api/investigate", None, raw=b"{not json")
    assert status == 400
    assert "valid JSON" in json.loads(body)["error"]


def test_investigate_rejects_non_object_json():
    with running_server() as base:
        status, body = _post(base + "/api/investigate", None, raw=b'["a", "b"]')
    assert status == 400


def test_investigate_rejects_oversized_body():
    with running_server() as base:
        status, body = _post(
            base + "/api/investigate", None, raw=b'{"identifier":"' + b"a" * (9 * 1024) + b'"}'
        )
    assert status == 413


def test_post_to_unknown_path_404():
    with running_server() as base:
        status, _ = _post(base + "/api/nope", {"identifier": "x"})
    assert status == 404


def test_upstream_exception_is_not_leaked():
    """An unexpected internal error must not expose internals to the client."""
    class Boom(HttpClient):
        def __init__(self, *a, **k):
            pass

        def get_json(self, *a, **k):
            raise RuntimeError("internal detail: /etc/passwd")

    with running_server() as base:
        original = ui_module.HttpClient
        ui_module.HttpClient = Boom  # type: ignore[assignment]
        try:
            status, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
        finally:
            ui_module.HttpClient = original  # type: ignore[assignment]
    assert status == 502
    text = body.decode()
    assert "internal detail" not in text
    assert "/etc/passwd" not in text
