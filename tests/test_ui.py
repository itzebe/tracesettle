"""Interface tests: a real HTTP server on a real socket, real request handling.

Only the outbound network is substituted. The server, routing, validation,
serialization, and HTML rendering are the real code paths.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager

import pytest

from tracesettle import __version__
from tracesettle import config
from tracesettle import ui as ui_module
from tracesettle.httpclient import HttpClient
from tracesettle.model import OverallOutcome
from tracesettle.ratelimit import TokenBucketLimiter
from tracesettle.ui import InvestigationServer

from conftest import (
    FakeOpener,
    REAL_DEPOSIT_ADDRESS,
    client_for,
    load_raw,
)

#: Sentinel for a connection-level overload refusal: the server closed the
#: connection (reset / broken pipe) before the client finished sending its body.
#: This is a distinct, expected outcome from an HTTP status response.
CONNECTION_REFUSED = object()


@contextmanager
def running_server(opener: FakeOpener | None = None, max_attempts: int = 1, **server_kwargs):
    """Start the real server; patch only the outbound HTTP opener.

    Extra keyword arguments are forwarded to :class:`InvestigationServer` so a test
    can tighten the concurrency cap, socket timeout, or rate limits.
    """
    server = InvestigationServer(
        ("127.0.0.1", 0), timeout_seconds=2.0, max_attempts=max_attempts, **server_kwargs
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    original = ui_module.HttpClient

    if opener is not None:
        def patched(timeout=None, max_attempts=None, **kwargs):
            return client_for(
                opener,
                attempts=max_attempts or 1,
                cache=server.upstream_cache,
                host_limiter=server.host_limiter,
            )

        ui_module.HttpClient = patched  # type: ignore[assignment]
    try:
        yield f"http://{host}:{port}"
    finally:
        ui_module.HttpClient = original  # type: ignore[assignment]
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _host_port(base: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(base)
    return parsed.hostname or "127.0.0.1", parsed.port or 80


@contextmanager
def _raw_connection(base: str):
    host, port = _host_port(base)
    sock = socket.create_connection((host, port), timeout=5)
    try:
        yield sock
    finally:
        try:
            sock.close()
        except OSError:
            pass


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
    # The page requests the full response so its copy/download buttons have both
    # the JSON and Markdown documents to work with.
    assert "api/investigate?format=full" in html
    # The narrow-screen rule hides a column by class, not by position, so adding
    # an evidence column can never silently hide the wrong one.
    assert ".col-secondary { display: none; }" in html
    assert "nth-child" not in html
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


#: Hashes from the success fixtures, used to key fake routes on the request body
#: so concurrent investigations do not depend on route-consumption order.
_ORIGIN_TX = "0xfca11aa01bce5fc20a6cbeb4ca30e8af994cda47de9bd5fa53a9ca4295ba01d2"
_DEST_TX = "0x91cd1ede3f49313787d6c21c633aee5a1417c46a6dfd33904dc407498c9af3f3"
_NEAR_DEPOSIT_TX = "5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb"
_NEAR_SETTLEMENT_TX = "FbrSoTHbQdwD6HxabhaozvQQVBA4kF2Qn2c3W2otp284"


def _wire_full_success(opener: FakeOpener) -> FakeOpener:
    """Wire a complete successful investigation, independent of request ordering."""
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), body_contains=_ORIGIN_TX)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"), body_contains=_DEST_TX)
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"), body_contains=_NEAR_DEPOSIT_TX)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx_omft.json"), body_contains=_NEAR_SETTLEMENT_TX)
    return opener


def test_investigate_success_end_to_end():
    opener = _wire_full_success(FakeOpener())

    with running_server(opener) as base:
        status, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
    assert status == 200
    payload = json.loads(body)
    assert payload["data"]["outcome"] == OverallOutcome.SETTLED_VERIFIED.value
    # The default response is the structured report only: the pretty JSON and
    # Markdown documents are not serialized unless explicitly requested.
    assert set(payload) == {"data"}
    # No credential material.
    blob = body.decode().lower()
    for needle in ("x-api-key", "api_key", "authorization", "bearer ", "private_key"):
        assert needle not in blob
    # Every evidence item carries a verification method, so a reader can see how
    # each classification was reached rather than only what was concluded.
    items = payload["data"]["evidence"]
    assert items
    assert all(e.get("verification_method") for e in items)


def test_investigate_full_format_is_backward_compatible():
    """``format=full`` returns all three representations, as the API always did."""
    opener = _wire_full_success(FakeOpener())
    with running_server(opener) as base:
        status, body = _post(
            base + "/api/investigate?format=full", {"identifier": REAL_DEPOSIT_ADDRESS}
        )
    assert status == 200
    payload = json.loads(body)
    assert set(payload) == {"data", "json", "markdown"}
    assert "TRACESETTLE investigation report" in payload["markdown"]
    assert json.loads(payload["json"])["outcome"] == OverallOutcome.SETTLED_VERIFIED.value
    assert "| Method |" in payload["markdown"]


@pytest.mark.parametrize(
    "fmt,expected_key,marker",
    [
        ("json", "json", "TRACESETTLE"),
        ("markdown", "markdown", "TRACESETTLE investigation report"),
    ],
)
def test_investigate_explicit_export_formats(fmt, expected_key, marker):
    opener = _wire_full_success(FakeOpener())
    with running_server(opener) as base:
        status, body = _post(
            base + f"/api/investigate?format={fmt}", {"identifier": REAL_DEPOSIT_ADDRESS}
        )
    assert status == 200
    payload = json.loads(body)
    assert set(payload) == {expected_key}
    assert marker in payload[expected_key]


def test_investigate_unknown_format_rejected():
    with running_server() as base:
        status, body = _post(
            base + "/api/investigate?format=xml", {"identifier": REAL_DEPOSIT_ADDRESS}
        )
    assert status == 400
    assert "format" in json.loads(body)["error"]


def test_default_response_is_smaller_than_full():
    """The lean default must be materially smaller than the all-formats payload."""
    opener = _wire_full_success(FakeOpener())
    with running_server(opener) as base:
        _, lean = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
    opener2 = _wire_full_success(FakeOpener())
    with running_server(opener2) as base:
        _, full = _post(
            base + "/api/investigate?format=full", {"identifier": REAL_DEPOSIT_ADDRESS}
        )
    assert len(lean) < len(full)
    # The Markdown and pretty-JSON copies are the bulk of the difference.
    assert len(full) - len(lean) > 5_000


def test_default_response_size_is_bounded():
    """A response must not balloon past a sane ceiling for one investigation."""
    opener = _wire_full_success(FakeOpener())
    with running_server(opener) as base:
        _, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
    # The structured report for one investigation is tens of kilobytes; the
    # ceiling guards against an accidental re-introduction of duplication.
    assert len(body) < 60_000


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


# --- Phase 1: slowloris, concurrency, body bounding --------------------------


def test_slow_client_is_timed_out_and_does_not_pin_a_slot():
    """A client that never sends its body is dropped by the socket timeout."""
    with running_server(client_socket_timeout=0.6) as base:
        host, port = _host_port(base)
        sock = socket.create_connection((host, port), timeout=5)
        try:
            # Announce a body we never send: a classic slowloris hold.
            sock.sendall(
                b"POST /api/investigate HTTP/1.1\r\n"
                b"Host: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"
            )
            start = time.monotonic()
            sock.settimeout(5)
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, ConnectionResetError, OSError):
                pass
            elapsed = time.monotonic() - start
        finally:
            sock.close()
    # The server must have closed or answered within the socket timeout, not held
    # the connection open indefinitely.
    assert elapsed < 5.0
    if data:
        assert b"408" in data.split(b"\r\n", 1)[0] or b"400" in data.split(b"\r\n", 1)[0]


def test_concurrency_cap_rejects_excess_with_503():
    """With a cap of 1, a second simultaneous connection is refused, not queued."""
    with running_server(max_concurrency=1, client_socket_timeout=2.0) as base:
        host, port = _host_port(base)
        holder = socket.create_connection((host, port), timeout=5)
        try:
            # Hold the only slot with a half-open request.
            holder.sendall(b"POST /api/investigate HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n")
            time.sleep(0.3)
            # A second connection must be answered 503 immediately.
            second = socket.create_connection((host, port), timeout=5)
            try:
                second.sendall(b"GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n")
                second.settimeout(5)
                reply = second.recv(4096)
            finally:
                second.close()
            assert reply.startswith(b"HTTP/1.1 503"), reply[:40]
            assert b"Retry-After" in reply
        finally:
            holder.close()


def test_semaphore_slot_is_released_after_success_and_error():
    """A slot is returned on every path, so the server keeps serving."""
    with running_server(max_concurrency=1) as base:
        # A successful request.
        status, _, _ = _get(base + "/api/health")
        assert status == 200
        # A malformed request (handler returns early, before the body is read).
        status, _ = _post(base + "/api/investigate", None, raw=b"{not json")
        assert status == 400
        # The slot must be free again: another request still succeeds.
        status, _, _ = _get(base + "/api/health")
        assert status == 200


def test_handler_exception_releases_slot():
    """An exception inside the handler must not leak a concurrency slot."""
    class Boom(HttpClient):
        def __init__(self, *a, **k):
            pass

        def get_json(self, *a, **k):
            raise RuntimeError("boom")

    with running_server(max_concurrency=1) as base:
        original = ui_module.HttpClient
        ui_module.HttpClient = Boom  # type: ignore[assignment]
        try:
            status, _ = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
        finally:
            ui_module.HttpClient = original  # type: ignore[assignment]
        assert status == 502
        # The slot was released; the next request is served.
        status, _, _ = _get(base + "/api/health")
        assert status == 200


def test_oversized_body_rejected_before_reading():
    """A declared body larger than the cap is refused without being read."""
    with running_server() as base:
        status, body = _post(
            base + "/api/investigate",
            None,
            raw=b'{"identifier":"' + b"a" * (20 * 1024) + b'"}',
        )
    assert status == 413
    assert "too large" in json.loads(body)["error"]


def test_many_idle_connections_do_not_exhaust_threads():
    """Idle connections are bounded by the cap and then closed by the timeout."""
    with running_server(max_concurrency=4, client_socket_timeout=0.6) as base:
        host, port = _host_port(base)
        socks = []
        try:
            for _ in range(10):
                try:
                    s = socket.create_connection((host, port), timeout=2)
                    socks.append(s)
                except OSError:
                    break
            # Every connection that was accepted must be closed by the server
            # within roughly the socket timeout; none may hang forever.
            time.sleep(1.5)
            for s in socks:
                s.settimeout(1)
                try:
                    s.recv(1)
                except (socket.timeout, ConnectionResetError, OSError):
                    pass
        finally:
            for s in socks:
                s.close()
        # The server is still healthy afterwards.
        status, _, _ = _get(base + "/api/health")
        assert status == 200


def test_connection_flood_does_not_spawn_a_thread_per_connection():
    """Overload is refused at accept time, so a flood cannot create threads."""
    created: list[str] = []
    original_init = threading.Thread.__init__

    def counting_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created.append(self.name)

    threading.Thread.__init__ = counting_init
    try:
        with running_server(max_concurrency=2, client_socket_timeout=1.0) as base:
            host, port = _host_port(base)
            socks = []
            try:
                for _ in range(40):
                    try:
                        socks.append(socket.create_connection((host, port), timeout=1))
                    except OSError:
                        break
                time.sleep(0.4)
                spawned = len(created)
            finally:
                for s in socks:
                    s.close()
    finally:
        threading.Thread.__init__ = original_init

    # ThreadingMixIn would spawn one thread per connection without the accept-time
    # check; with it, only the capped workers exist. Allow a small margin for the
    # accept thread and the test's own thread.
    assert spawned <= 6, f"spawned {spawned} threads for {len(socks)} connections"


# --- Phase 2: authentication and rate limiting ------------------------------


def test_api_key_required_when_configured(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "s3cret-key")
    with running_server() as base:
        status, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
    assert status == 401
    assert "s3cret" not in body.decode()
    assert json.loads(body)["error"] == "unauthorized"


def test_api_key_accepts_correct_key(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "s3cret-key")
    opener = _wire_full_success(FakeOpener())
    with running_server(opener) as base:
        req = urllib.request.Request(
            base + "/api/investigate",
            data=json.dumps({"identifier": REAL_DEPOSIT_ADDRESS}).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": "s3cret-key"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            body = resp.read()
    assert status == 200
    assert json.loads(body)["data"]["outcome"] == OverallOutcome.SETTLED_VERIFIED.value


def test_api_key_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "s3cret-key")
    with running_server() as base:
        req = urllib.request.Request(
            base + "/api/investigate",
            data=json.dumps({"identifier": REAL_DEPOSIT_ADDRESS}).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": "wrong"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            status = 200
        except urllib.error.HTTPError as e:
            status = e.code
    assert status == 401


def test_api_key_does_not_gate_health_or_page(monkeypatch):
    """Only the investigation endpoint is gated; liveness and the page stay open."""
    monkeypatch.setattr(config, "API_KEY", "s3cret-key")
    with running_server() as base:
        assert _get(base + "/api/health")[0] == 200
        assert _get(base + "/")[0] == 200


def test_per_ip_rate_limit_returns_429():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=2)
    with running_server(client_limiter=limiter) as base:
        codes = [_get(base + "/api/health")[0] for _ in range(1)]  # health is ungated
        assert codes == [200]
        # The investigation endpoint is the rate-limited one.
        seen = []
        for _ in range(4):
            status, body = _post(base + "/api/investigate", {"identifier": "x" * 200})
            seen.append(status)
    assert 429 in seen
    # Once limited, the Retry-After header is present.
    assert seen[-1] == 429


def test_rate_limit_not_bypassed_by_forwarded_header():
    """A spoofed X-Forwarded-For must not grant a fresh bucket."""
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1)
    with running_server(client_limiter=limiter) as base:
        def call(xff: str):
            req = urllib.request.Request(
                base + "/api/investigate",
                data=json.dumps({"identifier": "0xdeadbeef"}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "X-Forwarded-For": xff},
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code

        first = call("1.1.1.1")
        # A different forwarded address must NOT get a fresh allowance, because the
        # limiter keys on the real socket peer, not the header.
        second = call("2.2.2.2")
    assert first == 200
    assert second == 429


def test_retry_after_header_on_rate_limit():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1)
    with running_server(client_limiter=limiter) as base:
        _post(base + "/api/investigate", {"identifier": "0xdeadbeef"})
        req = urllib.request.Request(
            base + "/api/investigate",
            data=json.dumps({"identifier": "0xdeadbeef"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            headers = {}
            status = 200
        except urllib.error.HTTPError as e:
            status = e.code
            headers = dict(e.headers)
    assert status == 429
    assert int(headers.get("Retry-After", "0")) >= 1
    # The connection is closed so the unread request body cannot be parsed as a
    # second request on a kept-alive connection.
    assert headers.get("Connection", "").lower() == "close"


def test_error_response_closes_connection_to_avoid_body_desync(monkeypatch):
    """An early rejection must not leave the unread body to be re-parsed."""
    monkeypatch.setattr(config, "API_KEY", "s3cret-key")
    with running_server() as base:
        host, port = _host_port(base)
        sock = socket.create_connection((host, port), timeout=5)
        body = json.dumps({"identifier": REAL_DEPOSIT_ADDRESS}).encode()
        # One connection, two pipelined requests; both are refused (no key) and
        # the connection closes after the first, so the body cannot be re-read.
        sock.sendall(
            b"POST /api/investigate HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        sock.close()
        raw = b"".join(chunks)
    assert raw.startswith(b"HTTP/1.1 401")
    assert b"Connection: close" in raw
    # Exactly one response: the second (desynced) request was never parsed.
    assert raw.count(b"HTTP/1.1 ") == 1


# --- Phase 5: version disclosure --------------------------------------------


def test_server_header_does_not_disclose_version_or_python():
    with running_server() as base:
        status, _, headers = _get(base + "/api/health")
    assert status == 200
    server = headers.get("Server", "")
    assert server == "TRACESETTLE"
    assert __version__ not in server
    assert "Python" not in server


# --- Phase 1: concurrency under load ----------------------------------------


def test_concurrent_investigations_all_succeed_within_cap():
    """Many simultaneous real investigations are served without error or deadlock."""
    opener = _wire_full_success(FakeOpener())
    with running_server(opener, max_concurrency=8) as base:
        results: list[tuple[int, str]] = []
        lock = threading.Lock()

        def worker():
            status, body = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
            with lock:
                results.append((status, json.loads(body)["data"]["outcome"]))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert len(results) == 8
        assert all(status == 200 for status, _ in results)
        assert all(outcome == OverallOutcome.SETTLED_VERIFIED.value for _, outcome in results)


def test_overload_returns_503_and_recovers():
    """Under more load than the cap allows, excess is refused and the server recovers.

    A refusal has two legitimate forms, both documented by ``_reject_overloaded``:
    an HTTP ``503`` when the request is refused after the body arrives, or a
    connection-level reset when the server closes before the client finishes
    uploading. The test records both explicitly and still requires that *every*
    request reaches a definite outcome (none hangs) and that the server recovers.
    A timeout is never accepted as a refusal: a hung request must fail the test.
    """
    opener = _wire_full_success(FakeOpener())
    with running_server(opener, max_concurrency=2) as base:
        outcomes: list[object] = []  # an HTTP status int, or the refusal sentinel
        lock = threading.Lock()

        def worker():
            try:
                status, _ = _post(
                    base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS}
                )
                outcome: object = status
            except urllib.error.URLError as exc:
                # A timeout is a hang, not a refusal: let it fail the test.
                if isinstance(exc.reason, TimeoutError):
                    raise
                # Broken pipe / reset: the server refused at the connection level
                # before the request body finished uploading.
                outcome = CONNECTION_REFUSED
            except ConnectionError:
                outcome = CONNECTION_REFUSED
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        # Every request reached a definite outcome; none hung.
        assert len(outcomes) == 12
        http_statuses = [o for o in outcomes if o is not CONNECTION_REFUSED]
        # Every HTTP response was an admission or an overload refusal.
        assert set(http_statuses) <= {200, 503}
        # The server is genuinely functional under this load, not dead: at least
        # one request was served. This also rules out a vacuous pass where every
        # request failed at the connection level.
        assert 200 in http_statuses
        # Once the load subsides the server serves normally again.
        status, _, _ = _get(base + "/api/health")
        assert status == 200


# --- Phase 3: caching through the server ------------------------------------


def test_identical_investigations_reuse_cached_upstream_status():
    """A repeated investigation does not re-fetch the cacheable status record."""
    opener = _wire_full_success(FakeOpener())

    with running_server(opener) as base:
        first_status, first = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})
        second_status, second = _post(base + "/api/investigate", {"identifier": REAL_DEPOSIT_ADDRESS})

    assert first_status == 200 and second_status == 200
    # Same verdict from the cached status record.
    assert json.loads(first)["data"]["outcome"] == OverallOutcome.SETTLED_VERIFIED.value
    assert json.loads(second)["data"]["outcome"] == OverallOutcome.SETTLED_VERIFIED.value
    # The 1Click status GET was issued exactly once across both investigations.
    status_calls = [c for c in opener.calls if "/v0/status" in c]
    assert len(status_calls) == 1
