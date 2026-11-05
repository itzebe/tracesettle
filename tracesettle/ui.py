"""Read-only investigation interface (Python standard library only).

Serves a single page plus two JSON endpoints:

* ``GET /``                — the investigation form.
* ``POST /api/investigate`` — run an investigation, return the structured report.
* ``GET /api/health``      — liveness.

Design constraints honoured here:

* read-only: no endpoint mutates anything, signs anything, or moves funds;
* no secrets are read from or written to the client;
* every upstream call has a timeout and a bounded retry budget;
* the page never fabricates balances, hashes, or live-status badges.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import pathlib
import signal
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import DISCLAIMER, __version__, config
from .cache import TtlCache
from .guard.api import GuardAPI
from .guard.service import GuardService
from .guard.console import CONSOLE_HTML
from .httpclient import HttpClient
from .investigation import build_result, investigate
from .model import IdentifierType
from .ratelimit import TokenBucketLimiter
from .report import build_report
from .serviceauth import CREDENTIAL_HEADER

log = logging.getLogger("tracesettle.ui")

MAX_BODY_BYTES = 8 * 1024
MAX_IDENTIFIER_CHARS = 128

#: The default Content-Security-Policy: everything same-origin, no third-party
#: origin at all. It applies to every response except the security console and
#: its vendored wallet asset.
DEFAULT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "connect-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'"
)

#: The console CSP. It additionally allows the *bundled* wallet connector to run
#: wallet code in a sandboxed iframe and to resolve the wallet manifest. The
#: connector executes wallet integrations hosted by the wallet teams, so the
#: console alone permits those origins; the API responses and every other page
#: keep :data:`DEFAULT_CSP`. ``script-src 'self'`` is deliberate - the connector
#: is served from this origin, so no third-party script is loaded.
#:
#: ``connect-src`` also names the public NEAR JSON-RPC endpoints the connector's
#: wallet integrations call to build and broadcast a transfer (``final`` block
#: hash, access-key nonce, ``broadcast_tx_commit``). Without them the browser
#: blocks the fetch and the wallet cannot sign, so the whole wallet-mediated flow
#: is dead even though every other part works. Each host is an explicit literal;
#: no wildcard is used. ``rpc.near.nightly.app`` is deliberately absent: it served
#: a stale chain head and the wallet then broadcast against a mismatched block.
CONSOLE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
    "connect-src 'self' https://cdn.jsdelivr.net https://raw.githubusercontent.com "
    "https://rpc.testnet.near.org https://test.rpc.fastnear.com "
    "https://rpc.mainnet.near.org https://free.rpc.fastnear.com https://rpc.mainnet.fastnear.com "
    "https://archival-rpc.mainnet.fastnear.com; "
    "frame-src https://cdn.jsdelivr.net https://raw.githubusercontent.com; "
    "img-src 'self' data:; form-action 'none'; base-uri 'none'"
)

#: Static assets served from ``tracesettle/static``. A fixed allowlist, so a
#: request path can never escape the package directory.
_STATIC_FILES = {
    "/assets/near-connect.js": ("near-connect.js", "text/javascript; charset=utf-8"),
}

#: Sentinel returned by :meth:`Handler._authenticate_service` when it has already
#: sent a refusal. Distinct from ``None``, which means "authentication disabled".
_AUTH_REFUSED = object()

#: The guard POST routes that carry a service identity and therefore require
#: per-service authentication when a credential registry is configured.
_SERVICE_OPERATION_PATHS = frozenset(
    {
        "/api/guard/evaluate",
        "/api/guard/sign",
        "/api/guard/near/agent-evaluate",
        "/api/guard/near/lifecycle",
        "/api/guard/near/lifecycle/list",
    }
)

#: Distinguishes "no registry argument was supplied" (load from configuration)
#: from an explicit ``None`` (service authentication deliberately disabled).
_UNSET = object()

#: Response formats for ``POST /api/investigate``.
#:   * ``default``  — ``data`` only (the structured report; leanest).
#:   * ``json``     — the pretty-printed JSON document.
#:   * ``markdown`` — the Markdown document.
#:   * ``full``     — all three, for backward compatibility with earlier clients.
_VALID_FORMATS = frozenset({"default", "json", "markdown", "full"})

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACESETTLE — NEAR Intents settlement investigator</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --fg: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff;
    --ok: #3fb950; --warn: #d29922; --bad: #f85149; --unknown: #8b949e; --sim: #a371f7;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { padding: 20px 16px 12px; border-bottom: 1px solid var(--border); }
  h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: .5px; }
  .tag { color: var(--muted); font-size: 12px; }
  main { max-width: 1100px; margin: 0 auto; padding: 16px; }
  .disclaimer { background: #1c2128; border: 1px solid var(--border); border-left: 3px solid var(--accent);
    padding: 10px 12px; border-radius: 6px; color: var(--muted); font-size: 13px; margin-bottom: 16px; }
  form { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  input[type=text] { flex: 1 1 320px; min-width: 0; padding: 10px 12px; border-radius: 6px;
    border: 1px solid var(--border); background: #0b0f14; color: var(--fg); font: inherit; }
  input[type=text]:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
  button { padding: 10px 16px; border-radius: 6px; border: 1px solid var(--border);
    background: #21262d; color: var(--fg); font: inherit; cursor: pointer; }
  button:hover { border-color: var(--accent); }
  button[disabled] { opacity: .5; cursor: progress; }
  .hint { color: var(--muted); font-size: 12px; margin-bottom: 16px; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 14px 16px; margin-bottom: 14px; }
  .panel h2 { margin: 0 0 10px; font-size: 15px; }
  .outcome { font-size: 18px; font-weight: 700; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px;
    border: 1px solid var(--border); color: var(--muted); margin-right: 6px; }
  .state-CONFIRMED { color: var(--ok); border-color: var(--ok); }
  .state-REPORTED { color: var(--warn); border-color: var(--warn); }
  .state-MISSING, .state-UNKNOWN { color: var(--unknown); }
  .state-INCOMPLETE { color: var(--unknown); border-color: var(--unknown); }
  .state-UNAVAILABLE { color: var(--bad); border-color: var(--bad); }
  .state-CONTRADICTORY { color: var(--bad); border-color: var(--bad); }
  .state-SIMULATED { color: var(--sim); border-color: var(--sim); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--border);
    vertical-align: top; word-break: break-word; }
  th { color: var(--muted); font-weight: 600; }
  .stage-row td:first-child { white-space: nowrap; }
  ul { margin: 6px 0 0; padding-left: 18px; }
  li { margin-bottom: 4px; }
  .sim-banner { border-left: 3px solid var(--sim); background: #1d1a2e; padding: 8px 12px;
    border-radius: 6px; color: #d6c9ff; font-size: 13px; margin-bottom: 12px; }
  .error { border-left: 3px solid var(--bad); background: #2b1618; padding: 8px 12px;
    border-radius: 6px; color: #ffb3ae; font-size: 13px; margin-bottom: 12px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; font-size: 13px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; word-break: break-all; }
  a { color: var(--accent); }
  code { background: #0b0f14; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  footer { color: var(--muted); font-size: 12px; padding: 20px 16px; text-align: center; }
  @media (max-width: 640px) {
    h1 { font-size: 17px; }
    table { font-size: 12px; }
    .col-secondary { display: none; }
  }
</style>
</head>
<body>
<header>
  <h1>TRACESETTLE</h1>
  <div class="tag">Read-only cross-chain settlement investigator &middot; NEAR Intents 1Click &middot; v__VERSION__</div>
</header>
<main>
  <div class="disclaimer" id="disclaimer">__DISCLAIMER__</div>
  <form id="form" autocomplete="off">
    <input type="text" id="identifier" name="identifier" maxlength="128"
      placeholder="Deposit address, intent hash, or NEAR transaction hash" aria-label="Identifier">
    <button type="submit" id="submit">Investigate</button>
  </form>
  <div class="hint">
    Supported: 1Click <strong>deposit addresses</strong> (full path), <strong>intent hashes</strong>
    (settlement status only). A transaction hash cannot be reverse-looked-up. No keys required.
  </div>
  <div id="output" aria-live="polite"></div>
</main>
<footer>TRACESETTLE never signs, submits, or moves anything. Evidence is attributed to its source.
  &middot; <a href="console">Security Operations Console</a></footer>
<script>
const out = document.getElementById('output');
const form = document.getElementById('form');
const input = document.getElementById('identifier');
const submit = document.getElementById('submit');

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function pill(state) {
  return '<span class="pill state-' + esc(state) + '">' + esc(state) + '</span>';
}

function panel(title, inner) {
  return '<section class="panel"><h2>' + esc(title) + '</h2>' + inner + '</section>';
}

function render(d) {
  let html = '';

  const stages = d.stages || [];
  const simulated = (d.evidence || []).some(e => e.provenance === 'SIMULATED');
  if (simulated) {
    html += '<div class="sim-banner"><strong>Simulated evidence present.</strong> ' +
      'At least one item below is simulated test data, not a live transaction.</div>';
  }

  const inp = d.input || {};
  let summary = '<div class="kv">' +
    '<dt>Outcome</dt><dd class="outcome">' + esc(d.outcome) + '</dd>' +
    '<dt>Last confirmed stage</dt><dd>' + esc(d.last_confirmed_stage || 'none') + '</dd>' +
    '<dt>Supplied identifier</dt><dd><code>' + esc(inp.identifier || '') + '</code></dd>' +
    '<dt>Identifier type</dt><dd>' + esc(inp.identifier_type || 'unknown') + '</dd>' +
    '<dt>Supported path</dt><dd>' + esc(d.supported_path || 'unknown') + '</dd>' +
    '<dt>Investigation</dt><dd><code>' + esc(d.investigation_id) + '</code></dd>' +
    '<dt>Observed at</dt><dd>' + esc(d.created_at) + '</dd>' +
    '</div>';
  summary += '<p>' + esc(d.summary) + '</p>';
  html += panel('Result', summary);

  const assurance = d.settlement_assurance;
  if (assurance) {
    const aRows = (assurance.stages || []).map(s =>
      '<tr class="stage-row"><td>' + esc(s.name) + '</td><td>' + pill(s.state) +
      '</td><td>' + (s.confirmed ? 'yes' : 'no') + '</td><td>' + esc(s.detail) + '</td></tr>'
    ).join('');
    let aHtml = '<div class="kv">' +
      '<dt>Assurance level</dt><dd class="outcome">' + esc(assurance.level) + '</dd>' +
      '<dt>Independently verified</dt><dd>' + (assurance.independently_verified ? 'yes' : 'no') + '</dd>' +
      '<dt>Provider claimed success</dt><dd>' + (assurance.provider_claimed_success ? 'yes' : 'no') + '</dd>' +
      (assurance.partial_settlement ? '<dt>Partial settlement</dt><dd>yes</dd>' : '') +
      '</div>';
    aHtml += '<p>' + esc(assurance.summary) + '</p>';
    aHtml += '<table><thead><tr><th>Settlement stage</th><th>State</th><th>Confirmed</th>' +
      '<th>Detail</th></tr></thead><tbody>' + aRows + '</tbody></table>';
    if ((assurance.limitations || []).length) {
      aHtml += '<ul>';
      assurance.limitations.forEach(l => { aHtml += '<li>' + esc(l) + '</li>'; });
      aHtml += '</ul>';
    }
    html += panel('Settlement assurance', aHtml);
  }

  let stageRows = '<table><thead><tr><th>Stage</th><th>State</th><th>Explanation</th></tr></thead><tbody>';
  stages.forEach(s => {
    stageRows += '<tr class="stage-row"><td>' + esc(s.stage) + '</td><td>' + pill(s.state) +
      '</td><td>' + esc(s.summary) + '</td></tr>';
  });
  stageRows += '</tbody></table>';
  html += panel('Stages', stageRows);

  if ((d.contradictions || []).length) {
    let items = '<ul>';
    d.contradictions.forEach(c => {
      items += '<li>' + esc(c.description) + ' <span class="tag">(' +
        esc((c.evidence_ids || []).join(', ')) + ')</span></li>';
    });
    items += '</ul>';
    html += panel('Contradictions', items);
  }

  if ((d.outstanding_questions || []).length) {
    let items = '<ul>';
    d.outstanding_questions.forEach(q => { items += '<li>' + esc(q) + '</li>'; });
    items += '</ul>';
    html += panel('Outstanding questions', items);
  }

  const sources = d.sources || [];
  if (sources.length) {
    let rows = '<table><thead><tr><th>Source</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
    sources.forEach(s => {
      rows += '<tr><td>' + esc(s.source) + '</td><td>' + pill(s.status) + '</td><td>' +
        esc(s.message || '') + '</td></tr>';
    });
    rows += '</tbody></table>';
    html += panel('Source availability', rows);
  }

  const evidence = (d.evidence || []).slice().sort((a, b) =>
    String(a.timestamp || '').localeCompare(String(b.timestamp || '')) || a.id.localeCompare(b.id));
  if (evidence.length) {
    let rows = '<table><thead><tr><th>Stage</th><th>Event</th><th>Source</th><th>Class</th>' +
      '<th>Method</th><th>Hash</th><th class="col-secondary">Timestamp</th>' +
      '<th>Record</th></tr></thead><tbody>';
    evidence.forEach(e => {
      const link = e.evidence_url
        ? '<a href="' + esc(e.evidence_url) + '" target="_blank" rel="noopener noreferrer">open</a>'
        : '<span class="tag">none</span>';
      rows += '<tr><td>' + esc(e.stage) + '</td><td>' + esc(e.event_type) + '</td><td>' +
        esc(e.source) + '</td><td>' + pill(e.verification) + '</td><td>' +
        esc(e.verification_method || '') + '</td><td><code>' +
        esc(e.tx_hash || '') + '</code></td><td class="col-secondary">' +
        esc(e.timestamp || '') + '</td><td>' + link +
        '</td></tr>';
    });
    rows += '</tbody></table>';
    html += panel('Evidence (chronological)', rows);
  }

  if ((d.notes || []).length) {
    let items = '<ul>';
    d.notes.forEach(n => { items += '<li>' + esc(n) + '</li>'; });
    items += '</ul>';
    html += panel('Notes and limitations', items);
  }

  if ((d.known_limitations || []).length) {
    let items = '<ul>';
    d.known_limitations.forEach(n => { items += '<li>' + esc(n) + '</li>'; });
    items += '</ul>';
    html += panel('Tool limitations', items);
  }

  html += '<div class="actions">' +
    '<button type="button" id="copy">Copy JSON report</button>' +
    '<button type="button" id="download">Download JSON</button>' +
    '<button type="button" id="downloadmd">Download Markdown</button>' +
    '</div>';

  out.innerHTML = html;

  document.getElementById('copy').onclick = async () => {
    try { await navigator.clipboard.writeText(window.__report.json); } catch (e) {}
  };
  document.getElementById('download').onclick = () => {
    download(window.__report.json, 'tracesettle-' + window.__report.data.investigation_id + '.json',
      'application/json');
  };
  document.getElementById('downloadmd').onclick = () => {
    download(window.__report.markdown, 'tracesettle-' + window.__report.data.investigation_id + '.md',
      'text/markdown');
  };
}

function download(text, filename, mime) {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const identifier = input.value.trim();
  if (!identifier) { return; }
  out.innerHTML = '<div class="panel">Investigating <code>' + esc(identifier) +
    '</code>&hellip;</div>';
  submit.disabled = true;
  try {
    const res = await fetch('api/investigate?format=full', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier }),
    });
    const body = await res.json();
    if (!res.ok) {
      out.innerHTML = '<div class="error">' + esc(body.error || ('HTTP ' + res.status)) + '</div>';
      return;
    }
    window.__report = body;
    render(body.data);
  } catch (err) {
    out.innerHTML = '<div class="error">Request failed: ' + esc(err.message) + '</div>';
  } finally {
    submit.disabled = false;
  }
});
</script>
</body>
</html>
"""


def _classify_override(identifier: str) -> IdentifierType | None:
    """Never force a type; let the classifier decide. Kept explicit for clarity."""
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        """A non-identifying server token.

        The default leaks the package version and the exact Python build. Neither
        helps a client and both help an attacker fingerprint the deployment, so
        the header states the product name and nothing else.
        """
        return "TRACESETTLE"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Never log the full request line: identifiers are user data. Never log
        # headers either: the API key travels in one. ``command`` is absent when a
        # connection closes before a request line is read (idle or overloaded).
        log.info("request handled: %s", getattr(self, "command", None) or "-")

    # -- helpers ------------------------------------------------------------

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
        csp: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # An error response may be sent before the request body is read (auth,
        # rate limit, size, format). Keeping the connection alive would leave the
        # unread body bytes to be parsed as the next request, so errors always
        # close the connection. ``Connection: close`` sets close_connection, so
        # the handler tears the socket down after this response.
        if status >= 400:
            self.send_header("Connection", "close")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Security-Policy", csp or DEFAULT_CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
            extra_headers,
        )

    def _authorized(self) -> bool:
        """Whether the request carries the configured API key.

        When no key is configured the endpoint is open (local, loopback-only use).
        The comparison is constant-time so the check does not leak the key length
        or content through timing. The key is never logged or echoed back.
        """
        expected = config.API_KEY
        if expected is None:
            return True
        provided = self.headers.get("X-API-Key") or ""
        return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))

    def _serve_static(self, path: str) -> None:
        """Serve a bundled static asset from the package directory.

        The path is resolved through a fixed allowlist (:data:`_STATIC_FILES`), so
        no request string is ever joined onto a filesystem path; a traversal
        attempt simply misses the allowlist and 404s. A missing file is a 404, not
        a 500: the asset is optional and its absence must not break the console.
        """
        filename, content_type = _STATIC_FILES[path]
        asset = pathlib.Path(__file__).resolve().parent / "static" / filename
        try:
            body = asset.read_bytes()
        except OSError:
            self._json(404, {"error": "not found"})
            return
        self._send(200, body, content_type, csp=CONSOLE_CSP)

    def _guard_allowed(self) -> bool:
        """Per-client rate limit and API-key check shared by every guard route.

        Returns True when the request may proceed. On refusal it has already sent
        the response and the caller must return immediately.
        """
        client_ip = self.client_address[0] if self.client_address else "unknown"
        limiter = self.server.guard_limiter  # type: ignore[attr-defined]
        if not limiter.allow(client_ip):
            retry_after = limiter.retry_after_seconds(client_ip)
            self._json(
                429,
                {"error": "rate limit exceeded; retry later"},
                {"Retry-After": str(retry_after)},
            )
            return False
        if not self._authorized():
            self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate": "X-API-Key"})
            return False
        return True

    def _authenticate_service(self) -> str | None:
        """Resolve the caller's service identity from its credential.

        Returns the authenticated ``service_id`` when a registry is configured,
        or ``None`` when service authentication is disabled (loopback default).
        On refusal it has already sent the response and returns
        :data:`_AUTH_REFUSED`.

        The identity comes **only** from the credential; the request body is
        never consulted here. The API layer compares the declared identity
        against this value, so a caller cannot adopt another service's identity
        by editing a field. The credential is never logged or echoed.
        """
        registry = getattr(self.server, "service_registry", None)  # type: ignore[attr-defined]
        if registry is None or not registry.enabled():
            return None
        presented = self.headers.get(CREDENTIAL_HEADER)
        result = registry.authenticate(presented)
        if not result.ok:
            # Generic message: never say which check failed, never echo the
            # credential, never reveal whether it was known.
            self._json(
                401,
                {"error": "service authentication failed"},
                {"WWW-Authenticate": CREDENTIAL_HEADER},
            )
            return _AUTH_REFUSED
        return result.service_id

    def _handle_guard_post(self, parsed: Any, path: str) -> None:
        """Serve a guard write endpoint: rate limit, authenticate, then dispatch."""
        if not self._guard_allowed():
            return
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"error": "invalid Content-Length"})
            return
        if length <= 0 or length > config.GUARD_MAX_BODY_BYTES:
            self._json(413, {"error": "request body missing or too large"})
            return
        try:
            raw = self.rfile.read(length)
        except (TimeoutError, OSError):
            self._json(408, {"error": "request body read timed out"})
            return
        try:
            body = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "request body must be valid JSON"})
            return
        # Bind the request to the caller's authenticated service identity before
        # it is evaluated. Only the service-facing operations carry a service
        # identity; the administrative routes (incident status) are gated by the
        # API key alone, keeping the two authentication planes separate.
        authenticated: str | None = None
        if path in _SERVICE_OPERATION_PATHS or path.startswith("/api/guard/near/lifecycle/"):
            authenticated = self._authenticate_service()
            if authenticated is _AUTH_REFUSED:
                return
        response = self.server.guard_api.dispatch(  # type: ignore[attr-defined]
            "POST", path, params, body, authenticated_service_id=authenticated
        )
        self._json(response.status, response.payload, response.headers)

    # -- routes -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = _INDEX_HTML.replace("__VERSION__", __version__).replace(
                "__DISCLAIMER__", DISCLAIMER
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path in ("/console", "/console/"):
            html = CONSOLE_HTML.replace("__VERSION__", __version__).replace(
                "__DISCLAIMER__", DISCLAIMER
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", csp=CONSOLE_CSP)
        elif path in _STATIC_FILES:
            self._serve_static(path)
        elif path == "/api/health":
            self._json(200, {"status": "ok", "tool": "TRACESETTLE", "version": __version__, "read_only": True})
        elif path.startswith("/api/guard/"):
            # Guard reads expose operational state, not user data, but they are
            # still gated by the same API key as the investigate endpoint when
            # one is configured, and carry their own per-client rate limit.
            if not self._guard_allowed():
                return
            parsed = urlparse(self.path)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            response = self.server.guard_api.dispatch("GET", path, params, None)  # type: ignore[attr-defined]
            self._json(response.status, response.payload, response.headers)
        else:
            self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/guard/"):
            self._handle_guard_post(parsed, path)
            return
        if path != "/api/investigate":
            self._json(404, {"error": "not found"})
            return

        # Per-client-IP rate limit, applied before authentication so that a
        # brute-force attempt against the API key is throttled too. The key is
        # the socket peer address, which the client cannot spoof over TCP; a
        # forwarded-for header is deliberately not trusted, so the limit cannot
        # be bypassed by adding one.
        client_ip = self.client_address[0] if self.client_address else "unknown"
        limiter = self.server.client_limiter  # type: ignore[attr-defined]
        if not limiter.allow(client_ip):
            retry_after = limiter.retry_after_seconds(client_ip)
            self._json(
                429,
                {"error": "rate limit exceeded; retry later"},
                {"Retry-After": str(retry_after)},
            )
            return

        if not self._authorized():
            # Generic message; never echo the key, the expected value, or a
            # prefix of either.
            self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate": "X-API-Key"})
            return

        fmt = (parse_qs(parsed.query).get("format", ["default"])[0] or "default").lower()
        if fmt not in _VALID_FORMATS:
            self._json(400, {"error": f"unknown format; expected one of {sorted(_VALID_FORMATS)}"})
            return

        # Bound the body *before* reading a single byte, so an oversized or
        # mis-declared request cannot make the server allocate or block.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"error": "invalid Content-Length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "request body missing or too large"})
            return

        try:
            raw = self.rfile.read(length)
        except (TimeoutError, OSError):
            # A slow or stalled client; the socket read timeout fired.
            self._json(408, {"error": "request body read timed out"})
            return

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "request body must be valid JSON"})
            return

        if not isinstance(payload, dict):
            self._json(400, {"error": "request body must be a JSON object"})
            return

        identifier = payload.get("identifier")
        if not isinstance(identifier, str):
            self._json(400, {"error": "field 'identifier' must be a string"})
            return
        identifier = identifier.strip()
        if not identifier:
            self._json(400, {"error": "field 'identifier' must not be empty"})
            return
        if len(identifier) > MAX_IDENTIFIER_CHARS:
            self._json(400, {"error": f"identifier exceeds {MAX_IDENTIFIER_CHARS} characters"})
            return
        # Reject control characters outright.
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in identifier):
            self._json(400, {"error": "identifier contains control characters"})
            return

        try:
            report = self._run_investigation(identifier)
        except Exception:  # noqa: BLE001 - never leak internals to the client
            log.exception("investigation failed")
            self._json(502, {"error": "investigation failed; see server logs"})
            return

        self._json(200, self._render_report(report, fmt))

    @staticmethod
    def _render_report(report: Any, fmt: str) -> dict[str, Any]:
        """Serialise the report in the requested format.

        The default returns the structured ``data`` only; the pretty JSON and
        Markdown documents are available on request. ``full`` preserves the
        earlier behaviour of returning all three, so existing clients keep working.
        """
        if fmt == "json":
            return {"json": report.to_json()}
        if fmt == "markdown":
            return {"markdown": report.to_markdown()}
        data = report.to_dict()
        if fmt == "full":
            return {"data": data, "json": report.to_json(), "markdown": report.to_markdown()}
        return {"data": data}

    # -- investigation ------------------------------------------------------

    def _run_investigation(self, identifier: str):
        server = self.server  # type: ignore[attr-defined]
        client = HttpClient(
            timeout=server.timeout_seconds,
            max_attempts=server.max_attempts,
            cache=server.upstream_cache,
            host_limiter=server.host_limiter,
        )
        inv = investigate(identifier, client)
        result = build_result(inv)
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        report = build_report(inv, result, created_at)
        # Persist the report when durability is configured. A configured store
        # that cannot record the conclusion is a hard failure: the operator asked
        # for a retrievable history, so a silent drop would be a false promise.
        store = getattr(server, "investigation_store", None)
        if store is not None:
            store.save(report.to_dict())
        return report


def _build_guard_service() -> GuardService:
    """Build the guard from configuration.

    A configured policy file, audit-log path, or durable-state database that
    cannot be read is a hard failure: a security control must not silently fall
    back to a weaker default. When a state database is configured, the replay
    store and the revocation store are backed by it, so spent nonces and
    revocations survive a restart.
    """
    from .guard.audit import AuditLog
    from .guard.authorization import AuthorizationAuthority
    from .guard.policy import DEFAULT_POLICY, load_policy
    from .guard.safeguards import open_safeguard_store
    from .guard.state import DurableReplayStore, DurableRevocationStore, open_state_store

    if config.GUARD_POLICY_PATH:
        policy = load_policy(config.GUARD_POLICY_PATH)
    else:
        policy = DEFAULT_POLICY
    audit = AuditLog(
        path=config.GUARD_AUDIT_LOG_PATH,
        max_records=config.GUARD_AUDIT_MAX_RECORDS,
    )
    # The learning loop's durable store. Unset means the loop is inert; a
    # configured path that cannot be opened raises here, so start-up fails rather
    # than running with learning silently disabled.
    safeguard_store = open_safeguard_store(
        config.GUARD_SAFEGUARD_DB,
        busy_timeout_ms=config.GUARD_SAFEGUARD_BUSY_TIMEOUT_MS,
    )
    state_store = open_state_store(
        config.GUARD_STATE_DB,
        backend=config.GUARD_STATE_BACKEND,
        busy_timeout_ms=config.GUARD_STATE_BUSY_TIMEOUT_MS,
        pg_dsn=config.GUARD_STATE_PG_DSN,
        pg_connect_timeout_s=config.GUARD_STATE_PG_CONNECT_TIMEOUT_S,
        pg_statement_timeout_ms=config.GUARD_STATE_PG_STATEMENT_TIMEOUT_MS,
        require_postgres=config.GUARD_REQUIRE_POSTGRES,
    )
    if state_store is None:
        return GuardService(policy=policy, audit=audit, safeguard_store=safeguard_store)
    authority = AuthorizationAuthority(
        replay_store=DurableReplayStore(
            state_store, counter_retention_seconds=config.GUARD_STATE_RETENTION_SECONDS
        ),
        revocations=DurableRevocationStore(state_store),
        ttl_seconds=policy.authorization_ttl_seconds,
    )
    return GuardService(
        policy=policy,
        audit=audit,
        authority=authority,
        state_store=state_store,
        safeguard_store=safeguard_store,
    )


def _build_lifecycle(guard_service: GuardService, *, upstream_cache: TtlCache | None = None) -> Any:
    """Build the NEAR Intents lifecycle, or ``None`` when it is not enabled.

    The lifecycle can issue a live (fundable) quote, so it is an explicit
    operator decision: it is built only when ``TRACESETTLE_NEAR_LIFECYCLE`` is
    on. It needs a durable store; when ``TRACESETTLE_INTENTS_DB`` is unset it
    falls back to an in-process store so the loopback demo works, and that
    fallback is reported honestly by the settings endpoint.

    A configured database that cannot be opened is a hard failure: a security
    record must not silently fall back to a weaker default.
    """
    if not config.NEAR_LIFECYCLE_ENABLED:
        return None
    from .intents_store import IntentStore
    from .near.lifecycle import NearIntentsLifecycle

    if config.INTENTS_DB:
        store = IntentStore(config.INTENTS_DB)
    else:
        import tempfile

        store = IntentStore(os.path.join(tempfile.mkdtemp(prefix="tracesettle-intents-"), "intents.db"))
    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
        cache=upstream_cache,
    )
    return NearIntentsLifecycle(guard_service=guard_service, http_client=client, store=store)


def _build_near_execution(guard_service: GuardService) -> Any:
    """Build the NEAR execution boundary, or ``None`` when it is not enabled.

    The boundary can broadcast a real transaction, so it is an explicit operator
    decision (``TRACESETTLE_NEAR_EXECUTION=1``), never a public-bind default. The
    network is resolved server-side (testnet by default) and its genesis hash is
    verified against the RPC before any transaction is built, so a mainnet
    endpoint answering while the code believes it is on testnet is a hard error.

    The boundary holds no key: it builds the transaction, accepts a wallet
    signature, and broadcasts. A misconfigured network name is a hard failure at
    start-up, not a silent fallback.
    """
    if not config.NEAR_EXECUTION_ENABLED:
        return None
    from .near.execution import NearExecutionBoundary
    from .near.networks import NetworkError, network_config
    from .near.rpc import NearRpc

    try:
        net_config = network_config(config.NEAR_EXECUTION_NETWORK)
    except NetworkError as exc:
        raise RuntimeError(f"TRACESETTLE_NEAR_EXECUTION_NETWORK: {exc}") from exc
    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )
    return NearExecutionBoundary(guard_service, net_config, rpc=NearRpc(net_config, client=client))


def _build_tee_provider() -> Any:
    """Build the real TEE attestation provider, or ``None`` when it is not enabled.

    The provider fetches a genuine Intel TDX quote from the NEAR AI Cloud gateway
    and verifies it locally against the pinned Intel SGX Root CA. It is an explicit
    operator decision (``TRACESETTLE_TEE_ATTESTATION=1``) because it makes an
    outbound request; when it is disabled no TEE protection is claimed anywhere.
    """
    if not config.TEE_ATTESTATION_ENABLED:
        return None
    from .near.attestation import TeeAttestationProvider

    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )
    return TeeAttestationProvider(url=config.TEE_ATTESTATION_URL, client=client)


def _build_investigation_store() -> Any:
    """Build the durable investigations store, or ``None`` when unconfigured.

    A configured database that cannot be opened is a hard failure: a recorded
    conclusion must not silently fail to persist. Unset means investigations are
    returned but not stored, which is the loopback default.
    """
    if not config.INVESTIGATIONS_DB:
        return None
    from .investigation_store import InvestigationStore

    return InvestigationStore(config.INVESTIGATIONS_DB)


def _load_service_registry() -> Any:
    """Build the per-service credential registry from configuration, or ``None``.

    A configured store that cannot be read or parsed raises here, so the server
    refuses to start rather than run without the authentication it was told to
    enforce.
    """
    return config.load_service_registry()


class InvestigationServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = config.REQUEST_QUEUE_SIZE

    def __init__(
        self,
        address: tuple[str, int],
        timeout_seconds: float = 15.0,
        max_attempts: int = 3,
        *,
        max_concurrency: int | None = None,
        client_socket_timeout: float | None = None,
        client_limiter: TokenBucketLimiter | None = None,
        host_limiter: TokenBucketLimiter | None = None,
        upstream_cache: TtlCache | None = None,
        guard_service: GuardService | None = None,
        guard_limiter: TokenBucketLimiter | None = None,
        lifecycle: Any = _UNSET,
        service_registry: Any = _UNSET,
        investigation_store: Any = _UNSET,
    ):
        super().__init__(address, Handler)
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.client_socket_timeout = (
            config.CLIENT_SOCKET_TIMEOUT_SECONDS
            if client_socket_timeout is None
            else client_socket_timeout
        )
        cap = config.MAX_CONCURRENT_REQUESTS if max_concurrency is None else max_concurrency
        # A hard cap on concurrently served connections. Threads that cannot get a
        # slot are rejected with 503 rather than queued, so a slow client cannot
        # exhaust memory or file descriptors.
        self._semaphore = threading.BoundedSemaphore(max(1, cap))
        self.client_limiter = client_limiter or TokenBucketLimiter(
            config.RATE_LIMIT_PER_MINUTE, config.RATE_LIMIT_BURST
        )
        self.host_limiter = host_limiter or TokenBucketLimiter(
            config.HOST_RATE_LIMIT_PER_MINUTE, config.HOST_RATE_LIMIT_BURST
        )
        self.upstream_cache = upstream_cache or TtlCache(
            config.UPSTREAM_CACHE_TTL_SECONDS, max_entries=config.UPSTREAM_CACHE_MAX_ENTRIES
        )
        self.guard_service = guard_service or _build_guard_service()
        self.lifecycle = (
            _build_lifecycle(self.guard_service, upstream_cache=self.upstream_cache)
            if lifecycle is _UNSET
            else lifecycle
        )
        # Durable settlement-investigation history. A configured database that
        # cannot be opened raises in the builder, so the server refuses to start
        # rather than silently fail to persist a recorded conclusion.
        self.investigation_store = (
            _build_investigation_store() if investigation_store is _UNSET else investigation_store
        )
        self.guard_api = GuardAPI(
            self.guard_service,
            lifecycle=self.lifecycle,
            investigation_store=self.investigation_store,
            near_execution=_build_near_execution(self.guard_service),
            tee_provider=_build_tee_provider(),
        )
        self.guard_limiter = guard_limiter or TokenBucketLimiter(
            config.GUARD_RATE_LIMIT_PER_MINUTE, config.GUARD_RATE_LIMIT_BURST
        )
        # Per-service credential registry. When no argument is supplied it is
        # loaded from configuration; an explicit ``None`` disables service
        # authentication (the loopback development default). A configured store
        # that cannot be read raises here, so the server refuses to start rather
        # than run without the authentication it was told to enforce.
        self.service_registry = _load_service_registry() if service_registry is _UNSET else service_registry

    def process_request(self, request: Any, client_address: Any) -> None:
        """Admit a connection or refuse it *before* a worker thread is created.

        ``ThreadingMixIn`` spawns one thread per accepted connection, so refusing
        overload inside the thread would still let a flood create unbounded
        threads. The slot is taken here, in the single accepting thread, and
        released by the worker in :meth:`process_request_thread`.
        """
        if not self._semaphore.acquire(blocking=False):
            _reject_overloaded(request)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            # The thread could not be started; return the slot rather than leak it.
            self._semaphore.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        """Serve one connection, bounded by the concurrency cap and a read timeout.

        The slot was taken in :meth:`process_request`; it is released in a
        ``finally`` so it is returned on *every* path: success, client error,
        timeout, or an unexpected exception inside the handler.
        """
        try:
            request.settimeout(self.client_socket_timeout)
            super().process_request_thread(request, client_address)
        finally:
            self._semaphore.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Keep connection-level noise out of the log.

        A client that disconnects mid-response (a broken pipe or reset) is normal
        and not worth a traceback; logging it on every such event is also a cheap
        log-flooding vector. Anything genuinely unexpected is logged once, at
        error level, without the traceback unless debug logging is on.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            log.debug("client disconnected before the response completed")
            return
        log.error("unhandled error while serving a request")
        log.debug("request error detail", exc_info=True)


def _reject_overloaded(request: Any) -> None:
    """Best-effort 503 to a client we are refusing to serve.

    This runs in the accept loop, so it must never block: it sends the response,
    half-closes, and drains only bytes that have already arrived. Draining avoids
    the kernel sending RST (which would discard the response we just wrote)
    because a socket closed with unread inbound data is reset rather than
    finished. A client that has not sent anything yet gets a reset, which is an
    acceptable rejection and, crucially, cannot stall acceptance.
    """
    body = b'{"error":"server busy; retry later"}'
    try:
        request.sendall(
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            b"Retry-After: 1\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        request.setblocking(False)
        try:
            while request.recv(4096):
                pass
        except (BlockingIOError, OSError):
            pass
    except OSError:
        pass


def serve(host: str = "127.0.0.1", port: int = 8000, timeout_seconds: float = 15.0, max_attempts: int = 3) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Fail closed *before* a socket is opened: a public binding with authentication
    # disabled must refuse to start rather than expose protected endpoints.
    from .securityconfig import ConfigurationError, validate_from_config

    try:
        profile = validate_from_config(host)
    except ConfigurationError as exc:
        log.error("refusing to start: %s", exc)
        raise SystemExit(2) from exc
    log.info("deployment profile: %s", profile.describe())

    try:
        server = InvestigationServer(
            (host, port), timeout_seconds=timeout_seconds, max_attempts=max_attempts
        )
    except (RuntimeError, ValueError) as exc:
        # A configured security control (e.g. a credential store) that cannot be
        # loaded must stop the process, never silently degrade to "no auth".
        log.error("refusing to start: %s", exc)
        raise SystemExit(2) from exc

    # A process that is PID 1 (as it is inside a container) gets no default action
    # for SIGTERM, so without a handler a ``docker stop`` would hang until the
    # runtime SIGKILLs it. Stop the loop cleanly instead. The handler runs in the
    # main thread, which is the thread executing ``serve_forever``; calling
    # ``server.shutdown()`` from there would deadlock (it waits for that loop to
    # exit), so the handler asks a short-lived helper thread to do it.
    def _request_shutdown(signum: int, _frame: Any) -> None:
        log.info("received signal %d; shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    previous: dict[int, Any] = {}
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, _request_shutdown)
    except ValueError:
        # Not in the main thread (e.g. embedded in a test harness); leave the
        # default handling in place rather than failing to serve.
        previous = {}

    log.info("TRACESETTLE serving on http://%s:%d (read-only)", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # Belt-and-suspenders: the SIGINT handler above normally prevents this.
        pass
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, TypeError):
                pass
        server.server_close()
