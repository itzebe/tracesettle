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

import json
import logging
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from . import DISCLAIMER, __version__
from .httpclient import HttpClient
from .investigation import build_result, investigate
from .model import IdentifierType
from .report import build_report

log = logging.getLogger("tracesettle.ui")

MAX_BODY_BYTES = 8 * 1024
MAX_IDENTIFIER_CHARS = 128

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
    th:nth-child(6), td:nth-child(6) { display: none; }
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
<footer>TRACESETTLE never signs, submits, or moves anything. Evidence is attributed to its source.</footer>
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

  let summary = '<div class="kv">' +
    '<dt>Outcome</dt><dd class="outcome">' + esc(d.outcome) + '</dd>' +
    '<dt>Last confirmed stage</dt><dd>' + esc(d.last_confirmed_stage || 'none') + '</dd>' +
    '<dt>Investigation</dt><dd><code>' + esc(d.investigation_id) + '</code></dd>' +
    '<dt>Observed at</dt><dd>' + esc(d.created_at) + '</dd>' +
    '</div>';
  summary += '<p>' + esc(d.summary) + '</p>';
  html += panel('Result', summary);

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
      '<th>Hash</th><th>Timestamp</th><th>Record</th></tr></thead><tbody>';
    evidence.forEach(e => {
      const link = e.evidence_url
        ? '<a href="' + esc(e.evidence_url) + '" target="_blank" rel="noopener noreferrer">open</a>'
        : '<span class="tag">none</span>';
      rows += '<tr><td>' + esc(e.stage) + '</td><td>' + esc(e.event_type) + '</td><td>' +
        esc(e.source) + '</td><td>' + pill(e.verification) + '</td><td><code>' +
        esc(e.tx_hash || '') + '</code></td><td>' + esc(e.timestamp || '') + '</td><td>' + link +
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
    const res = await fetch('api/investigate', {
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
    server_version = f"TRACESETTLE/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Never log the full request line: identifiers are user data.
        log.info("request handled: %s", self.command)

    # -- helpers ------------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    # -- routes -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = _INDEX_HTML.replace("__VERSION__", __version__).replace(
                "__DISCLAIMER__", DISCLAIMER
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/health":
            self._json(200, {"status": "ok", "tool": "TRACESETTLE", "version": __version__, "read_only": True})
        else:
            self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/investigate":
            self._json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"error": "invalid Content-Length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "request body missing or too large"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
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

        self._json(
            200,
            {
                "data": report.to_dict(),
                "json": report.to_json(),
                "markdown": report.to_markdown(),
            },
        )

    # -- investigation ------------------------------------------------------

    def _run_investigation(self, identifier: str):
        client = HttpClient(timeout=self.server.timeout_seconds, max_attempts=self.server.max_attempts)  # type: ignore[attr-defined]
        inv = investigate(identifier, client)
        result = build_result(inv)
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return build_report(inv, result, created_at)


class InvestigationServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], timeout_seconds: float = 15.0, max_attempts: int = 3):
        super().__init__(address, Handler)
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts


def serve(host: str = "127.0.0.1", port: int = 8000, timeout_seconds: float = 15.0, max_attempts: int = 3) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = InvestigationServer((host, port), timeout_seconds=timeout_seconds, max_attempts=max_attempts)
    log.info("TRACESETTLE serving on http://%s:%d (read-only)", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
