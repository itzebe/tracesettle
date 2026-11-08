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
from .agentapi import AgentAPI
from .cache import TtlCache
from .guard.api import SERVICE_FACING_POST_PATHS, GuardAPI
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

#: The **only** guard GET routes that may be served without the API key when
#: ``TRACESETTLE_PUBLIC_DEMO`` is enabled. Every entry is self-contained,
#: read-only, and deterministic, and the list is an exact-match allowlist: a
#: route that is not named here keeps the API-key requirement, so enabling the
#: demonstration cannot widen the surface by accident.
#:
#: Deliberately **absent** (and therefore still key-gated): ``/api/guard/policy``,
#: ``/api/guard/metrics``, ``/api/guard/incidents``, ``/api/guard/audit``,
#: ``/api/guard/invariants``, ``/api/guard/safeguards``, the investigations
#: routes, the Intents lifecycle, the wallet and execution routes, the enclave
#: and TEE attestation routes, ``/api/investigate``, and every POST route.
PUBLIC_DEMO_ROUTES = frozenset(
    {
        "/api/guard/scenarios",
        "/api/guard/judge/scenarios",
        "/api/guard/near/agent-demo",
        "/api/guard/near/policy-scope",
        "/api/guard/near/behaviours",
        "/api/guard/near/prompt-injection",
        "/api/guard/near/settlement-check",
    }
)

#: The agent-facing sandbox integration routes. Keyless (when the public
#: demonstration is enabled) but gated by a short-lived sandbox credential, so an
#: independent judge can connect an agent without the operator's API key. Kept
#: separate from :data:`PUBLIC_DEMO_ROUTES` so the guard-route invariant that
#: asserts the keyless guard routes are read-only keeps its exact meaning.
AGENT_ROUTES = frozenset(
    {
        "/api/agent/connect",
        "/api/agent/evaluate",
        "/api/agent/execute",
        "/api/agent/approval",
        "/api/agent/evidence",
        "/api/agent/revoke",
        "/api/agent/settlement",
        "/api/agent/config",
        "/api/agent/openapi.json",
    }
)

#: Sentinel returned by :meth:`Handler._authenticate_service` when it has already
#: sent a refusal. Distinct from ``None``, which means "authentication disabled".
_AUTH_REFUSED = object()

#: The guard POST routes that carry a service identity and therefore require
#: per-service authentication when a credential registry is configured.
#:
#: The set lives in :mod:`tracesettle.guard.api` as
#: :data:`~tracesettle.guard.api.SERVICE_FACING_POST_PATHS`, next to the routing
#: that consumes the authenticated identity, so the gate and the routes cannot
#: drift apart. The lifecycle sub-routes (``/lifecycle/<id>``) are matched by
#: prefix below.
_SERVICE_OPERATION_PATHS = SERVICE_FACING_POST_PATHS

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
<title>TRACESETTLE — Security infrastructure for autonomous payments</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0e14'/%3E%3Cpath d='M9 11h14M16 11v11' stroke='%236ea8fe' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
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
  header .wrap { max-width: 1100px; margin: 0 auto; display: flex; gap: 12px;
    align-items: flex-start; flex-wrap: wrap; }
  header nav { margin-left: auto; display: flex; gap: 6px; font-size: 13px; }
  /* WCAG 2.2 AA 2.5.8: nav targets must be at least 24x24 CSS px. */
  header nav a { display: inline-block; padding: 6px 9px; border-radius: 7px; }
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
  /* WCAG 2.2 AA 2.5.8: keep inline footer links at a 24x24 CSS px target. */
  footer a { display: inline-block; padding: 5px 8px; border-radius: 6px; }
  .hero { margin-bottom: 20px; }
  .hero-title { margin: 0 0 4px; font-size: 24px; line-height: 1.25; }
  .hero-sub { margin: 0 0 10px; font-size: 16px; color: var(--accent); font-weight: 600; }
  .hero-body { margin: 0; color: var(--muted); font-size: 14px; max-width: 78ch; }
  .caps { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 14px; margin-bottom: 16px; }
  .cap { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; }
  .cap h3 { margin: 0 0 4px; font-size: 16px; }
  .cap-lead { margin: 0 0 10px; color: var(--muted); font-size: 13px; }
  .cap ul { margin: 0; padding-left: 18px; }
  .cap li { margin-bottom: 6px; font-size: 13px; }
  .cap-cta { margin: 12px 0 0; font-size: 13px; font-weight: 600; }
  /* WCAG 2.2 AA target size (2.5.8): a call to action must offer at least a
     24x24 CSS px target. An inline link is only ~15px tall, so the CTAs are
     promoted to inline-blocks with vertical padding. */
  .cap-cta a, .hero a.cta { display: inline-block; padding: 7px 12px; border-radius: 7px;
    border: 1px solid var(--border); background: #21262d; text-decoration: none; }
  .cap-cta a:hover, .hero a.cta:hover { border-color: var(--accent); }
  .demo-cta { background: #1d1a2e; border: 1px solid var(--border); border-left: 3px solid var(--sim);
    border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; }
  .demo-cta h3 { margin: 0 0 6px; font-size: 15px; }
  .demo-cta p { margin: 0; font-size: 13px; color: #d6c9ff; }
  .investigate { border-top: 1px solid var(--border); padding-top: 18px; }
  .investigate h3 { margin: 0 0 12px; font-size: 16px; }
  .skip { position: absolute; left: -999px; top: 0; background: var(--accent); color: #0d1117;
    padding: 8px 12px; border-radius: 0 0 6px 0; z-index: 20; }
  .skip:focus { left: 0; }
  @media (max-width: 640px) {
    h1 { font-size: 17px; }
    .hero-title { font-size: 20px; }
    table { font-size: 12px; }
    .col-secondary { display: none; }
  }
</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header>
  <div class="wrap">
    <div>
      <h1>TRACESETTLE</h1>
      <div class="tag">Security infrastructure for autonomous payments &middot; NEAR &middot; v__VERSION__</div>
    </div>
    <nav aria-label="Site">__SITE_NAV__</nav>
  </div>
</header>
<main id="main">
  <section class="hero">
    <h2 class="hero-title">Stop unauthorized AI payments before they happen.</h2>
    <p class="hero-sub">Verify every settlement afterward.</p>
    <p class="hero-body">TRACESETTLE enforces transaction-level authorization for autonomous
      agents and independently verifies settlement across supported payment infrastructure.
      It evaluates what an agent is about to pay, refuses anything outside policy before a
      signer is reached, and checks the on-chain result rather than trusting a provider's word.</p>
  </section>

  <section class="caps" aria-label="Capabilities">
    <article class="cap">
      <h3>Protect payments</h3>
      <p class="cap-lead">Pre-signing authorization for agents.</p>
      <ul>
        <li>Evaluates the <strong>actual transaction parameters</strong> — recipient, amount,
          network and payload — not the agent's explanation.</li>
        <li>Returns an explicit <strong>ALLOW</strong>, <strong>REQUIRE_APPROVAL</strong>,
          <strong>BLOCK</strong>, <strong>HOLD</strong> or <strong>UNKNOWN</strong> decision.</li>
        <li>Binds any authorization to the <strong>exact bytes</strong> to be signed, so a
          substitution after approval is refused.</li>
        <li>Refuses replay, expiry and reuse; a <strong>BLOCK</strong> never reaches the signer.</li>
      </ul>
      <p class="cap-cta">__GUARD_LINK__</p>
    </article>

    <article class="cap">
      <h3>Investigate settlement</h3>
      <p class="cap-lead">Independent, evidence-backed investigation.</p>
      <ul>
        <li>Traces a NEAR Intents 1Click swap from a <strong>deposit address</strong> or an
          <strong>intent hash</strong>.</li>
        <li>Separates what is <strong>independently verified</strong> from what is merely
          <strong>reported</strong> by an upstream service.</li>
        <li>Surfaces contradictions and missing evidence instead of guessing; never treats a
          provider's <strong>SUCCESS</strong> as proof funds arrived.</li>
        <li>Read-only: it never signs, submits or moves anything, and needs no keys.</li>
      </ul>
      <p class="cap-cta"><a href="#investigate">Investigate a transaction &darr;</a></p>
    </article>
  </section>

  <section class="demo-cta" aria-label="Demonstration">
    <div>
      <h3>See the firewall block a payment</h3>
      <p>A deterministic demonstration runs the real authorization boundary, signer and settlement
        verifier: an agent is manipulated into redirecting a payment, the boundary
        <strong>BLOCK</strong>s it, and the signer is <strong>never invoked</strong> (proven by a
        zero call count). A legitimate payment is then authorized, signed and independently
        verified, and a real NEAR testnet settlement is read live as proof.
        <span class="tag">Two simulated payments; the testnet check is real and read-only.</span></p>
    </div>
    <p class="cap-cta">__DEMO_LINK__</p>
  </section>

  <section id="investigate" class="investigate">
    <h3>Investigate a transaction</h3>
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
  </section>
</main>
<footer>
  <p>This public interface is <strong>read-only</strong>: it never signs, submits or moves funds.
    The authorization firewall protects agent execution through its signer enforcement boundary —
    see the <a href="console">Security Operations Console</a>.</p>
  <p class="tag">Evidence is attributed to its source. Simulated demonstrations are labelled as
    such and never describe a real blockchain transaction.</p>
</footer>
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

#: The public six-scene demonstration. It runs entirely from real endpoints and
#: real code: the authorization boundary, the signer, the settlement verifier,
#: and a live read-only NEAR testnet check. Nothing is hardcoded; every value on
#: the page is read back from a response. Same-origin only (no third-party
#: origin), so it is served under :data:`DEFAULT_CSP`.
_DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACESETTLE — Stop an unauthorized AI payment, then prove the real one</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0e14'/%3E%3Cpath d='M9 11h14M16 11v11' stroke='%236ea8fe' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --fg: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff;
    --ok: #3fb950; --warn: #d29922; --bad: #f85149; --sim: #a371f7;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  a { color: var(--accent); }
  .skip { position: absolute; left: -999px; top: 0; background: var(--accent); color: #0d1117;
    padding: 8px 12px; border-radius: 0 0 6px 0; z-index: 20; }
  .skip:focus { left: 0; }
  header { padding: 18px 16px 14px; border-bottom: 1px solid var(--border); }
  header .wrap { max-width: 1080px; margin: 0 auto; display: flex; gap: 14px;
    align-items: flex-start; flex-wrap: wrap; }
  header nav { margin-left: auto; display: flex; gap: 6px; font-size: 13px; }
  /* WCAG 2.2 AA 2.5.8: nav targets must be at least 24x24 CSS px. */
  header nav a { display: inline-block; padding: 6px 9px; border-radius: 7px; }
  h1 { margin: 0 0 4px; font-size: 19px; letter-spacing: .5px; }
  .tag { color: var(--muted); font-size: 12px; }
  main { max-width: 1080px; margin: 0 auto; padding: 20px 16px 40px; }
  .hero { margin-bottom: 18px; }
  .hero h2 { margin: 0 0 6px; font-size: 26px; line-height: 1.2; }
  .hero .sub { margin: 0 0 10px; font-size: 16px; color: var(--accent); font-weight: 600; }
  .hero p.body { margin: 0; color: var(--muted); font-size: 14px; max-width: 82ch; }
  .flow { display: flex; flex-wrap: wrap; gap: 6px 10px; margin: 16px 0 4px; padding: 0;
    list-style: none; font-size: 12px; }
  .flow li { border: 1px solid var(--border); border-radius: 999px; padding: 4px 10px;
    color: var(--muted); }
  .flow li.hot { border-color: var(--accent); color: var(--fg); }
  .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 18px 0; }
  button { padding: 11px 18px; border-radius: 6px; border: 1px solid var(--border);
    background: #21262d; color: var(--fg); font: inherit; cursor: pointer; }
  button.primary { background: var(--accent); color: #08111f; border-color: var(--accent);
    font-weight: 700; }
  button:hover { border-color: var(--accent); }
  button[disabled] { opacity: .55; cursor: progress; }
  .scenes { display: grid; gap: 14px; }
  .scene { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; }
  .scene[data-state="pending"] { opacity: .62; }
  .scene .eyebrow { font-size: 11px; letter-spacing: .14em; text-transform: uppercase;
    color: var(--muted); margin: 0 0 4px; }
  .scene h3 { margin: 0 0 8px; font-size: 16px; }
  .scene p { margin: 0 0 10px; font-size: 13.5px; color: var(--muted); }
  .scene .verdict { display: inline-flex; align-items: center; gap: 8px; font-weight: 700;
    font-size: 14px; padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border); }
  .v-ALLOW { color: var(--ok); border-color: var(--ok); }
  .v-REQUIRE_APPROVAL { color: var(--warn); border-color: var(--warn); }
  .v-BLOCK { color: var(--bad); border-color: var(--bad); }
  .v-HOLD, .v-UNKNOWN { color: var(--muted); }
  .v-VERIFIED { color: var(--ok); border-color: var(--ok); }
  .v-UNAVAILABLE { color: var(--bad); border-color: var(--bad); }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 3px 14px; font-size: 12.5px;
    margin-top: 8px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; word-break: break-all; }
  .reasons { margin: 8px 0 0; padding-left: 18px; font-size: 12.5px; }
  .note { border-left: 3px solid var(--border); background: #1c2128; border-radius: 6px;
    padding: 9px 12px; font-size: 12.5px; color: var(--muted); margin-top: 10px; }
  .note.sim { border-left-color: var(--sim); color: #d6c9ff; }
  .note.ok { border-left-color: var(--ok); }
  .note.bad { border-left-color: var(--bad); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 8px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border);
    vertical-align: top; word-break: break-word; }
  th { color: var(--muted); font-weight: 600; }
  .ok { color: var(--ok); } .bad { color: var(--bad); }
  code { background: #0b0f14; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .mono { word-break: break-all; }
  footer { color: var(--muted); font-size: 12px; padding: 24px 16px; text-align: center;
    border-top: 1px solid var(--border); }
  /* WCAG 2.2 AA 2.5.8: keep inline footer links at a 24x24 CSS px target. */
  footer a { display: inline-block; padding: 5px 8px; border-radius: 6px; }
  @media (max-width: 640px) {
    .hero h2 { font-size: 21px; }
    .kv { grid-template-columns: 1fr; gap: 1px 0; }
    .kv dt { margin-top: 6px; }
  }
</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header>
  <div class="wrap">
    <div>
      <h1>TRACESETTLE</h1>
      <div class="tag">Security infrastructure for autonomous payments &middot; NEAR &middot; v__VERSION__</div>
    </div>
    <nav aria-label="Site">
      <a href="/">Home</a>
      <a href="/evaluate">Evaluate</a>
      <a href="/JUDGE_GUIDE">Judge guide</a>
      <a href="/console">Console</a>
    </nav>
  </div>
</header>
<main id="main">
  <section class="hero">
    <h2>Stop an unauthorized AI payment &mdash; then prove the real one.</h2>
    <p class="sub">An agent's intention is never payment authorization.</p>
    <p class="body">An AI agent can propose a payment, but a compromised agent, a malicious
      instruction, an altered recipient or a manipulated amount can turn an apparently
      legitimate payment into an unauthorized transfer. TRACESETTLE puts an independent
      security boundary between the agent's payment <em>intent</em> and the wallet that
      <em>signs</em>. The agent does not control the decision, and the user keeps the signing
      authority. This page runs that boundary for real.</p>
    <ol class="flow" aria-label="The enforcement path">
      <li>Agent proposes a payment</li>
      <li class="hot">TRACESETTLE evaluates the transaction</li>
      <li class="hot">Authorization decision</li>
      <li>Wallet signs</li>
      <li>Network executes</li>
      <li>Independent settlement verification</li>
    </ol>
  </section>

  <div class="controls">
    <button class="primary" type="button" id="run">Run the six-scene demonstration</button>
    <span class="tag" id="run-note">Runs the real authorization boundary, signer and
      settlement verifier, plus a live read-only NEAR testnet check.</span>
  </div>

  <div id="output" aria-live="polite"></div>

  <div class="note">
    <strong>What is real here.</strong> The authorization boundary, the guard controls, the
    signer enforcement, the pipeline and the settlement verifier are the production code. The
    only substitution is the network transport for the two simulated payments: no key is held
    and nothing is broadcast to a chain. Scene 6 is a genuine read-only check of an
    already-final NEAR <strong>testnet</strong> transaction. TRACESETTLE never requests a
    private key or seed phrase, never signs on your behalf, and never moves funds.
  </div>
</main>
<footer>
  <p>Read-only and non-custodial. This public demonstration never signs, broadcasts or moves
    funds. The operator console is at <a href="console">/console</a>.</p>
</footer>
<script>
const out = document.getElementById('output');
const runBtn = document.getElementById('run');

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function verdict(v) { return '<span class="verdict v-' + esc(v) + '">' + esc(v) + '</span>'; }
function kv(pairs) {
  return '<dl class="kv">' + pairs.map(function (p) {
    return '<dt>' + esc(p[0]) + '</dt><dd>' + p[1] + '</dd>';
  }).join('') + '</dl>';
}
function scene(n, eyebrow, title, body, state) {
  return '<section class="scene" data-state="' + esc(state || 'pending') + '">' +
    '<p class="eyebrow">Scene ' + n + ' &middot; ' + esc(eyebrow) + '</p>' +
    '<h3>' + esc(title) + '</h3>' + body + '</section>';
}

function placeholder() {
  out.innerHTML = '<div class="scenes">' +
    scene(1, 'the threat', 'An AI agent is manipulated into redirecting a payment',
      '<p>Press <strong>Run the six-scene demonstration</strong> to execute the real boundary.</p>') +
    scene(2, 'the interception', 'TRACESETTLE evaluates the transaction before signing', '') +
    scene(3, 'the decision', 'The unauthorized destination is blocked', '') +
    scene(4, 'the legitimate payment', 'An approved payment passes the checks', '') +
    scene(5, 'the execution', 'The wallet signing boundary', '') +
    scene(6, 'the proof', 'Independent settlement verification', '') +
    '</div>';
}

function render(demo, check) {
  const mal = demo.malicious, leg = demo.legitimate;
  const sc = (check && check.verification) || null;

  let html = '<div class="scenes">';

  html += scene(1, 'the threat', 'An AI agent is manipulated into redirecting a payment',
    '<p>The agent was told to pay an approved supplier. Injected context then redirects the same ' +
      'invoice to an attacker-controlled receiver.</p>' +
    kv([['Agent instruction', '<span class="mono">' + esc(mal.instruction) + '</span>'],
        ['Injected context', '<span class="mono">' + esc(mal.injected_context || '(none)') + '</span>'],
        ['Receiver the agent proposed', '<strong class="mono">' + esc(mal.proposed_receiver) + '</strong>'],
        ['Amount', esc(mal.proposed_amount) + ' NEAR']]), 'done');

  html += scene(2, 'the interception', 'TRACESETTLE evaluates the transaction before signing',
    '<p>The boundary reads the <strong>actual transaction parameters</strong> — recipient, amount, ' +
      'network and asset — never the agent\u2019s explanation. A convincing instruction cannot ' +
      'change the decision.</p>' +
    kv([['Bound service identity', esc((mal.authorization_binding || {}).service_id || '—')],
        ['Chain', esc((mal.authorization_binding || {}).chain || '—')],
        ['Asset', esc((mal.authorization_binding || {}).asset || '—')],
        ['Evaluated destination', '<span class="mono">' + esc(mal.proposed_receiver) + '</span>']]), 'done');

  html += scene(3, 'the decision', 'The unauthorized destination is blocked',
    '<p>The destination is not on the approved list, so the boundary returns ' + verdict(mal.decision) +
      '. No authorization is issued, so the signer is <strong>never invoked</strong> — proven by a ' +
      'call count of <strong>' + esc(String(mal.signer_calls)) + '</strong>, not asserted.</p>' +
    (mal.reasons && mal.reasons.length
      ? '<ul class="reasons">' + mal.reasons.map(function (r) { return '<li>' + esc(r) + '</li>'; }).join('') + '</ul>'
      : '') +
    kv([['Signer invocations', '<strong>' + esc(String(mal.signer_calls)) + '</strong>'],
        ['Signed', esc(String(mal.signed))],
        ['Broadcast', esc(String(mal.broadcast_occurred))]]), 'done');

  html += scene(4, 'the legitimate payment', 'An approved payment passes the checks',
    '<p>The same agent, with no injected context, proposes the operator-approved receiver. The ' +
      'boundary returns ' + verdict(leg.decision) + ' and issues a short-lived authorization bound ' +
      'to the exact bytes to be signed.</p>' +
    kv([['Receiver', '<span class="mono">' + esc(leg.proposed_receiver) + '</span>'],
        ['Amount', esc(leg.proposed_amount) + ' NEAR'],
        ['Authorization digest', '<span class="mono">' + esc((leg.authorization_binding || {}).transaction_digest || '—') + '</span>'],
        ['Digest of signed bytes', '<span class="mono">' + esc(leg.signed_bytes_digest || '—') + '</span>'],
        ['Digests agree', ((leg.authorization_binding || {}).transaction_digest === leg.signed_bytes_digest)
          ? '<span class="ok">yes</span>' : '<span class="bad">no</span>']]), 'done');

  html += scene(5, 'the execution', 'The wallet signing boundary',
    '<p>The signer re-derives the binding from the transaction it was asked to sign. A ' +
      'substitution after approval, a replay, an expired authorization, or a token minted for a ' +
      'different transaction is refused here. The demonstration replaces the network with a ' +
      'deterministic offline transport, so the signer, pipeline and verifier all run for real but ' +
      '<strong>nothing is signed for real and nothing reaches a chain</strong> — which is why this ' +
      'whole run is labelled a simulation.</p>' +
    kv([['Signer invocations', '<strong>' + esc(String(leg.signer_calls)) + '</strong>'],
        ['Signed (real key)', '<span class="ok">no — simulated transport</span>'],
        ['Simulated pipeline state', esc(leg.submission_state || '—')],
        ['Reached a chain', '<span class="ok">no</span>']]), 'done');

  let proofBody = '<p>The provider\u2019s success is never proof. Scene 6 reads a real, ' +
    'already-final NEAR <strong>testnet</strong> transaction from a public RPC and checks it field ' +
    'by field against the operation it was supposed to perform.</p>';
  if (check && check.available && sc) {
    const rows = (sc.checks || []).map(function (c) {
      return '<tr><td>' + esc(c.name) + '</td><td class="' + (c.ok ? 'ok' : 'bad') + '">' +
        (c.ok ? 'pass' : 'fail') + '</td><td class="mono">' + esc(c.detail) + '</td></tr>';
    }).join('');
    proofBody += kv([['Transaction hash', '<span class="mono">' + esc(check.tx_hash) + '</span>'],
        ['Network', esc(check.network) + ' (mainnet: ' + esc(String(check.mainnet)) + ')'],
        ['Verified state', verdict(check.state)],
        ['Read live from', 'a public NEAR testnet RPC'],
        ['Explorer', '<a href="' + esc(check.explorer_url) + '" rel="noopener noreferrer">' +
          esc(check.tx_hash) + '</a>']]) +
      '<table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>' +
      rows + '</tbody></table>' +
      '<div class="note ok">Read live; the transaction was already final before this read. ' +
      'Nothing was signed, broadcast or moved to produce this evidence.</div>';
  } else {
    proofBody += '<div class="note bad">' + esc((check && check.note) ||
      'The public NEAR testnet RPC could not be reached, so no conclusion is drawn.') + '</div>';
  }
  html += scene(6, 'the proof', 'Independent settlement verification', proofBody,
    check && check.available ? 'done' : 'pending');

  html += '</div>';

  html += '<div class="note ' + (demo.reproduced ? 'ok' : 'bad') + '">' +
    esc(demo.reproduced
      ? 'Reproduced: the injected redirect was blocked before signing, the approved payment was ' +
        'authorized and signed, and a real testnet settlement was independently verified.'
      : 'The demonstration did not reproduce the expected outcome.') + '</div>' +
    '<div class="note sim">' + esc(demo.note) + '</div>';

  out.innerHTML = html;
}

async function run() {
  runBtn.disabled = true;
  out.innerHTML = '<div class="note">Running the real boundary, signer and verifier&hellip;</div>';
  try {
    const demoRes = await fetch('api/guard/near/agent-demo');
    const demo = await demoRes.json();
    if (!demoRes.ok) { throw new Error(demo.error || ('HTTP ' + demoRes.status)); }

    let check = null;
    try {
      const checkRes = await fetch('api/guard/near/settlement-check');
      check = await checkRes.json();
      if (!checkRes.ok) { check = null; }
    } catch (e) { check = null; }

    render(demo, check);
  } catch (err) {
    out.innerHTML = '<div class="note bad">' + esc(err.message) + '</div>';
  } finally {
    runBtn.disabled = false;
  }
}

placeholder();
runBtn.addEventListener('click', run);
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

    def _guard_allowed(self, path: str | None = None) -> bool:
        """Per-client rate limit and API-key check shared by every guard route.

        Returns True when the request may proceed. On refusal it has already sent
        the response and the caller must return immediately.

        ``path`` is the exact request path. When the operator has enabled the
        public demonstration and ``path`` is on the read-only allowlist
        (:data:`PUBLIC_DEMO_ROUTES`), the API key is not required; every other
        path keeps the requirement. The rate limit is charged exactly once on
        every path, so a keyless demonstration route can never be used to hammer
        the free upstreams, and a refusal is never written twice.
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
        keyless_demo = (
            config.PUBLIC_DEMO_ENABLED and path is not None and path in PUBLIC_DEMO_ROUTES
        )
        # The agent-facing sandbox routes are also keyless when the demonstration
        # is enabled. They are gated by a short-lived sandbox credential inside
        # :class:`~tracesettle.agentapi.AgentAPI` (or, for ``connect``, by the
        # per-client rate limit charged above). The credential can only ever
        # reach the sandbox policy; it cannot name an operator service or reach a
        # signer without a valid authorization. They are kept out of
        # ``PUBLIC_DEMO_ROUTES`` so the guard-route invariant keeps its exact
        # meaning.
        keyless_agent = (
            config.PUBLIC_DEMO_ENABLED
            and path is not None
            and path in AGENT_ROUTES
        )
        if not keyless_demo and not keyless_agent and not self._authorized():
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

    def _agent_headers(self) -> dict[str, str]:
        return {
            "X-Sandbox-Credential": self.headers.get("X-Sandbox-Credential") or "",
            "X-Approval-Secret": self.headers.get("X-Approval-Secret") or "",
        }

    def _handle_agent_get(self, path: str) -> None:
        """Serve a read-only agent route. Public demo must be enabled."""
        api = getattr(self.server, "agent_api", None)  # type: ignore[attr-defined]
        if api is None:
            self._json(404, {"error": "not found"})
            return
        if not self._guard_allowed(path):
            return
        parsed = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        response = api.get(path, params, self._agent_headers())
        self._json(response.status, response.payload, response.headers)

    def _handle_agent_post(self, parsed: Any, path: str) -> None:
        """Serve a write agent route: rate limit, then dispatch.

        Authentication is by the sandbox credential header, resolved inside the
        API against the durable store, so there is no separate key gate here.
        """
        api = getattr(self.server, "agent_api", None)  # type: ignore[attr-defined]
        if api is None:
            self._json(404, {"error": "not found"})
            return
        if not self._guard_allowed(path):
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"error": "invalid Content-Length"})
            return
        if length > config.GUARD_MAX_BODY_BYTES:
            self._json(413, {"error": "request body too large"})
            return
        body: Any = {}
        if length > 0:
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
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        response = api.post(path, params, body, self._agent_headers())
        self._json(response.status, response.payload, response.headers)

    def _index_page(self) -> bytes:
        """Render the landing page, pointing at whichever demonstration exists.

        When the public demonstration is enabled the primary call to action opens
        the keyless ``/demo`` page; otherwise it opens the operator console's
        attack simulations, so the page never links to a route that would answer
        with an authentication error.
        """
        if config.PUBLIC_DEMO_ENABLED:
            guard_link = '<a href="evaluate">Test TRACESETTLE &rarr;</a>'
            demo_link = '<a href="demo">Run the six-scene demonstration &rarr;</a>'
            site_nav = (
                '<a href="demo">Demo</a>'
                '<a href="evaluate">Evaluate</a>'
                '<a href="evaluate#connect">Connect an agent</a>'
                '<a href="JUDGE_GUIDE">Judge guide</a>'
                '<a href="console">Console</a>'
            )
        else:
            guard_link = '<a href="console#guard">Open the authorization firewall &rarr;</a>'
            demo_link = '<a href="console#lab">Open the demonstration &rarr;</a>'
            site_nav = '<a href="console">Console</a>'
        html = (
            _INDEX_HTML.replace("__VERSION__", __version__)
            .replace("__DISCLAIMER__", DISCLAIMER)
            .replace("__SITE_NAV__", site_nav)
            .replace("__GUARD_LINK__", guard_link)
            .replace("__DEMO_LINK__", demo_link)
        )
        return html.encode("utf-8")

    def _serve_judge_guide(self) -> None:
        """Render ``JUDGE_GUIDE.md`` from the repository root to HTML.

        The file is read from the project root, not from the package, so a
        deployment that ships only the package answers 404 rather than rendering
        a stale or empty page.
        """
        from .markdown import render

        root = pathlib.Path(__file__).resolve().parent.parent
        source = root / "JUDGE_GUIDE.md"
        try:
            text = source.read_text(encoding="utf-8")
        except OSError:
            self._json(404, {"error": "judge guide not available in this deployment"})
            return
        body = render(text)
        from .evaluate import DOC_PAGE

        html = DOC_PAGE.replace("__TITLE__", "Judge guide").replace("__BODY__", body).replace(
            "__VERSION__", __version__
        )
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, self._index_page(), "text/html; charset=utf-8")
        elif path in ("/demo", "/demo/"):
            # The public, keyless six-scene demonstration. It is served only when
            # the operator opted in; otherwise the landing page's link to it is
            # not rendered either, so the two never disagree.
            if not config.PUBLIC_DEMO_ENABLED:
                self._json(404, {"error": "not found"})
                return
            html = _DEMO_HTML.replace("__VERSION__", __version__).replace(
                "__DISCLAIMER__", DISCLAIMER
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path in ("/evaluate", "/evaluate/"):
            # The public, keyless independent-evaluation page. Served only when
            # the operator opted into the public demonstration, so it and /demo
            # are always either both present or both absent.
            if not config.PUBLIC_DEMO_ENABLED:
                self._json(404, {"error": "not found"})
                return
            from .evaluate import EVALUATE_HTML

            html = EVALUATE_HTML.replace("__VERSION__", __version__)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path in ("/JUDGE_GUIDE", "/judge-guide", "/judge-guide/"):
            # The judge guide is one file, rendered at request time, so the copy
            # a judge reads here and the copy in the repository cannot drift.
            if not config.PUBLIC_DEMO_ENABLED:
                self._json(404, {"error": "not found"})
                return
            self._serve_judge_guide()
        elif path in ("/console", "/console/"):
            html = CONSOLE_HTML.replace("__VERSION__", __version__).replace(
                "__DISCLAIMER__", DISCLAIMER
            ).replace(
                "__DEMO_HINT__",
                ' " For a keyless walkthrough, open the public demonstration at /demo."'
                if config.PUBLIC_DEMO_ENABLED
                else ' ""',
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", csp=CONSOLE_CSP)
        elif path in _STATIC_FILES:
            self._serve_static(path)
        elif path == "/api/health":
            self._json(200, {"status": "ok", "tool": "TRACESETTLE", "version": __version__, "read_only": True})
        elif path.startswith("/api/agent/"):
            self._handle_agent_get(path)
        elif path.startswith("/api/guard/"):
            # Guard reads expose operational state, not user data, but they are
            # still gated by the same API key as the investigate endpoint when
            # one is configured, and carry their own per-client rate limit. The
            # only exception is the exact public-demonstration allowlist, served
            # keyless (and rate-limited) when the operator opts in.
            if not self._guard_allowed(path):
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
        if path.startswith("/api/agent/"):
            self._handle_agent_post(parsed, path)
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
        return GuardService(
            policy=policy,
            audit=audit,
            safeguard_store=safeguard_store,
            approval_authority=_build_approval_authority(),
            counterparty_reader=_build_counterparty_reader(),
        )
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
        approval_authority=_build_approval_authority(),
        counterparty_reader=_build_counterparty_reader(),
    )


def _build_agent_api(guard_service: GuardService) -> AgentAPI:
    """Build the agent-facing sandbox integration API.

    It reuses the guard's durable state store (so sandbox credentials survive a
    restart and are shared across instances) and exposes the reference NEAR
    testnet settlement check as its read-only settlement reader. The sandbox
    authority derives per-credential authorization and approval keys from a
    server-side master key that the client never sees.
    """
    from .guard.sandbox import SandboxAuthority

    state_store = getattr(guard_service, "state_store", None)
    authority = SandboxAuthority(state_store)

    def _settlement_reader() -> Any:
        from .near.settlement_check import verify_reference_settlement

        return verify_reference_settlement()

    return AgentAPI(authority, settlement_reader=_settlement_reader)


def _build_approval_authority() -> Any:
    """Build the human-approval authority, or ``None`` when it is not enabled.

    Off by default: with no authority, a REQUIRE_APPROVAL decision can never be
    raised to ALLOW, which is the fail-closed default. When enabled, the key is
    read from ``TRACESETTLE_GUARD_APPROVAL_KEY`` or an ephemeral one is minted
    (and reported as ephemeral). The key never leaves this object.
    """
    if not config.NEAR_APPROVAL_ENABLED:
        return None

    from .near.approval import ApprovalAuthority

    key = _approval_key()
    return ApprovalAuthority(
        key=key,
        key_id="approval",
        ttl_seconds=config.NEAR_APPROVAL_TTL_SECONDS,
    )


def _approval_key() -> bytes:
    """The approval signing key: configured, else a fresh ephemeral key.

    Only the hash of the key id is ever exposed. An ephemeral key is safe for a
    single process (the approval must be validated in the same process that
    minted it); a multi-process deployment must configure
    ``TRACESETTLE_GUARD_APPROVAL_KEY``.
    """
    import hashlib
    import secrets as _secrets

    configured = config.GUARD_APPROVAL_KEY
    if configured:
        try:
            return bytes.fromhex(configured.strip())
        except ValueError:
            return hashlib.sha256(configured.encode("utf-8")).digest()
    return _secrets.token_bytes(32)


def _build_counterparty_reader() -> Any:
    """Build the counterparty intelligence reader, or ``None`` when disabled.

    A configured blocklist that cannot be read or that carries an unevidenced
    entry is a hard failure: a security control must not silently fall back to a
    weaker default. The reader performs only public, keyless RPC reads.
    """
    if not config.NEAR_COUNTERPARTY_ENABLED:
        return None
    from .near.counterparty import Blocklist, CounterpartyIntelligence
    from .near.networks import network_config
    from .near.rpc import NearRpc

    blocklist = None
    if config.NEAR_BLOCKLIST_PATH:
        try:
            blocklist = Blocklist.from_file(config.NEAR_BLOCKLIST_PATH)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"TRACESETTLE_NEAR_BLOCKLIST: {exc}") from exc
    net_config = network_config(config.NEAR_EXECUTION_NETWORK)
    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )
    rpc = NearRpc(net_config, client=client)
    return CounterpartyIntelligence(
        rpc,
        chain=net_config.chain_id,
        blocklist=blocklist,
        min_account_age_blocks=config.NEAR_COUNTERPARTY_MIN_AGE_BLOCKS,
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


def _near_policy_adapter(http_client: Any = None) -> Any:
    """Build the provider-policy adapter from server configuration, or ``None``.

    Shared by the guard API and the NEAR execution boundary so a policy read is
    resolved identically wherever it is enforced: the operator's pinned fixture
    first, then a live Agent API URL. ``None`` means the layer is not configured,
    which the caller reports honestly rather than inventing a policy.
    """
    from .near.policy import adapter_from_config

    return adapter_from_config(config, http_client)


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
    from .near.tee_execution import ExecutionRecordStore, TeeExecutionAuthorizer

    try:
        net_config = network_config(config.NEAR_EXECUTION_NETWORK)
    except NetworkError as exc:
        raise RuntimeError(f"TRACESETTLE_NEAR_EXECUTION_NETWORK: {exc}") from exc
    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )

    # The TEE trust boundary. When attestation is required, the authorizer makes
    # a verified, transaction-bound attestation a precondition of signing; the
    # boundary refuses any transaction that lacks one. A configured record
    # database that cannot be opened is a hard failure, never a silent fallback.
    tee_authorizer = None
    tee_provider = None
    if config.NEAR_TEE_REQUIRED:
        try:
            store = ExecutionRecordStore(config.NEAR_EXECUTION_DB)
        except Exception as exc:  # noqa: BLE001 - a broken store must not start
            raise RuntimeError(f"TRACESETTLE_NEAR_EXECUTION_DB: {exc}") from exc
        tee_authorizer = TeeExecutionAuthorizer(
            store=store,
            require_attestation=True,
            expected_measurement=config.NEAR_TEE_EXPECTED_MEASUREMENT,
            ttl_seconds=config.NEAR_EXECUTION_TTL_SECONDS,
        )
        from .near.attestation import TeeAttestationProvider

        tee_provider = TeeAttestationProvider(
            url=config.TEE_ATTESTATION_URL,
            client=HttpClient(
                timeout=config.REQUEST_TIMEOUT_SECONDS,
                max_attempts=config.MAX_ATTEMPTS,
            ),
        )

    boundary = NearExecutionBoundary(
        guard_service,
        net_config,
        rpc=NearRpc(net_config, client=client),
        tee_authorizer=tee_authorizer,
        tee_provider=tee_provider,
        policy_adapter=_near_policy_adapter(client),
        provider_policy_agent_id=config.NEAR_AGENT_ID,
        require_provider_policy=config.NEAR_REQUIRE_PROVIDER_POLICY,
    )
    # The durable pipeline wraps the boundary for the broadcast route: it records
    # every submission before it is sent (so an unknown outcome is resolved from
    # the chain, never blindly retried) and polls for finality. A configured
    # ledger that cannot be opened is a hard failure, never a silent fallback to
    # memory. The pipeline never holds a key - the caller signs.
    from .near.ledger import SubmissionLedger
    from .near.pipeline import NearExecutionPipeline
    from .near.tee_signing import EvidenceChainStore

    try:
        ledger = SubmissionLedger(config.NEAR_LEDGER_DB)
    except Exception as exc:  # noqa: BLE001 - a broken ledger must not start
        raise RuntimeError(f"TRACESETTLE_NEAR_LEDGER_DB: {exc}") from exc
    # The durable evidence chain. Same rule: a configured store that cannot be
    # opened is a hard failure, never a silent fallback to memory, so a
    # deployment that promises an inspectable chain actually keeps one.
    try:
        chain_store = EvidenceChainStore(config.NEAR_CHAIN_DB)
    except Exception as exc:  # noqa: BLE001 - a broken chain store must not start
        raise RuntimeError(f"TRACESETTLE_NEAR_CHAIN_DB: {exc}") from exc
    boundary.pipeline = NearExecutionPipeline(
        boundary,
        ledger=ledger,
        chain_store=chain_store,
        finality_attempts=config.NEAR_FINALITY_ATTEMPTS,
        finality_delay=config.NEAR_FINALITY_DELAY_SECONDS,
    )
    return boundary


def _build_custody_boundary(guard_service: GuardService) -> Any:
    """Build the OutLayer custody boundary, or ``None`` when it is not enabled.

    The custody boundary is the one path that sends an *authorized* operation to
    a TEE-held signing wallet. It is an explicit operator decision
    (``TRACESETTLE_OUTLAYER_ENABLED=1`` plus an API key), never a public-bind
    default, and it requires the NEAR execution boundary to be enabled so an
    operation is always authorized before it is signed. A missing key, an unknown
    network, or a wallet id that does not match the key is a hard start-up
    failure, never a silent fallback.

    The provider's API key is read from configuration only. It is sent as a
    bearer header to the provider host and is never logged, returned, or placed
    in an error message.
    """
    if not config.OUTLAYER_ENABLED:
        return None
    from .near.networks import NetworkError, network_config
    from .near.outlayer import OutLayerConfig, OutLayerCustodyProvider
    from .near.outlayer_execution import OutLayerCustodyBoundary
    from .near.policy import PolicyAdapter
    from .near.rpc import NearRpc

    provider_config = OutLayerConfig(
        api_key=config.OUTLAYER_API_KEY,
        network=config.OUTLAYER_NETWORK,
        wallet_id=config.OUTLAYER_WALLET_ID,
        timeout=config.OUTLAYER_TIMEOUT_SECONDS,
    )
    try:
        net_config = network_config(config.NEAR_EXECUTION_NETWORK)
    except NetworkError as exc:
        raise RuntimeError(f"TRACESETTLE_NEAR_EXECUTION_NETWORK: {exc}") from exc
    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )
    provider = OutLayerCustodyProvider(provider_config, client=client)
    # The independent NEAR provider (Agent API) policy. It is a second layer,
    # separate from OutLayer's own wallet policy, and is required by default. The
    # adapter reads live policy only when a base URL and key are configured;
    # otherwise the gate reports the policy as unreadable and fails closed.
    policy_adapter = PolicyAdapter(
        base_url=config.NEAR_AGENT_API_URL,
        api_key=config.NEAR_AGENT_API_KEY,
        http_client=client,
        expected_host=config.NEAR_AGENT_API_EXPECTED_HOST,
        expected_agent_id=config.OUTLAYER_PROVIDER_POLICY_AGENT_ID,
        max_age_seconds=config.OUTLAYER_PROVIDER_POLICY_MAX_AGE_SECONDS,
    )
    return OutLayerCustodyBoundary(
        guard_service,
        provider,
        network=net_config.network,
        rpc=NearRpc(net_config, client=client),
        policy_adapter=policy_adapter,
        provider_policy_agent_id=config.OUTLAYER_PROVIDER_POLICY_AGENT_ID,
        require_provider_policy=config.OUTLAYER_REQUIRE_PROVIDER_POLICY,
    )


def _build_enclave_boundary() -> Any:
    """Build the enclave signing boundary, or ``None`` when it is not configured.

    Enclave signing is an explicit operator decision (``TRACESETTLE_ENCLAVE_SIGN_URL``
    plus ``TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT``). With no signing endpoint
    the boundary reports itself unavailable and refuses to sign, so hardware
    execution stays disabled rather than silently falling back to a software key.
    A malformed approved measurement is a hard failure at start-up.
    """
    if not config.ENCLAVE_SIGN_URL:
        return None
    from .near.collateral import PcsCollateralClient
    from .near.enclave import (
        ApprovedMeasurement,
        EnclaveKeyRegistry,
        EnclaveSigningBoundary,
        HttpEnclaveTransport,
        MeasurementPolicy,
    )

    try:
        fields = config.parse_approved_measurement(config.ENCLAVE_APPROVED_MEASUREMENT)
    except ValueError as exc:
        raise RuntimeError(f"TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT: {exc}") from exc
    approved = [ApprovedMeasurement("operator-approved", fields)] if fields else []
    client = HttpClient(
        timeout=config.REQUEST_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )
    registry = EnclaveKeyRegistry(config.ENCLAVE_KEY_DB)
    return EnclaveSigningBoundary(
        transport=HttpEnclaveTransport(
            base_url=_attestation_base_url(), sign_url=config.ENCLAVE_SIGN_URL, client=client
        ),
        measurements=MeasurementPolicy(approved, require_pin=True),
        registry=registry,
        collateral_client=PcsCollateralClient(),
    )


def _build_tee_signing_boundary() -> Any:
    """Build the TEE signing boundary, or ``None`` when it is not configured.

    This is the OutLayer Signing Keys route — the only one that signs the exact
    NEAR transaction digest inside an Intel TDX enclave. It is a **paid**
    per-execution route, so enabling it is an explicit operator decision and it is
    never a public-bind default. A missing owner, project or approved build is a
    hard failure at start-up (the boundary would otherwise report itself
    available and then refuse every call).

    With the flag off, or with no owner/project, the boundary is not built and the
    route reports it disabled. With owner and project set but no payment key, the
    boundary *is* built and reports itself unavailable and refuses to sign — the
    honest state for "the route exists but this deployment cannot pay for it".
    """
    if not config.TEE_SIGNING_ENABLED:
        return None
    from .near.tee_signing import OutLayerSigningProvider, TeeSigningBoundary

    if not config.TEE_SIGNING_OWNER or not config.TEE_SIGNING_PROJECT:
        raise RuntimeError(
            "TRACESETTLE_TEE_SIGNING=1 requires TRACESETTLE_TEE_SIGNING_OWNER and "
            "TRACESETTLE_TEE_SIGNING_PROJECT"
        )
    if not config.TEE_SIGNING_APPROVED_BUILD:
        raise RuntimeError(
            "TRACESETTLE_TEE_SIGNING=1 requires TRACESETTLE_TEE_SIGNING_APPROVED_BUILD "
            "(the sha256 of the exact signing WASM), so a swapped build cannot sign"
        )
    from .near.collateral import PcsCollateralClient

    approved_measurement = None
    if config.TEE_SIGNING_APPROVED_MEASUREMENT:
        from .near.enclave import ApprovedMeasurement, MeasurementPolicy

        fields = config.parse_approved_measurement(config.TEE_SIGNING_APPROVED_MEASUREMENT)
        approved_measurement = MeasurementPolicy(
            [ApprovedMeasurement("operator-approved", fields)], require_pin=True
        )

    client = HttpClient(
        timeout=config.OUTLAYER_TIMEOUT_SECONDS,
        max_attempts=config.MAX_ATTEMPTS,
    )
    provider = OutLayerSigningProvider(
        client=client,
        network=config.TEE_SIGNING_NETWORK,
        owner=config.TEE_SIGNING_OWNER,
        project=config.TEE_SIGNING_PROJECT,
        payment_key=config.TEE_SIGNING_PAYMENT_KEY or None,
        approved_build=config.TEE_SIGNING_APPROVED_BUILD,
    )
    boundary = TeeSigningBoundary(
        provider=provider,
        approved_build=config.TEE_SIGNING_APPROVED_BUILD,
        approved_measurement=approved_measurement,
        expected_caller=config.TEE_SIGNING_OWNER,
        expected_project=config.TEE_SIGNING_PROJECT,
        collateral_client=PcsCollateralClient(),
    )
    boundary.required = config.TEE_SIGNING_REQUIRED
    return boundary


def _attestation_base_url() -> str:
    """The attested gateway origin, derived from the configured attestation URL."""
    from urllib.parse import urlsplit

    parts = urlsplit(config.TEE_ATTESTATION_URL)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return "https://cloud-api.near.ai"


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
            enclave=_build_enclave_boundary(),
            custody=_build_custody_boundary(self.guard_service),
            tee_signing=_build_tee_signing_boundary(),
        )
        self.guard_limiter = guard_limiter or TokenBucketLimiter(
            config.GUARD_RATE_LIMIT_PER_MINUTE, config.GUARD_RATE_LIMIT_BURST
        )
        # The agent-facing sandbox integration. Built only when the operator
        # opted into the public demonstration; otherwise the routes 404, so an
        # operator deployment never exposes an agent surface it did not ask for.
        self.agent_api = (
            _build_agent_api(self.guard_service) if config.PUBLIC_DEMO_ENABLED else None
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
