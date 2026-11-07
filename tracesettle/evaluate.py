"""The public judge evaluation page (``/evaluate``).

A single, self-contained document that lets an independent technical judge test
TRACESETTLE's core security proposition without the developer's help, a wallet,
credentials, or any paid service. It runs the real scenario matrix
(:mod:`tracesettle.judge`) in the browser and shows, per scenario, the input,
the expected result, what actually happened, whether the signer was reached, and
the supporting evidence.

The page is served only when the operator enables the public demonstration
(``TRACESETTLE_PUBLIC_DEMO``); otherwise ``/evaluate`` returns 404, exactly like
``/demo``. It never performs a state-changing operation: the only endpoint it
calls is the read-only ``/api/guard/judge/scenarios``.
"""

from __future__ import annotations

# The page reuses the project's design tokens (see docs/DESIGN.md) so it is
# visually consistent with the landing page, the demonstration and the console.
EVALUATE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACESETTLE — Independent evaluation</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0e14'/%3E%3Cpath d='M9 11h14M16 11v11' stroke='%236ea8fe' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
  :root {
    --bg: #0b0e14; --panel: #121722; --panel-2: #0e131c; --line: #232b3a;
    --fg: #e8eef7; --muted: #93a1b5; --accent: #6ea8fe; --accent-2: #b98bff;
    --ok: #3fb950; --warn: #e3b341; --bad: #ff7b72; --hold: #d2a8ff; --sim: #b98bff;
    --focus: #ffd33d;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-text-size-adjust: 100%; }
  a { color: var(--accent); }
  .skip { position: absolute; left: -999px; top: 0; background: var(--focus); color: #111;
    padding: 8px 12px; border-radius: 0 0 6px 0; z-index: 20; }
  .skip:focus { left: 0; }
  :focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
  header.app { border-bottom: 1px solid var(--line); background: linear-gradient(180deg,#101623,#0b0e14);
    position: sticky; top: 0; z-index: 10; }
  .bar { max-width: 1080px; margin: 0 auto; padding: 14px 18px; display: flex; gap: 14px;
    align-items: center; flex-wrap: wrap; }
  .brand { font-weight: 700; letter-spacing: .12em; font-size: 16px; }
  .brand span { color: var(--accent); }
  .tagline { color: var(--muted); font-size: 12.5px; }
  .bar nav { margin-left: auto; display: flex; gap: 6px; font-size: 13.5px; }
  /* WCAG 2.2 AA 2.5.8: nav targets must be at least 24x24 CSS px. */
  .bar nav a { display: inline-block; padding: 6px 8px; border-radius: 7px; }
  main { max-width: 1080px; margin: 0 auto; padding: 26px 18px 72px; }
  .hero h1 { font-size: 30px; line-height: 1.15; margin: 0 0 10px; letter-spacing: -.01em; }
  .hero .sub { color: var(--accent); font-weight: 600; font-size: 16px; margin: 0 0 12px; }
  .hero p { color: var(--muted); max-width: 74ch; margin: 0 0 10px; }
  .pillrow { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0 6px; }
  .pill { font-size: 11.5px; letter-spacing: .05em; text-transform: uppercase; border: 1px solid var(--line);
    border-radius: 999px; padding: 4px 10px; color: var(--muted); }
  .pill.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 55%, var(--line)); }
  .pill.sim { color: var(--sim); border-color: color-mix(in srgb, var(--sim) 55%, var(--line)); }
  .pill.real { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 55%, var(--line)); }
  .grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px;
    margin: 22px 0; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px 18px; }
  .card h2 { font-size: 14px; margin: 0 0 10px; letter-spacing: .02em; }
  .card p { color: var(--muted); font-size: 13.5px; margin: 0 0 8px; }
  .card ul { margin: 0; padding-left: 18px; color: var(--muted); font-size: 13.5px; }
  .card li { margin-bottom: 5px; }
  .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 24px 0 8px; }
  .controls > a { display: inline-block; padding: 10px 14px; border-radius: 9px; border: 1px solid var(--line);
    background: #1a2130; text-decoration: none; font-size: 14px; }
  .controls > a:hover { border-color: var(--accent); }
  button { padding: 12px 20px; border-radius: 9px; border: 1px solid var(--line);
    background: #1a2130; color: var(--fg); font: inherit; font-size: 14px; cursor: pointer; }
  button.primary { background: var(--accent); color: #08111f; border-color: var(--accent); font-weight: 700; }
  button:hover { border-color: var(--accent); }
  button[disabled] { opacity: .55; cursor: progress; }
  .hint { color: var(--muted); font-size: 12.5px; margin: 0 0 20px; }
  .summary { display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0; }
  .kpi { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    padding: 12px 16px; min-width: 130px; }
  .kpi .n { font-size: 26px; font-weight: 700; line-height: 1.1; }
  .kpi .l { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; }
  .scenario { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
    padding: 0; margin-bottom: 12px; overflow: hidden; }
  .scenario > summary { list-style: none; cursor: pointer; padding: 15px 18px; display: flex;
    gap: 12px; align-items: center; flex-wrap: wrap; }
  .scenario > summary::-webkit-details-marker { display: none; }
  .scenario .st { font-size: 11px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
    padding: 3px 9px; border-radius: 999px; border: 1px solid currentColor; white-space: nowrap; }
  .st-pass { color: var(--ok); } .st-fail { color: var(--bad); } .st-wait { color: var(--muted); }
  .st-skip { color: var(--muted); }
  .scenario .name { font-weight: 600; font-size: 15px; }
  .scenario .exp { color: var(--muted); font-size: 13px; margin-left: auto; }
  .scenario .body { border-top: 1px solid var(--line); padding: 16px 18px; background: var(--panel-2); }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; font-size: 13.5px;
    margin: 0 0 12px; }
  .kv dt { color: var(--muted); } .kv dd { margin: 0; overflow-wrap: anywhere; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
  .badge-row { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 12px; }
  .badge { font-size: 11.5px; border: 1px solid var(--line); border-radius: 7px; padding: 4px 9px;
    color: var(--muted); }
  .badge.no { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, var(--line)); }
  .badge.yes { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 45%, var(--line)); }
  .note { border-left: 3px solid var(--accent); background: #101a2b; padding: 9px 12px; border-radius: 6px;
    color: #cfe0f7; font-size: 13px; margin: 0 0 14px; }
  .note.sim { border-left-color: var(--sim); background: #171327; color: #ded0ff; }
  .note.bad { border-left-color: var(--bad); background: #2a1518; color: #ffc9c4; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; display: block; overflow-x: auto; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: .05em;
    font-size: 11px; white-space: nowrap; }
  details.raw { margin-top: 10px; }
  details.raw summary { cursor: pointer; color: var(--muted); font-size: 12.5px; }
  pre { background: #080b11; border: 1px solid var(--line); border-radius: 8px; padding: 12px;
    overflow: auto; font-size: 12px; max-height: 360px; }
  .loading { color: var(--muted); font-size: 13.5px; padding: 14px 0; }
  footer { color: var(--muted); font-size: 12px; text-align: center; padding: 26px 16px;
    border-top: 1px solid var(--line); margin-top: 30px; }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
  @media (max-width: 560px) {
    main { padding-left: 12px; padding-right: 12px; }
    .hero h1 { font-size: 23px; }
    .scenario .exp { margin-left: 0; width: 100%; }
  }
</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header class="app">
  <div class="bar">
    <div>
      <div class="brand">TRACE<span>SETTLE</span></div>
      <div class="tagline">Independent evaluation &middot; v__VERSION__</div>
    </div>
    <nav aria-label="Site">
      <a href="/">Home</a>
      <a href="/demo">Demo</a>
      <a href="/console">Console</a>
    </nav>
  </div>
</header>
<main id="main">
  <section class="hero">
    <h1>Test the security boundary yourself.</h1>
    <p class="sub">No wallet. No credentials. No paid service.</p>
    <p>This page runs TRACESETTLE's real authorization boundary, reference signer, replay store and
      settlement verifier against ten scenarios. Each result states its own decision, whether the
      signer was reached, whether anything was signed, and whether anything was broadcast. Nothing
      here is a screenshot: the numbers come from the running backend.</p>
    <div class="pillrow">
      <span class="pill real">1 live testnet check</span>
      <span class="pill sim">9 controlled simulations</span>
      <span class="pill ok">read-only</span>
      <span class="pill">no key requested</span>
    </div>
  </section>

  <div class="grid2">
    <article class="card">
      <h2>What you are testing</h2>
      <p>The core proposition: an AI agent's intention is never payment authorization. The boundary
        reads the actual transaction parameters, decides, and refuses anything outside policy
        <strong>before</strong> a signer is reached.</p>
    </article>
    <article class="card">
      <h2>What is real, and what is simulated</h2>
      <ul>
        <li><strong>Real code:</strong> the authorization boundary, guard controls, reference signer,
          replay store, approval authority, NEAR policy analysis and the settlement verifier.</li>
        <li><strong>Simulated:</strong> the two executor scenarios' transaction parameters are
          synthetic and the executor never touches a chain.</li>
        <li><strong>Real evidence:</strong> scenario 10 reads an already-final NEAR
          <strong>testnet</strong> transaction from a public RPC. It never signs or broadcasts.</li>
        <li><strong>Needs external setup:</strong> a live wallet signature and mainnet settlement are
          not exercised here — see the limitations in the judge guide.</li>
      </ul>
    </article>
  </div>

  <div class="controls">
    <button id="run" class="primary" type="button">Run the ten scenarios</button>
    <a href="JUDGE_GUIDE">Judge guide</a>
    <a href="api/guard/judge/scenarios">Raw JSON</a>
  </div>
  <p class="hint">Runs in a few seconds. The live testnet check may report <span class="mono">UNAVAILABLE</span>
    if the public RPC cannot be reached — that is a limitation of the live read, never a verdict about
    the transaction.</p>

  <div id="out" aria-live="polite"></div>
</main>
<footer>
  <p>Read-only and non-custodial. This evaluation never signs, broadcasts or moves funds.
    TRACESETTLE never requests a private key or seed phrase.</p>
</footer>
<script>
const out = document.getElementById('out');
const runBtn = document.getElementById('run');

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function kv(pairs) {
  return '<dl class="kv">' + pairs.map(function (p) {
    return '<dt>' + esc(p[0]) + '</dt><dd>' + p[1] + '</dd>';
  }).join('') + '</dl>';
}
function boolBadge(label, value, dangerWhenTrue) {
  const cls = dangerWhenTrue ? (value ? 'yes' : 'no') : (value ? 'yes' : 'no');
  return '<span class="badge ' + cls + '">' + esc(label) + ': ' + esc(String(value)) + '</span>';
}

function scenarioCard(s) {
  const skipped = s.skipped;
  const stateCls = skipped ? 'st-skip' : (s.passed ? 'st-pass' : 'st-fail');
  const stateLabel = skipped ? 'not run here (no network)'
                             : (s.passed ? 'expected result' : 'unexpected');
  const realPill = s.real ? '<span class="pill real">real evidence</span>'
                          : '<span class="pill sim">simulated</span>';
  let body = '<div class="badge-row">' + realPill +
    '<span class="st ' + stateCls + '">' + stateLabel + '</span>' +
    '<span class="badge">decision: ' + esc(s.decision) + '</span>' +
    boolBadge('signer reached', s.signer_calls > 0, false) +
    boolBadge('signed', s.signed, true) +
    boolBadge('broadcast', s.broadcast, true) +
    '</div>';
  body += '<p class="exp"><strong>Threat.</strong> ' + esc(s.threat) + '</p>';
  body += kv([
    ['Expected', esc(s.expected)],
    ['Observed', '<span class="mono">' + esc(s.observed) + '</span>'],
    ['Signer invocations', esc(String(s.signer_calls))],
    ['Input', '<span class="mono">' + esc(JSON.stringify(s.input)) + '</span>'],
  ]);
  body += '<details class="raw"><summary>Raw evidence (JSON)</summary><pre>' +
    esc(JSON.stringify(s.evidence, null, 2)) + '</pre></details>';
  return '<details class="scenario" open>' +
    '<summary><span class="name">' + esc(s.title) + '</span>' +
    '<span class="exp">' + esc(s.expected) + '</span></summary>' +
    '<div class="body">' + body + '</div></details>';
}

function render(rep) {
  const s = rep.summary;
  let html = '<div class="summary">' +
    '<div class="kpi"><div class="n">' + esc(String(s.passed)) + '/' + esc(String(s.total)) +
      '</div><div class="l">scenarios as expected</div></div>' +
    '<div class="kpi"><div class="n">' + esc(String(s.enforcement_passed)) + '/' +
      esc(String(s.enforcement_total)) + '</div><div class="l">enforcement (simulated)</div></div>' +
    '<div class="kpi"><div class="n">' + esc(String(s.live_passed)) + '/' + esc(String(s.live_total)) +
      '</div><div class="l">live testnet check</div></div>' +
    '<div class="kpi"><div class="n">' + esc(String(s.broadcast_occurred ? 'yes' : 'no')) +
      '</div><div class="l">anything broadcast</div></div>' +
    '</div>';
  html += '<div class="note sim">' + esc(rep.disclaimer) + '</div>';
  html += rep.scenarios.map(scenarioCard).join('');
  out.innerHTML = html;
}

async function run() {
  runBtn.disabled = true;
  out.innerHTML = '<div class="loading">Running the boundary, signer and verifier&hellip;</div>';
  try {
    const res = await fetch('api/guard/judge/scenarios');
    const rep = await res.json();
    if (!res.ok) { throw new Error(rep.error || ('HTTP ' + res.status)); }
    render(rep);
  } catch (err) {
    out.innerHTML = '<div class="note bad">' + esc(err.message) + '</div>';
  } finally {
    runBtn.disabled = false;
  }
}

runBtn.addEventListener('click', run);
</script>
</body>
</html>
"""

__all__ = ["EVALUATE_HTML", "DOC_PAGE"]

#: The shell for a served Markdown document (the judge guide). It reuses the same
#: design tokens as the evaluation page and the landing page.
DOC_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACESETTLE — __TITLE__</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0e14'/%3E%3Cpath d='M9 11h14M16 11v11' stroke='%236ea8fe' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
  :root {
    --bg: #0b0e14; --panel: #121722; --line: #232b3a; --fg: #e8eef7; --muted: #93a1b5;
    --accent: #6ea8fe; --ok: #3fb950; --focus: #ffd33d;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg);
    font: 15.5px/1.65 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-text-size-adjust: 100%; }
  a { color: var(--accent); }
  .skip { position: absolute; left: -999px; top: 0; background: var(--focus); color: #111;
    padding: 8px 12px; border-radius: 0 0 6px 0; z-index: 20; }
  .skip:focus { left: 0; }
  :focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
  header.app { border-bottom: 1px solid var(--line); background: linear-gradient(180deg,#101623,#0b0e14);
    position: sticky; top: 0; z-index: 10; }
  .bar { max-width: 860px; margin: 0 auto; padding: 14px 18px; display: flex; gap: 14px;
    align-items: center; flex-wrap: wrap; }
  .brand { font-weight: 700; letter-spacing: .12em; font-size: 16px; }
  .brand span { color: var(--accent); }
  .tagline { color: var(--muted); font-size: 12.5px; }
  .bar nav { margin-left: auto; display: flex; gap: 6px; font-size: 13.5px; }
  /* WCAG 2.2 AA 2.5.8: nav targets must be at least 24x24 CSS px. */
  .bar nav a { display: inline-block; padding: 6px 8px; border-radius: 7px; }
  main { max-width: 860px; margin: 0 auto; padding: 28px 18px 72px; }
  h1 { font-size: 28px; line-height: 1.2; margin: 0 0 14px; letter-spacing: -.01em; }
  h2 { font-size: 20px; margin: 34px 0 10px; padding-top: 6px; border-top: 1px solid var(--line); }
  h3 { font-size: 16px; margin: 24px 0 8px; }
  h4 { font-size: 14px; margin: 20px 0 6px; color: var(--muted); text-transform: uppercase;
    letter-spacing: .05em; }
  p, li { color: #d6dee9; }
  p { margin: 0 0 12px; }
  ul, ol { margin: 0 0 14px; padding-left: 22px; }
  li { margin-bottom: 5px; }
  code { background: #0a0e15; padding: 1px 6px; border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
  pre { background: #080b11; border: 1px solid var(--line); border-radius: 8px; padding: 14px;
    overflow: auto; font-size: 13px; margin: 0 0 16px; }
  pre code { background: none; padding: 0; }
  blockquote { border-left: 3px solid var(--accent); background: #101a2b; margin: 0 0 16px;
    padding: 10px 14px; border-radius: 6px; color: #cfe0f7; }
  blockquote p { margin: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 13.5px; margin: 0 0 18px;
    display: block; overflow-x: auto; }
  th, td { text-align: left; padding: 8px 11px; border-bottom: 1px solid var(--line);
    vertical-align: top; overflow-wrap: anywhere; }
  th { color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: .05em;
    font-size: 11.5px; white-space: nowrap; }
  hr { border: none; border-top: 1px solid var(--line); margin: 26px 0; }
  footer { color: var(--muted); font-size: 12px; text-align: center; padding: 26px 16px;
    border-top: 1px solid var(--line); }
  @media (max-width: 560px) { main { padding-left: 14px; padding-right: 14px; } h1 { font-size: 22px; } }
</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header class="app">
  <div class="bar">
    <div>
      <div class="brand">TRACE<span>SETTLE</span></div>
      <div class="tagline">__TITLE__ &middot; v__VERSION__</div>
    </div>
    <nav aria-label="Site">
      <a href="/">Home</a>
      <a href="/evaluate">Evaluate</a>
      <a href="/demo">Demo</a>
      <a href="/console">Console</a>
    </nav>
  </div>
</header>
<main id="main">
__BODY__
</main>
<footer>
  <p>Read-only and non-custodial. TRACESETTLE never signs, broadcasts or moves funds, and never
    requests a private key or seed phrase.</p>
</footer>
</body>
</html>
"""
