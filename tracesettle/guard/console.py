"""The security operations console.

A single self-contained page (standard library only, no build step, no CDN) that
gives an operator the eight sections the product requires. It is served by
:mod:`tracesettle.ui` at ``/console`` and talks only to this server's own JSON
endpoints.

Design notes
------------
* Information hierarchy first: an outcome is always a labelled status, never a
  bare colour. Colour is additive, never the only signal (WCAG 2.2 AA).
* Every asynchronous panel has explicit loading, empty, and error states.
* Nothing is fabricated: if a panel has no data it says so.
* A simulation banner is shown whenever any rendered item is simulated.
"""

from __future__ import annotations

CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACESETTLE — Security Operations Console</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0e14'/%3E%3Cpath d='M9 11h14M16 11v11' stroke='%236ea8fe' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
  :root {
    --bg: #0b0e14; --panel: #121722; --panel-2: #0e131c; --line: #232b3a;
    --fg: #e8eef7; --muted: #93a1b5; --accent: #6ea8fe; --accent-2: #b98bff;
    --ok: #3fb950; --warn: #e3b341; --bad: #ff7b72; --hold: #d2a8ff; --info: #79c0ff;
    --sim: #b98bff;
    --focus: #ffd33d;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body {
    background: var(--bg); color: var(--fg);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-text-size-adjust: 100%;
  }
  a { color: var(--accent); }
  .skip { position: absolute; left: -999px; top: 0; background: var(--focus); color: #111;
    padding: 8px 12px; border-radius: 0 0 6px 0; z-index: 20; }
  .skip:focus { left: 0; }
  :focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
  header.app { border-bottom: 1px solid var(--line); background: linear-gradient(180deg,#101623,#0b0e14);
    position: sticky; top: 0; z-index: 10; }
  .bar { max-width: 1240px; margin: 0 auto; padding: 14px 18px; display: flex; gap: 16px;
    align-items: center; flex-wrap: wrap; }
  .brand { font-weight: 700; letter-spacing: .12em; font-size: 16px; }
  .brand span { color: var(--accent); }
  .tagline { color: var(--muted); font-size: 12.5px; }
  .badges { margin-left: auto; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .badge { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; border: 1px solid var(--line);
    border-radius: 999px; padding: 3px 9px; color: var(--muted); white-space: nowrap; }
  .badge.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 55%, var(--line)); }
  .badge.sim { color: var(--sim); border-color: color-mix(in srgb, var(--sim) 55%, var(--line)); }
  .badge.bad { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 55%, var(--line)); }
  nav.tabs { border-bottom: 1px solid var(--line); background: var(--panel-2); position: sticky;
    top: 61px; z-index: 9; }
  nav.tabs ul { max-width: 1240px; margin: 0 auto; padding: 0 10px; display: flex; gap: 2px;
    list-style: none; overflow-x: auto; }
  nav.tabs button { appearance: none; background: none; border: none; border-bottom: 2px solid transparent;
    color: var(--muted); font: inherit; font-size: 13.5px; padding: 11px 13px; cursor: pointer;
    white-space: nowrap; }
  nav.tabs button[aria-selected="true"] { color: var(--fg); border-bottom-color: var(--accent); }
  nav.tabs button:hover { color: var(--fg); }
  main { max-width: 1240px; margin: 0 auto; padding: 20px 18px 64px; }
  section[role="tabpanel"] { display: none; }
  section[role="tabpanel"].active { display: block; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 0 0 12px; letter-spacing: .02em; }
  h3 { font-size: 13px; margin: 16px 0 8px; color: var(--muted); text-transform: uppercase;
    letter-spacing: .08em; }
  .lede { color: var(--muted); font-size: 13.5px; margin: 0 0 18px; max-width: 78ch; }
  .grid { display: grid; gap: 14px; }
  .grid.kpi { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }
  .grid.two { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 15px 16px; }
  .card.kpi .n { font-size: 30px; font-weight: 700; line-height: 1.1; }
  .card.kpi .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .07em; }
  .card.kpi .hint { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    padding: 16px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  caption { text-align: left; color: var(--muted); font-size: 12.5px; padding-bottom: 8px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase;
    letter-spacing: .06em; white-space: nowrap; }
  td.wrap { word-break: break-word; }
  .status { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600;
    letter-spacing: .04em; text-transform: uppercase; padding: 2px 8px; border-radius: 999px;
    border: 1px solid currentColor; }
  .status::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
  .s-ALLOW, .s-CONFIRMED, .s-EXECUTED, .s-OK, .s-RESOLVED, .s-VALID, .s-VERIFIED,
  .s-SETTLEMENT_VERIFIED, .s-DESTINATION_DELIVERY_VERIFIED, .s-ORIGIN_DEPOSIT_VERIFIED { color: var(--ok); }
  .s-REQUIRE_APPROVAL, .s-REPORTED, .s-ACKNOWLEDGED, .s-PARTIAL, .s-REPORTED_ONLY, .s-UNCONFIRMED { color: var(--warn); }
  .s-HOLD, .s-UNKNOWN, .s-INCOMPLETE, .s-OPEN, .s-NO_EXPIRY_STATED, .s-QUOTE_EXPIRED,
  .s-PENDING, .s-AWAITING_DEPOSIT, .s-DEPOSIT_SUBMITTED { color: var(--hold); }
  .s-BLOCK, .s-REFUSED, .s-CONTRADICTORY, .s-UNAVAILABLE, .s-FAILED { color: var(--bad); }
  .s-REFUNDED, .s-DEPOSIT_DETECTED, .s-DEPOSIT_INCOMPLETE, .s-DESTINATION_OBSERVED { color: var(--info); }
  .s-SIMULATED, .s-NOTICE { color: var(--sim); }
  .s-MISSING { color: var(--muted); }
  .sev-LOW { color: var(--info); } .sev-MEDIUM { color: var(--warn); }
  .sev-HIGH { color: #ffa657; } .sev-CRITICAL { color: var(--bad); }
  .sev-INFO { color: var(--muted); }
  button.act { appearance: none; font: inherit; font-size: 13px; padding: 9px 14px; border-radius: 8px;
    border: 1px solid var(--line); background: #1a2130; color: var(--fg); cursor: pointer; }
  button.act:hover { border-color: var(--accent); }
  button.act.primary { background: #1d4ed8; border-color: #1d4ed8; }
  button.act.primary:hover { background: #2563eb; }
  button.act[disabled] { opacity: .55; cursor: progress; }
  input[type=text], input[type=password], textarea, select {
    font: inherit; font-size: 13.5px; color: var(--fg); background: #0a0e15;
    border: 1px solid var(--line); border-radius: 8px; padding: 9px 11px; width: 100%; }
  label { display: block; font-size: 12px; color: var(--muted); margin: 0 0 4px; }
  .field { margin-bottom: 12px; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; }
  .row > .field { flex: 1 1 180px; margin-bottom: 0; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 5px 16px; font-size: 13px; }
  .kv dt { color: var(--muted); } .kv dd { margin: 0; word-break: break-word; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
  code { background: #0a0e15; padding: 1px 5px; border-radius: 4px; word-break: break-all; }
  .note { border-left: 3px solid var(--accent); background: #101a2b; padding: 9px 12px;
    border-radius: 6px; color: #cfe0f7; font-size: 13px; margin: 0 0 14px; }
  .note.sim { border-left-color: var(--sim); background: #171327; color: #ded0ff; }
  .note.bad { border-left-color: var(--bad); background: #2a1518; color: #ffc9c4; }
  .empty { color: var(--muted); font-size: 13px; padding: 12px; border: 1px dashed var(--line);
    border-radius: 8px; text-align: center; }
  .loading { color: var(--muted); font-size: 13px; }
  .preview { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; margin-top: 12px;
    background: #0b1220; font-size: 13px; }
  ul.plain { list-style: none; margin: 0; padding: 0; }
  ul.plain li { border-bottom: 1px solid var(--line); padding: 10px 0; }
  ul.plain li:last-child { border-bottom: none; }
  /* Long unbroken values (addresses, hashes) must wrap, or the page scrolls
     sideways on a narrow viewport. Applies to every text container. */
  .card, .panel, .kv dd, ul.plain li, td, th, p, li, dd, .status { overflow-wrap: anywhere; word-break: break-word; }
  table { display: block; overflow-x: auto; }
  @media (max-width: 560px) { main { padding-left: 12px; padding-right: 12px; } .bar { padding-left: 12px; padding-right: 12px; } }
  .muted { color: var(--muted); }
  .small { font-size: 12px; }
  .stack { display: flex; flex-direction: column; gap: 10px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px; }
  details.raw summary { cursor: pointer; color: var(--muted); font-size: 12.5px; }
  pre { background: #080b11; border: 1px solid var(--line); border-radius: 8px; padding: 12px;
    overflow: auto; font-size: 12px; max-height: 420px; }
  footer { color: var(--muted); font-size: 12px; text-align: center; padding: 24px 16px;
    border-top: 1px solid var(--line); }
  .sr { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden;
    clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
  @media (max-width: 640px) {
    .bar { padding: 12px; } nav.tabs { top: 0; position: static; }
    .hide-sm { display: none; } .card.kpi .n { font-size: 24px; }
  }
</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header class="app">
  <div class="bar">
    <div>
      <div class="brand">TRACE<span>SETTLE</span></div>
      <div class="tagline">Blockchain transaction security &amp; settlement assurance</div>
    </div>
    <div class="badges">
      <span class="badge" id="badge-version">v__VERSION__</span>
      <span class="badge ok" id="badge-audit">audit: checking</span>
      <span class="badge" id="badge-key">key: checking</span>
      <label class="sr" for="apikey">API key (sent as X-API-Key when configured)</label>
      <input type="password" id="apikey" placeholder="API key (if required)" autocomplete="off"
        style="width: 190px" aria-describedby="apikey-hint">
      <span id="apikey-hint" class="sr">Only needed when the server is configured with an API key.</span>
    </div>
  </div>
</header>
<nav class="tabs" aria-label="Sections">
  <ul role="tablist">
    <li role="presentation"><button role="tab" id="tab-overview" aria-controls="panel-overview" aria-selected="true">Security Overview</button></li>
    <li role="presentation"><button role="tab" id="tab-guard" aria-controls="panel-guard" aria-selected="false">Transaction Guard</button></li>
    <li role="presentation"><button role="tab" id="tab-lab" aria-controls="panel-lab" aria-selected="false">Attack Simulations</button></li>
    <li role="presentation"><button role="tab" id="tab-near" aria-controls="panel-near" aria-selected="false">NEAR Agent Security</button></li>
    <li role="presentation"><button role="tab" id="tab-intents" aria-controls="panel-intents" aria-selected="false">Intents Lifecycle</button></li>
    <li role="presentation"><button role="tab" id="tab-investigations" aria-controls="panel-investigations" aria-selected="false">Investigations</button></li>
    <li role="presentation"><button role="tab" id="tab-incidents" aria-controls="panel-incidents" aria-selected="false">Security Incidents</button></li>
    <li role="presentation"><button role="tab" id="tab-policies" aria-controls="panel-policies" aria-selected="false">Policies &amp; Controls</button></li>
    <li role="presentation"><button role="tab" id="tab-integrations" aria-controls="panel-integrations" aria-selected="false">Integrations</button></li>
    <li role="presentation"><button role="tab" id="tab-audit" aria-controls="panel-audit" aria-selected="false">Audit Logs</button></li>
    <li role="presentation"><button role="tab" id="tab-settings" aria-controls="panel-settings" aria-selected="false">Settings</button></li>
  </ul>
</nav>
<main id="main">
  <div class="note" id="global-note">__DISCLAIMER__</div>

  <section role="tabpanel" id="panel-overview" class="active" aria-labelledby="tab-overview">
    <h1>Security Overview</h1>
    <p class="lede">Every transaction request is evaluated before execution. A decision of ALLOW
      produces a short-lived, transaction-bound authorization; anything else produces none, so a
      signer that consults TraceSettle refuses it. Values below are live counters from this process.</p>
    <div class="grid kpi" id="kpis"></div>
    <div class="grid two" style="margin-top:16px">
      <div class="panel"><h2>Recent security events</h2><div id="overview-events"></div></div>
      <div class="panel"><h2>Open incidents</h2><div id="overview-incidents"></div></div>
    </div>
    <div class="panel"><h2>Recent investigations</h2><div id="overview-investigations"></div></div>
  </section>

  <section role="tabpanel" id="panel-guard" aria-labelledby="tab-guard">
    <h1>Transaction Guard</h1>
    <p class="lede">Evaluate a transaction request against policy, then hand the result to the
      reference signer. The signer validates the authorization independently and refuses anything
      that is missing, expired, replayed, or bound to different parameters.</p>
    <div class="panel">
      <h2>Evaluate a request</h2>
      <form id="guard-form" autocomplete="off">
        <div class="row">
          <div class="field"><label for="g-service">Service identity</label>
            <input type="text" id="g-service" value="treasury-agent"></div>
          <div class="field"><label for="g-operation">Operation</label>
            <input type="text" id="g-operation" value="WITHDRAWAL"></div>
          <div class="field"><label for="g-chain">Chain</label>
            <input type="text" id="g-chain" value="eth"></div>
          <div class="field"><label for="g-asset">Asset</label>
            <input type="text" id="g-asset" value="USDC"></div>
        </div>
        <div class="row" style="margin-top:12px">
          <div class="field"><label for="g-amount">Amount</label>
            <input type="text" id="g-amount" value="1250.50"></div>
          <div class="field" style="flex:2 1 320px"><label for="g-destination">Destination</label>
            <input type="text" id="g-destination" value="0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"></div>
        </div>
        <div class="row" style="margin-top:12px">
          <div class="field"><label for="g-request-id">Request reference (optional)</label>
            <input type="text" id="g-request-id" placeholder="auto-generated"></div>
          <div class="field"><label for="g-flag">Include a client approval flag (test)</label>
            <select id="g-flag">
              <option value="">none</option>
              <option value="approved">approved: true</option>
              <option value="skip_checks">skip_checks: true</option>
            </select></div>
        </div>
        <div class="actions">
          <button class="act primary" type="submit" id="g-submit">Evaluate</button>
          <button class="act" type="button" id="g-reset">Reset</button>
        </div>
      </form>
      <p class="small muted" style="margin:12px 0 0">A client approval flag is never honoured: its
        presence is reported as a finding and forces human review.</p>
    </div>
    <div id="guard-result" aria-live="polite"></div>
  </section>

  <section role="tabpanel" id="panel-lab" aria-labelledby="tab-lab">
    <h1>Attack Simulations</h1>
    <p class="lede">Controlled simulations that exercise the enforcement boundary. The transaction
      parameters are synthetic and the executor is simulated; nothing is broadcast to any chain. A
      simulated result never describes a real blockchain transaction.</p>
    <div id="lab-scenarios"></div>
    <div id="lab-output" aria-live="polite"></div>
  </section>

  <section role="tabpanel" id="panel-near" aria-labelledby="tab-near">
    <h1>NEAR Agent Security</h1>
    <p class="lede">The pre-execution boundary for an AI agent or payment service that acts on NEAR.
      Before the agent may sign, the wrapper inspects the real transaction parameters, the NEAR
      Intents policy scope, and the access-key scope. It returns one of ALLOW, REQUIRE_APPROVAL,
      BLOCK, HOLD or UNKNOWN. Nothing here signs or broadcasts a transaction.</p>

    <div class="panel" id="agent-demo-panel">
      <h2>End-to-end demonstration: block, authorize, settle, verify</h2>
      <p class="small">One story, two scenarios, through the <strong>real</strong> authorization
        boundary, signer, pipeline and settlement verifier. An agent is manipulated into
        redirecting a payment to an attacker: the boundary <strong>BLOCK</strong>s it and the signer
        is <strong>never invoked</strong> (a zero call count, not a claim). A legitimate payment is
        then authorized, signed, broadcast over a deterministic offline transport, and
        independently <strong>verified</strong> against the resulting record. The only substitution
        is the network; nothing is signed for real and nothing reaches a chain.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act primary" type="button" id="agent-demo-run">Run the demonstration</button>
      </div>
      <div id="agent-demo-output" aria-live="polite"></div>
    </div>

    <div class="panel">
      <h2>Connect a NEAR wallet</h2>
      <p class="small">Connect a NEAR wallet, then authorize and send one transfer. TraceSettle
        evaluates the real operation against the operator's policy <strong>before</strong> the wallet
        signs, binds the authorization to the exact transaction, and independently verifies the
        on-chain result afterwards. The <strong>wallet</strong> signs and sends; this server never
        holds a key. This panel is active only when the server enables the NEAR execution boundary
        (<span class="mono">TRACESETTLE_NEAR_EXECUTION=1</span>).</p>
      <div id="wallet-connect"></div>
      <div class="row" style="margin-top:12px">
        <div class="field"><label for="w-asset">Asset</label>
          <select id="w-asset"><option value="near:native">NEAR (native)</option></select></div>
        <div class="field"><label for="w-receiver">Recipient</label>
          <input type="text" id="w-receiver" placeholder="recipient.testnet" autocomplete="off"></div>
        <div class="field"><label for="w-amount">Amount</label>
          <input type="text" id="w-amount" value="0.02" autocomplete="off"></div>
      </div>
      <div id="w-preview" class="preview" hidden></div>
      <div class="actions" style="margin-top:12px">
        <button class="act primary" type="button" id="w-send" disabled>Authorize, sign and send</button>
      </div>
      <div id="wallet-output" aria-live="polite"></div>
    </div>

    <div class="panel">
      <h2>Policy scope</h2>
      <p class="small">An Intents policy protects the INTENTS path. A native NEAR/EVM/Solana
        request is <strong>not</strong> protected by its destinations, budget, timelock, schedule or
        owner approval; only the native method switch and an independent TraceSettle decision
        govern. This is the gap the panel makes visible.</p>
      <div id="near-scope"></div>
    </div>

    <div class="panel">
      <h2>Access-key permissions</h2>
      <p class="small">A function-call key cannot transfer NEAR and cannot attach NEAR tokens to a
        call. A full-access key is total control of the account. No private key material is present
        or requested.</p>
      <div id="near-keys"></div>
    </div>

    <div class="panel">
      <h2>Attack simulations</h2>
      <p class="small">Nine deterministic scenarios against the real controls. Each is a controlled
        simulation; the executor is simulated and nothing is broadcast.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act primary" type="button" id="near-run">Run all scenarios</button>
      </div>
      <div id="near-attacks"></div>
    </div>

    <div class="panel">
      <h2>Agent authorization behaviours</h2>
      <p class="small">Six required behaviours, each run against the real controls: a legitimate
        payment is allowed; an above-threshold payment requires a bound human approval; an
        unapproved destination is blocked; a tampered payload is refused; a replayed authorization
        is refused; and an unavailable control fails safe. The executor is simulated and nothing is
        broadcast.</p>
      <div id="near-behaviours"></div>
    </div>

    <div class="panel">
      <h2>Prompt-injection demonstration</h2>
      <p class="small">A manipulated agent is told to ignore its instructions and pay an attacker's
        receiver. TraceSettle evaluates the <strong>actual transaction parameters</strong>, not the
        agent's explanation, so the payment is blocked and never signed. This is a controlled
        simulation; the executor is simulated and nothing is broadcast.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act primary" type="button" id="near-injection-run">Run the injection demo</button>
      </div>
      <div id="near-injection"></div>
    </div>

    <div class="panel">
      <h2>Verifiable execution (Intel TDX attestation)</h2>
      <p class="small">The NEAR AI Cloud gateway runs inside an Intel TDX confidential VM. TraceSettle
        fetches the gateway's <strong>real</strong> hardware quote and verifies it locally against the
        pinned Intel SGX Root CA: the quote signature, the PCK certificate chain, the attestation key
        bound to the Quoting Enclave report, and the event log replayed to the RTMRs. The quote binds a
        fresh nonce, so an attestation cannot be replayed for a different decision. This is
        <strong>verification of a real quote</strong>, not a TEE-integrated execution path; the guard's
        decisions do not depend on it. Certificate revocation and TCB freshness need Intel PCS
        collateral and are <strong>not</strong> checked, so they are not claimed.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act primary" type="button" id="tee-run">Fetch and verify the gateway quote</button>
      </div>
      <div id="near-tee"></div>
    </div>

    <div class="panel">
      <h2>Enclave signing boundary</h2>
      <p class="small">When configured, a prepared NEAR transaction can be signed <strong>inside a
        measured enclave</strong> rather than by a software key held here. The boundary provisions a
        signing key only against a verified Intel TDX attestation that is pinned to the operator's
        approved measurement and bound to the exact transaction, and it verifies the returned
        signature over those exact bytes. With no signing endpoint configured it reports itself
        unavailable and refuses — it never falls back to a software key. This is a
        <strong>testnet-only</strong> signing boundary; it refuses mainnet, and it is not a claim of
        protection for any path that has not been configured.</p>
      <div id="near-enclave"></div>
    </div>

    <div class="panel">
      <h2>OutLayer custody evidence</h2>
      <p class="small">The OutLayer custody boundary sends an authorized operation to a
        <strong>TEE-held signing wallet</strong>. It reports the evidence state it actually
        established, on a strict ladder that never promotes a weaker state to a stronger one:
        <code>PROVIDER_CLAIMED</code> &lt; <code>CUSTODY_BOUND</code> &lt;
        <code>SETTLEMENT_VERIFIED</code> &lt; <code>ATTESTATION_VERIFIED</code> &lt;
        <code>TEE_SIGNING_VERIFIED</code>. A provider <code>success</code> is a claim, not proof.
        TEE signing is shown only when a genuine TDX attestation is cryptographically bound to the
        exact authorized operation and signing key <em>and</em> independent NEAR RPC settlement
        verification also holds.</p>
      <div id="near-custody"></div>
    </div>

    <div class="panel">
      <h2>Learning loop (durable safeguards)</h2>
      <p class="small">When a decision surfaces a security failure, the lesson is recorded as a
        durable safeguard and applied to later decisions. A safeguard only ever <strong>tightens</strong>
        a decision; it never overrides the operator's policy. With no safeguard store configured the
        loop is inert, and this panel says so.</p>
      <div id="near-safeguards"></div>
    </div>

    <div class="panel">
      <h2>Evaluate one agent transaction</h2>
      <p class="small">Inspects the real parameters, not the agent's explanation. The destination
        below is unapproved, so the default result is BLOCK.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act" type="button" id="near-eval-legit">Evaluate an approved payment</button>
        <button class="act" type="button" id="near-eval-attack">Evaluate an unapproved destination</button>
      </div>
      <div id="near-eval-output"></div>
    </div>
  </section>

  <section role="tabpanel" id="panel-intents" aria-labelledby="tab-intents">
    <h1>Intents Lifecycle</h1>
    <p class="lede">One NEAR Intents transaction, from authorization to settlement assurance.
      Each step inspects the real parameters, records its evidence durably, and is honest about
      what it does and does not establish. Nothing here signs, broadcasts, or holds a key: the
      only step that moves money is your own wallet funding the deposit address, which this
      product shows but never performs.</p>
    <div class="note sim">Provider endpoints are public and read-only. A live quote issues a
      deposit address; a dry quote does not. A provider success message is a reported claim, never
      proof of settlement.</div>

    <div class="panel">
      <h2>1. Create and authorize</h2>
      <p class="small">The guard evaluates the actual parameters against the server-resolved policy
        and the access-key scope. Only ALLOW issues a transaction-bound authorization.</p>
      <form id="intents-create" autocomplete="off">
        <div class="row">
          <div class="field" style="flex:1 1 160px"><label for="i-service">Service</label>
            <input type="text" id="i-service" value="treasury-agent"></div>
          <div class="field" style="flex:1 1 140px"><label for="i-op">Operation</label>
            <input type="text" id="i-op" value="SETTLEMENT"></div>
          <div class="field" style="flex:0 1 90px"><label for="i-chain">Chain</label>
            <input type="text" id="i-chain" value="eth"></div>
          <div class="field" style="flex:0 1 100px"><label for="i-asset">Asset</label>
            <input type="text" id="i-asset" value="USDC"></div>
          <div class="field" style="flex:0 1 130px"><label for="i-amount">Amount (base units)</label>
            <input type="text" id="i-amount" value="1000000"></div>
        </div>
        <div class="row">
          <div class="field" style="flex:2 1 320px"><label for="i-origin">Origin asset id</label>
            <input type="text" id="i-origin" value="nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near"></div>
          <div class="field" style="flex:2 1 320px"><label for="i-dest">Destination asset id</label>
            <input type="text" id="i-dest" value="nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near"></div>
        </div>
        <div class="row">
          <div class="field" style="flex:2 1 320px"><label for="i-recipient">Recipient</label>
            <input type="text" id="i-recipient" value="0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"></div>
          <div class="field" style="flex:0 0 auto"><button class="act primary" type="submit" id="i-submit">Authorize</button></div>
        </div>
      </form>
      <div id="intents-create-output" aria-live="polite"></div>
    </div>

    <div class="panel">
      <h2>2. Quote and deposit handoff</h2>
      <p class="small">Actions run against the intent created above. A live quote is refused unless
        the stored decision permits signing. A live quote issues a deposit address you fund from
        your own wallet; this product never signs or sends that transfer.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act" type="button" id="i-dry-quote">Request dry quote</button>
        <button class="act" type="button" id="i-live-quote">Request live quote</button>
        <button class="act" type="button" id="i-list">List my intents</button>
      </div>
      <div id="intents-step-output" aria-live="polite"></div>
      <div id="i-handoff"></div>
      <div id="i-approve-wrap" hidden>
        <p class="small">Approve only if the quote above matches what you intend to send. Approval
          does not move funds; it marks that you accept this exact quote.</p>
        <div class="actions" style="margin-bottom:12px">
          <button class="act primary" type="button" id="i-approve">Approve quote</button>
          <button class="act" type="button" id="i-reject">Reject quote</button>
        </div>
        <div id="i-approve-output" aria-live="polite"></div>
      </div>
      <div id="i-deposit-form-wrap" hidden>
        <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
        <label for="i-deposit-hash">Deposit transaction hash (from your wallet)</label>
        <div class="row" style="margin-top:6px">
          <div class="field" style="flex:2 1 320px">
            <input type="text" id="i-deposit-hash" placeholder="0x… (EVM) or a chain transaction hash" maxlength="200" autocomplete="off">
          </div>
          <div class="field" style="flex:0 0 auto">
            <button class="act primary" type="button" id="i-deposit">Record deposit</button>
          </div>
        </div>
        <p class="small muted" style="margin:6px 0 0">Recording the hash is optional and read-only: it tells the
          provider a deposit was sent so it can pre-verify it. It moves nothing.</p>
      </div>
    </div>

    <div class="panel">
      <h2>3. Monitor and verify settlement</h2>
      <p class="small">Read the provider's status, then run the independent settlement assurance.
        A provider success message is a reported claim; only decisive on-chain evidence raises the
        assurance level.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act" type="button" id="i-status">Refresh status</button>
        <button class="act" type="button" id="i-verify-origin">Verify deposit on origin chain</button>
        <button class="act" type="button" id="i-verify-destination">Verify delivery on destination chain</button>
        <button class="act" type="button" id="i-assurance">Run settlement assurance</button>
      </div>
      <div id="intents-assurance-output" aria-live="polite"></div>
    </div>

    <div class="panel">
      <h2>Provider assets</h2>
      <p class="small">The live supported-asset list from the provider (read-only).</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act" type="button" id="i-tokens">Load assets</button>
      </div>
      <div id="intents-tokens"></div>
    </div>
  </section>

  <section role="tabpanel" id="panel-investigations" aria-labelledby="tab-investigations">
    <h1>Investigations</h1>
    <p class="lede">The settlement investigation engine is unchanged and read-only. It reconstructs
      on-chain evidence around a completed NEAR Intents swap and reports what it can and cannot
      independently verify.</p>
    <div class="panel">
      <h2>Investigate a transaction</h2>
      <form id="inv-form" autocomplete="off">
        <div class="row">
          <div class="field" style="flex:3 1 340px"><label for="inv-id">Identifier</label>
            <input type="text" id="inv-id" placeholder="Deposit address, intent hash, or NEAR transaction hash" maxlength="128"></div>
          <div class="field" style="flex:0 0 auto"><button class="act primary" type="submit" id="inv-submit">Investigate</button></div>
        </div>
      </form>
      <p class="small muted" style="margin:10px 0 0">Supported: 1Click deposit addresses (full path)
        and intent hashes (settlement status only). No keys required. Read-only.</p>
    </div>
    <div class="panel">
      <h2>Saved investigations</h2>
      <p class="small">Reports retained across a restart. Selecting one loads the stored conclusion
        and its evidence, so a result can be revisited without re-reading live sources.</p>
      <div class="actions" style="margin-bottom:12px">
        <button class="act" type="button" id="inv-history-refresh">Refresh history</button>
      </div>
      <div id="inv-history"></div>
    </div>
    <div id="inv-result" aria-live="polite"></div>
  </section>

  <section role="tabpanel" id="panel-incidents" aria-labelledby="tab-incidents">
    <h1>Security Incidents</h1>
    <p class="lede">Incidents are opened by explicit rules when a control blocks a request, when a
      denied destination or unregistered identity is used, or when the signer refuses a transaction.</p>
    <div class="actions" style="margin-bottom:14px">
      <button class="act" type="button" data-incident-filter="OPEN">Open</button>
      <button class="act" type="button" data-incident-filter="ACKNOWLEDGED">Acknowledged</button>
      <button class="act" type="button" data-incident-filter="RESOLVED">Resolved</button>
      <button class="act" type="button" data-incident-filter="">All</button>
    </div>
    <div class="panel"><div id="incidents-body"></div></div>
  </section>

  <section role="tabpanel" id="panel-policies" aria-labelledby="tab-policies">
    <h1>Policies &amp; Controls</h1>
    <p class="lede">The active authorization policy and the deterministic controls that enforce it.
      Every control is a pure function of the request, the policy, and recorded history.</p>
    <div class="panel"><h2>Controls</h2><div id="controls-body"></div></div>
    <div class="panel"><h2>Active policy</h2><div id="policy-body"></div></div>
  </section>

  <section role="tabpanel" id="panel-integrations" aria-labelledby="tab-integrations">
    <h1>Integrations</h1>
    <p class="lede">The enforcement interface a signing system integrates with, and the external
      sources the settlement engine reads. Every external source is public and read-only.</p>
    <div class="panel"><h2>Authorization boundary</h2><div id="integration-body"></div></div>
    <div class="panel"><h2>Settlement data sources</h2><div id="sources-body"></div></div>
  </section>

  <section role="tabpanel" id="panel-audit" aria-labelledby="tab-audit">
    <h1>Audit Logs</h1>
    <p class="lede">Every evaluation, authorization, and signing attempt is appended to a
      hash-chained log. The chain gives tamper-evidence: an edit, reorder, or removal of a stored
      record is detectable by recomputation. It is not tamper-proof against an attacker who can
      rewrite the whole log, which is why the head digest is shown for external anchoring.</p>
    <div class="panel">
      <div class="actions" style="margin-bottom:12px">
        <button class="act" type="button" id="audit-verify">Verify chain</button>
        <button class="act" type="button" id="audit-refresh">Refresh</button>
      </div>
      <div id="audit-verification"></div>
      <div id="audit-body"></div>
    </div>
  </section>

  <section role="tabpanel" id="panel-settings" aria-labelledby="tab-settings">
    <h1>Settings</h1>
    <p class="lede">Runtime configuration reported by the server. Secrets are never displayed; the
      authorization key is shown only as a key identifier.</p>
    <div class="panel"><h2>Runtime</h2><div id="settings-body"></div></div>
  </section>
</main>
<footer>
  TRACESETTLE prevents an unauthorized transaction from reaching a signer that consults it. It does
  not sign, hold funds, or broadcast to any chain.
</footer>
<script src="/assets/near-connect.js"></script>
<script>
"use strict";
const S = { key: "", tab: "overview", investigations: [] };

function esc(v) {
  return String(v == null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function status(v) {
  return '<span class="status s-' + esc(v) + '">' + esc(v) + "</span>";
}
function sev(v) { return '<span class="status sev-' + esc(v) + '">' + esc(v) + "</span>"; }
function loading(text) { return '<div class="loading">' + esc(text) + "</div>"; }
function empty(text) { return '<div class="empty">' + esc(text) + "</div>"; }
function fmtAt(iso) { return esc(iso || ""); }

function headers() {
  const h = { "Content-Type": "application/json" };
  if (S.key) { h["X-API-Key"] = S.key; }
  return h;
}
async function api(method, path, body) {
  const res = await fetch(path, {
    method: method,
    headers: headers(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let payload = null;
  try { payload = await res.json(); } catch (e) { payload = null; }
  if (!res.ok) {
    if (res.status === 401) {
      // The operator console is key-gated. Say so plainly instead of a bare
      // "unauthorized", and point at the keyless public demonstration when the
      // operator has enabled it.
      throw new Error(
        "This console requires the operator API key (enter it above)." + __DEMO_HINT__
      );
    }
    const msg = (payload && payload.error) || ("HTTP " + res.status);
    throw new Error(msg);
  }
  return payload;
}

/* ---- tabs ---- */
function showTab(name) {
  S.tab = name;
  document.querySelectorAll('nav.tabs button[role="tab"]').forEach((b) => {
    const on = b.id === "tab-" + name;
    b.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll('section[role="tabpanel"]').forEach((s) => {
    s.classList.toggle("active", s.id === "panel-" + name);
  });
  const loaders = {
    overview: loadOverview, guard: () => {}, lab: loadLab, investigations: loadInvestigationHistory,
    incidents: () => loadIncidents("OPEN"), policies: loadPolicies, integrations: loadIntegrations,
    near: loadNear,
    intents: loadIntents,
    audit: loadAudit, settings: loadSettings,
  };
  if (loaders[name]) { loaders[name](); }
  if (location.hash !== "#" + name) { history.replaceState(null, "", "#" + name); }
}

/* ---- overview ---- */
async function loadOverview() {
  document.getElementById("kpis").innerHTML = loading("Loading metrics…");
  document.getElementById("overview-events").innerHTML = loading("Loading…");
  document.getElementById("overview-incidents").innerHTML = loading("Loading…");
  try {
    const m = await api("GET", "/api/guard/metrics");
    const c = m.counts || {};
    const cards = [
      ["Evaluated requests", c.evaluated || 0, "total pre-execution evaluations"],
      ["Approved", c.ALLOW || 0, "decision ALLOW"],
      ["Blocked", c.BLOCK || 0, "decision BLOCK"],
      ["Pending approvals", c.REQUIRE_APPROVAL || 0, "decision REQUIRE_APPROVAL"],
      ["Held", c.HOLD || 0, "decision HOLD"],
      ["Open incidents", c.open_incidents || 0, "not yet resolved"],
      ["Authorizations issued", c.authorizations_issued || 0, "short-lived, single-use"],
      ["Signer refusals", c.signer_refusals || 0, "refused at the signing boundary"],
    ];
    document.getElementById("kpis").innerHTML = cards.map(([l, n, h]) =>
      '<div class="card kpi"><div class="l">' + esc(l) + '</div><div class="n">' + esc(n) +
      '</div><div class="hint">' + esc(h) + "</div></div>").join("");
    renderEvents(m.recent_events || []);
    const inc = await api("GET", "/api/guard/incidents?status=OPEN&limit=5");
    renderIncidentList(document.getElementById("overview-incidents"), inc.incidents || [], true);
    renderInvestigations();
    updateBadges(m);
  } catch (err) {
    document.getElementById("kpis").innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
  }
}
function updateBadges(m) {
  const audit = (m && m.audit) || {};
  const badge = document.getElementById("badge-audit");
  badge.textContent = "audit: " + (audit.length || 0) + " records";
  const auth = (m && m.authorization) || {};
  const kb = document.getElementById("badge-key");
  kb.textContent = "key: " + (auth.ephemeral_key ? "ephemeral" : "configured");
  kb.className = "badge " + (auth.ephemeral_key ? "sim" : "ok");
}
function renderEvents(events) {
  const el = document.getElementById("overview-events");
  if (!events.length) { el.innerHTML = empty("No security events yet. Evaluate a request in Transaction Guard."); return; }
  el.innerHTML = '<ul class="plain">' + events.map((e) => {
    let label = e.kind;
    let detail = "";
    if (e.kind === "DECISION") { label = status(e.decision); detail = esc(e.summary || ""); }
    else if (e.kind === "SIGNER") { label = status(e.outcome); detail = esc(e.detail || ""); }
    else if (e.kind === "AUTHORIZATION_ISSUED") { detail = "authorization issued for " + esc(e.service_id || ""); }
    return "<li>" + label + ' <span class="small muted">' + fmtAt(e.at) + "</span><div>" + detail + "</div></li>";
  }).join("") + "</ul>";
}

/* ---- guard ---- */
function guardPayload() {
  const flag = document.getElementById("g-flag").value;
  const t = {
    service_id: document.getElementById("g-service").value.trim(),
    operation: document.getElementById("g-operation").value.trim(),
    chain: document.getElementById("g-chain").value.trim(),
    asset: document.getElementById("g-asset").value.trim(),
    amount: document.getElementById("g-amount").value.trim(),
    destination: document.getElementById("g-destination").value.trim(),
  };
  const rid = document.getElementById("g-request-id").value.trim();
  if (rid) { t.request_id = rid; }
  if (flag) { t[flag] = true; }
  return t;
}
function renderDecision(d, authorization, signResult) {
  let html = "";
  if (d.simulated) {
    html += '<div class="note sim"><strong>Simulation.</strong> This request was labelled simulated; ' +
      "the executor is simulated and nothing is broadcast to any chain.</div>";
  }
  html += '<div class="panel"><h2>Decision</h2><div class="kv">' +
    "<dt>Decision</dt><dd>" + status(d.decision) + "</dd>" +
    "<dt>Decision ID</dt><dd><code>" + esc(d.decision_id) + "</code></dd>" +
    "<dt>Risk level</dt><dd>" + sev(d.risk_level) + "</dd>" +
    "<dt>Request reference</dt><dd><code>" + esc(d.request.request_id) + "</code></dd>" +
    "<dt>Service</dt><dd>" + esc(d.request.service_id) + "</dd>" +
    "<dt>Transfer</dt><dd>" + esc(d.request.amount) + " " + esc(d.request.asset) + " on " +
      esc(d.request.chain) + "</dd>" +
    "<dt>Destination</dt><dd><code>" + esc(d.request.destination) + "</code></dd>" +
    "<dt>Bound parameters (digest)</dt><dd><code>" + esc(d.fingerprint.digest) + "</code></dd>" +
    "<dt>Authorizes signing</dt><dd>" + esc(d.authorizes_signing) + "</dd>" +
    "<dt>Evaluated at</dt><dd>" + fmtAt(d.created_at) + "</dd></div>" +
    "<p>" + esc(d.explanation) + "</p></div>";

  const findings = d.findings || [];
  html += '<div class="panel"><h2>Risk findings</h2>';
  if (!findings.length) { html += empty("No findings: every control passed."); }
  else {
    html += "<table><caption>Each finding is produced by a named control and is reproducible.</caption>" +
      "<thead><tr><th>Severity</th><th>Code</th><th>Finding</th><th>Policy</th></tr></thead><tbody>" +
      findings.map((f) => "<tr><td>" + sev(f.severity) + "</td><td><code>" + esc(f.code) +
        '</code></td><td class="wrap">' + esc(f.detail) + "</td><td>" + esc(f.policy) +
        "</td></tr>").join("") + "</tbody></table>";
  }
  html += "</div>";

  html += '<div class="panel"><h2>Controls</h2><table><thead><tr><th>Control</th><th>Outcome</th>' +
    "<th>Detail</th></tr></thead><tbody>" +
    (d.controls || []).map((c) => "<tr><td>" + esc(c.title) + "</td><td>" + status(c.outcome) +
      '</td><td class="wrap">' + esc(c.detail) + "</td></tr>").join("") + "</tbody></table></div>";

  if (authorization) {
    html += '<div class="panel"><h2>Issued authorization</h2><div class="kv">' +
      "<dt>Authorization ID</dt><dd><code>" + esc(authorization.authorization_id) + "</code></dd>" +
      "<dt>Bound digest</dt><dd><code>" + esc(authorization.fingerprint) + "</code></dd>" +
      "<dt>Issued at</dt><dd>" + esc(authorization.issued_at) + "</dd>" +
      "<dt>Expires at</dt><dd>" + esc(authorization.expires_at) + "</dd>" +
      "<dt>Nonce (single use)</dt><dd><code>" + esc(authorization.nonce) + "</code></dd>" +
      "</div></div>";
  } else if (d.decision === "ALLOW") {
    html += '<div class="panel">' + empty("An authorization was issued but was not requested in the response.") + "</div>";
  } else {
    html += '<div class="panel"><div class="note">No authorization was issued. A signer that ' +
      "consults TraceSettle will refuse this transaction.</div></div>";
  }

  if (signResult) {
    html += '<div class="panel"><h2>Reference signer</h2><div class="kv">' +
      "<dt>Outcome</dt><dd>" + status(signResult.outcome) + "</dd>" +
      "<dt>Authorization state</dt><dd>" + status(signResult.state) + "</dd>" +
      "<dt>Detail</dt><dd>" + esc(signResult.detail) + "</dd></div>" +
      (signResult.receipt ? '<p class="small muted">' + esc(signResult.receipt.note) +
        ' Execution <code>' + esc(signResult.receipt.execution_id) + "</code>.</p>" : "") +
      "</div>";
  }
  return html;
}
async function submitGuard(ev) {
  ev.preventDefault();
  const out = document.getElementById("guard-result");
  const btn = document.getElementById("g-submit");
  out.innerHTML = loading("Evaluating…");
  btn.disabled = true;
  try {
    const transaction = guardPayload();
    const d = await api("POST", "/api/guard/evaluate",
      { transaction: transaction, return_authorization: true });
    let signResult = null;
    if (d.decision === "ALLOW" && d.authorization) {
      signResult = await api("POST", "/api/guard/sign",
        { transaction: transaction, authorization: d.authorization, expected_service_id: transaction.service_id });
    } else {
      signResult = await api("POST", "/api/guard/sign",
        { transaction: transaction, authorization: d.authorization || null,
          expected_service_id: transaction.service_id });
    }
    out.innerHTML = renderDecision(d, d.authorization, signResult);
    loadOverview();
  } catch (err) {
    out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
  } finally { btn.disabled = false; }
}

/* ---- lab ---- */
/* ---- NEAR agent security ---- */
async function loadNear() {
  const scopeEl = document.getElementById("near-scope");
  const keysEl = document.getElementById("near-keys");
  const attacksEl = document.getElementById("near-attacks");
  scopeEl.innerHTML = loading("Loading policy scope…");
  keysEl.innerHTML = loading("Loading access-key analysis…");
  attacksEl.innerHTML = "";
  loadWallet();
  try {
    const scope = await api("GET", "/api/guard/near/policy-scope");
    const rows = Object.keys(scope.scope).map((name) => {
      const s = scope.scope[name];
      const applicable = (s.applicable_controls || []).map(esc).join(", ") || "none";
      const gap = (s.non_applicable_controls || []).map(esc).join(", ") || "none";
      return '<tr><td>' + esc(name) + '</td><td class="small">' + applicable +
        '</td><td class="small">' + gap + "</td></tr>";
    }).join("");
    scopeEl.innerHTML = '<div class="note sim">' + esc(scope.note) + "</div>" +
      '<table class="table"><thead><tr><th>Path</th><th>Controls that apply</th>' +
      "<th>Controls that do NOT apply</th></tr></thead><tbody>" + rows + "</tbody></table>";
  } catch (err) { scopeEl.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }

  try {
    const keys = await api("GET", "/api/guard/near/access-keys");
    const list = keys.keys || {};
    keysEl.innerHTML = '<div class="note sim">' + esc(keys.note) + "</div>" +
      Object.keys(list).map((name) => {
        const k = list[name];
        return '<div class="card"><h3>' + esc(name) + "</h3>" +
          '<div class="kv small"><dt>Permission</dt><dd>' + esc(k.permission) + "</dd>" +
          "<dt>Risk</dt><dd>" + sev(k.risk) + "</dd>" +
          "<dt>Can transfer NEAR</dt><dd>" + esc(k.can_transfer_near) + "</dd>" +
          "<dt>Can add keys</dt><dd>" + esc(k.can_add_keys) + "</dd>" +
          "<dt>Receiver</dt><dd>" + esc(k.receiver_id || "—") + "</dd>" +
          "<dt>Methods</dt><dd>" + esc((k.method_names || []).join(", ") || "all methods") +
          "</dd></div></div>";
      }).join("");
  } catch (err) { keysEl.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }

  const runBtn = document.getElementById("near-run");
  runBtn.onclick = runNearAttacks;
  const agentDemoBtn = document.getElementById("agent-demo-run");
  if (agentDemoBtn) agentDemoBtn.onclick = runAgentDemo;
  const injBtn = document.getElementById("near-injection-run");
  if (injBtn) injBtn.onclick = runNearInjection;
  loadNearBehaviours();
  document.getElementById("tee-run").onclick = runNearTee;
  document.getElementById("near-eval-legit").onclick = () => evalNear(true);
  document.getElementById("near-eval-attack").onclick = () => evalNear(false);

  const sgEl = document.getElementById("near-safeguards");
  sgEl.innerHTML = loading("Loading safeguards…");
  try {
    const data = await api("GET", "/api/guard/safeguards");
    if (!data.enabled) {
      sgEl.innerHTML = '<div class="note sim">' + esc(data.note) +
        " No safeguard store is configured, so the learning loop is disabled and every decision " +
        "is governed by the operator's policy alone.</div>";
      return;
    }
    const list = data.safeguards || [];
    const rows = list.map((s) =>
      '<tr><td class="mono small">' + esc(s.safeguard_id) + "</td><td>" + esc(s.service_id) +
      '</td><td>' + esc(s.asset || "all assets") + "</td><td>" + esc(s.dimension) +
      "</td><td>" + esc(s.threshold === null ? "—" : s.threshold) + "</td><td>" +
      esc(s.reason_code) + "</td><td>" + esc(String(s.applied_count)) + "</td></tr>"
    ).join("");
    sgEl.innerHTML = '<div class="note">' + esc(data.note) + "</div>" +
      (list.length
        ? '<table class="table"><caption class="small">' + list.length +
          " durable safeguard(s) in force</caption><thead><tr><th>ID</th><th>Service</th>" +
          "<th>Scope</th><th>Dimension</th><th>Threshold</th><th>Reason</th><th>Applied</th>" +
          "</tr></thead><tbody>" + rows + "</tbody></table>"
        : '<p class="small">No safeguard has been learned yet. A security failure will add one.</p>');
  } catch (err) { sgEl.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }

  const encEl = document.getElementById("near-enclave");
  encEl.innerHTML = loading("Loading enclave boundary…");
  try {
    const info = await api("GET", "/api/guard/near/enclave");
    if (!info.enabled) {
      encEl.innerHTML = '<div class="note sim">' + esc(info.note || "Enclave signing is disabled.") + "</div>";
      return;
    }
    const ms = (info.measurements || []).map((m) =>
      '<div class="kv small"><dt>' + esc(m.name) + "</dt><dd class='small mono'>" +
      esc(Object.keys(m.fields || {}).map((k) => k + "=" + m.fields[k]).join(", ") || "—") +
      "</dd></div>").join("");
    encEl.innerHTML = '<div class="card"><div class="kv"><dt>Available</dt><dd>' +
      (info.available ? '<span class="small ok">yes</span>' : '<span class="small bad">no</span>') +
      "</dd><dt>Signing algorithm</dt><dd>" + esc(info.signing_algo) +
      "</dd><dt>Approved measurements</dt><dd>" + esc(String((info.measurements || []).length)) +
      "</dd></div>" + ms + '<div class="note ' + (info.available ? "ok" : "sim") + '">' +
      esc(info.note) + "</div></div>";
  } catch (err) { encEl.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }

  const custEl = document.getElementById("near-custody");
  if (custEl) {
    custEl.innerHTML = loading("Loading custody evidence…");
    try {
      const info = await api("GET", "/api/guard/near/custody");
      const states = (info.evidence_states || []).join(" → ");
      custEl.innerHTML = '<div class="card"><div class="kv">' +
        "<dt>Custody boundary</dt><dd>" + (info.enabled ? "enabled" : "disabled") + "</dd>" +
        "<dt>Per-operation attestation</dt><dd>" +
        (info.per_operation_attestation
          ? '<span class="small bad">' + esc(info.per_operation_attestation) + "</span>"
          : '<span class="small">n/a</span>') +
        "</dd></div>" +
        (states ? '<p class="small mono">' + esc(states) + "</p>" : "") +
        '<div class="note sim">' +
        esc(info.attestation_note || info.note || "Custody evidence is not available.") + "</div></div>";
    } catch (err) { custEl.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
  }
}

async function runNearAttacks() {
  const el = document.getElementById("near-attacks");
  el.innerHTML = loading("Running nine scenarios…");
  try {
    const data = await api("GET", "/api/guard/near/scenarios");
    el.innerHTML = '<div class="note sim">' + esc(data.note) + "</div>" +
      data.results.map((r) => {
        const cls = r.passed ? "s-ALLOW" : "s-BLOCK";
        return '<div class="card"><h3>' + esc(r.scenario_id) + ". " + esc(r.title) + "</h3>" +
          '<div class="kv small"><dt>Expected</dt><dd class="small">' + esc(r.expected) + "</dd>" +
          "<dt>Observed</dt><dd>" + status(r.observed) + "</dd>" +
          '<dt>Detail</dt><dd class="small">' + esc(r.detail) + "</dd></div>" +
          '<div class="small ' + cls + '">' + (r.passed ? "PASS" : "FAIL") + "</div></div>";
      }).join("") +
      '<div class="note ' + (data.all_passed ? "ok" : "bad") + '">' +
      esc((data.all_passed ? "All scenarios matched expectation" : "A scenario did not match")) +
      "</div>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function runAgentDemo() {
  const el = document.getElementById("agent-demo-output");
  el.innerHTML = loading("Running the end-to-end demonstration…");
  try {
    const data = await api("GET", "/api/guard/near/agent-demo");
    const card = (label, r) => {
      const ver = r.verification || {};
      return '<div class="card"><h3>' + esc(label) + " — " + status(r.decision) + "</h3>" +
        '<div class="kv small"><dt>Proposed receiver</dt><dd class="mono small">' +
        esc(r.proposed_receiver) + "</dd>" +
        "<dt>Amount</dt><dd class='small'>" + esc(r.proposed_amount) + " NEAR</dd>" +
        "<dt>Signer invocations</dt><dd class='small'>" + esc(String(r.signer_calls)) + "</dd>" +
        "<dt>Signed</dt><dd class='small'>" + esc(String(r.signed)) + "</dd>" +
        "<dt>Broadcast</dt><dd class='small'>" + esc(String(r.broadcast_occurred)) + "</dd>" +
        "<dt>Settlement</dt><dd>" + status(r.settlement_state) + "</dd>" +
        "<dt>Verification</dt><dd class='small'>" + esc(ver.state || "—") + "</dd></div>" +
        (r.reasons && r.reasons.length
          ? '<ul class="small">' + r.reasons.map((x) => "<li>" + esc(x) + "</li>").join("") + "</ul>"
          : "") +
        '<div class="kv small"><dt>Bound to exact bytes</dt><dd class="mono small">' +
        esc((r.authorization_binding || {}).transaction_digest || "—") +
        "</dd><dt>Signed-bytes digest</dt><dd class='mono small'>" +
        esc(r.signed_bytes_digest || "—") + "</dd></div></div>";
    };
    const ok = data.reproduced;
    el.innerHTML = '<div class="note sim">' + esc(data.note) + "</div>" +
      '<div class="note ' + (ok ? "ok" : "bad") + '">' +
      esc(ok
        ? "Reproduced: the injected redirect was blocked before signing and the approved " +
          "payment was verified after settling."
        : "The run did not reproduce the expected outcome.") + "</div>" +
      '<div class="grid two">' +
      card("Injected redirect (attacker)", data.malicious) +
      card("Approved payment", data.legitimate) + "</div>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function loadNearBehaviours() {
  const el = document.getElementById("near-behaviours");
  if (!el) return;
  el.innerHTML = loading("Running the six behaviours…");
  try {
    const data = await api("GET", "/api/guard/near/behaviours");
    el.innerHTML = '<div class="note sim">' + esc(data.note) + "</div>" +
      (data.behaviours || []).map((b) => {
        const cls = b.held ? "s-ALLOW" : "s-BLOCK";
        return '<div class="card"><h3>' + esc(b.name) + " — " + esc(b.title) + "</h3>" +
          '<div class="kv small"><dt>Expected</dt><dd class="small">' + esc(b.expected) + "</dd>" +
          "<dt>Observed</dt><dd class='small'>" + esc(b.observed) + "</dd>" +
          "<dt>Detail</dt><dd class='small'>" + esc(b.detail) + "</dd></div>" +
          '<div class="small ' + cls + '">' + (b.held ? "HOLDS" : "DID NOT HOLD") + "</div></div>";
      }).join("") +
      '<div class="note ' + (data.all_held ? "ok" : "bad") + '">' +
      esc(data.all_held ? "All six behaviours held" : "A behaviour did not hold") + "</div>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function runNearInjection() {
  const el = document.getElementById("near-injection");
  el.innerHTML = loading("Running the prompt-injection demo…");
  try {
    const data = await api("GET", "/api/guard/near/prompt-injection");
    const a = data.audit || {};
    el.innerHTML = '<div class="note sim">' + esc(data.note) + "</div>" +
      '<div class="card"><h3>Agent instruction (untrusted)</h3>' +
      '<p class="small mono">' + esc(a.injection_text || "") + "</p></div>" +
      '<div class="card"><h3>What the guard actually evaluated</h3>' +
      '<div class="kv small"><dt>Requested receiver</dt><dd class="mono small">' +
      esc(a.actual_receiver || "") + "</dd>" +
      "<dt>Approved destinations</dt><dd class='mono small'>" +
      esc((a.approved_destinations || []).join(", ")) + "</dd>" +
      "<dt>Amount</dt><dd class='small'>" + esc(a.amount || "") + " " + esc(a.asset || "") + "</dd>" +
      "<dt>Decision</dt><dd>" + status(a.authorization_result) + "</dd>" +
      "<dt>Signed</dt><dd>" + esc(String(a.signed)) + "</dd>" +
      "<dt>Broadcast</dt><dd>" + esc(String(a.broadcast_occurred)) + "</dd></div></div>" +
      '<div class="card"><h3>Why it was refused</h3><ul class="small">' +
      (a.rejection_reasons || []).map((r) => "<li>" + esc(r) + "</li>").join("") +
      "</ul></div>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function runNearTee() {
  const el = document.getElementById("near-tee");
  el.innerHTML = loading("Fetching and verifying the gateway quote…");
  try {
    const info = await api("GET", "/api/guard/near/tee");
    if (!info.enabled) {
      el.innerHTML = '<div class="note sim">' + esc(info.note || "TEE attestation is disabled.") + "</div>";
      return;
    }
    const r = await api("GET", "/api/guard/near/tee/attest?transaction_fingerprint=" +
      encodeURIComponent("console-demo"));
    const checks = r.verification && r.verification.checks ? r.verification.checks : {};
    const rows = Object.keys(checks).map((k) =>
      "<dt>" + esc(k) + "</dt><dd>" + (checks[k] ? '<span class="small ok">pass</span>'
        : '<span class="small bad">fail</span>') + "</dd>").join("");
    el.innerHTML = '<div class="card"><div class="kv"><dt>Status</dt><dd>' +
      status(r.status) + "</dd><dt>Verified</dt><dd>" + esc(r.verified) +
      "</dd><dt>Signing address</dt><dd class='small'>" + esc(r.signing_address || "") +
      "</dd><dt>Pinned root</dt><dd class='small'>" + esc(r.intel_root_fingerprint || "") +
      "</dd></div><div class='kv small'>" + rows + "</div>" +
      '<div class="note ' + (r.verified ? "ok" : "bad") + '">' +
      esc(r.verified ? "The quote is genuine hardware attestation, verified locally." :
        "The quote did not verify; no protection is claimed.") + "</div></div>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function evalNear(approved) {
  const out = document.getElementById("near-eval-output");
  out.innerHTML = loading("Evaluating…");
  const transaction = {
    service_id: "treasury-agent",
    operation: "WITHDRAWAL",
    chain: "base",
    asset: "USDC",
    amount: "1250.50",
    destination: approved ? "0x4e6d3a556e485188e9c9a528bc72c88bd92bd735"
      : "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    scope: "INTENTS",
    policy_action: "withdraw",
  };
  try {
    const d = await api("POST", "/api/guard/near/agent-evaluate", { transaction: transaction });
    out.innerHTML = '<div class="card"><div class="kv"><dt>Outcome</dt><dd>' + status(d.outcome) +
      "</dd><dt>Permits signing</dt><dd>" + esc(d.permits_signing) +
      '</dd><dt>Summary</dt><dd class="small">' + esc(d.summary) + "</dd></div>" +
      '<div class="small">Findings: ' +
      esc((d.findings || []).map((f) => f.code).join(", ")) + "</div></div>";
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

/* ---- NEAR wallet-mediated flow (the connected wallet signs and sends) ---- */
const WALLET = { connector: null, accountId: null, info: null, network: "testnet" };

async function loadWallet() {
  const connectEl = document.getElementById("wallet-connect");
  const out = document.getElementById("wallet-output");
  const sendBtn = document.getElementById("w-send");
  out.innerHTML = "";
  hideWalletPreview();
  let info;
  try {
    info = await api("GET", "/api/guard/near/wallet");
  } catch (err) {
    connectEl.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
    return;
  }
  WALLET.info = info;
  if (!info.enabled) {
    connectEl.innerHTML = '<div class="note sim">' +
      esc(info.note || "The NEAR wallet flow is disabled on this server.") + "</div>";
    sendBtn.disabled = true;
    return;
  }
  if (!window.TraceSettleWallet) {
    connectEl.innerHTML = '<div class="note bad">The bundled wallet connector did not load, ' +
      "so a wallet cannot be connected from this page.</div>";
    sendBtn.disabled = true;
    return;
  }
  const network = info.network || "testnet";
  WALLET.network = network;
  populateWalletAssets(info.supported_assets || []);
  connectEl.innerHTML =
    '<div class="actions"><button class="act primary" type="button" id="w-connect">Connect wallet</button>' +
    '<button class="act" type="button" id="w-disconnect" hidden>Disconnect</button>' +
    '<span id="w-account" class="small muted" style="margin-left:10px">not connected</span></div>' +
    '<div class="small muted" style="margin-top:8px">Network: ' + esc(network) +
    ". The wallet signs and sends; this server authorizes and independently verifies.</div>";
  document.getElementById("w-connect").onclick = () => connectWallet(network);
  document.getElementById("w-disconnect").onclick = () => disconnectWallet();
  sendBtn.onclick = sendWalletOperation;
  // A live preview of what will be authorized, so the exact parameters are
  // visible before the wallet is ever asked to sign.
  ["w-receiver", "w-amount", "w-asset"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) { el.addEventListener("input", renderWalletPreview); el.addEventListener("change", renderWalletPreview); }
  });
  renderWalletPreview();
}

function populateWalletAssets(assets) {
  const sel = document.getElementById("w-asset");
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = assets.length
    ? assets.map((a) => '<option value="' + esc(a.identifier) + '">' + esc(a.symbol) +
        " — " + esc(a.name || a.identifier) + " (" + esc(a.decimals) + " decimals)</option>").join("")
    : '<option value="near:native">NEAR (native)</option>';
  if (current) {
    for (const opt of sel.options) { if (opt.value === current) { sel.value = current; break; } }
  }
}

function currentWalletSelection() {
  const assetEl = document.getElementById("w-asset");
  const receiverEl = document.getElementById("w-receiver");
  const amountEl = document.getElementById("w-amount");
  return {
    asset: assetEl ? assetEl.value : "near:native",
    assetLabel: assetEl && assetEl.selectedOptions.length ? assetEl.selectedOptions[0].textContent : "NEAR",
    receiver: receiverEl ? receiverEl.value.trim() : "",
    amount: amountEl ? amountEl.value.trim() : "",
  };
}

function hideWalletPreview() {
  const el = document.getElementById("w-preview");
  if (el) { el.hidden = true; el.innerHTML = ""; }
}

function renderWalletPreview() {
  const el = document.getElementById("w-preview");
  if (!el) return;
  const sel = currentWalletSelection();
  if (!sel.receiver && !sel.amount) { hideWalletPreview(); return; }
  el.hidden = false;
  el.innerHTML =
    '<div class="small muted">This is what TraceSettle will evaluate and, if allowed, ' +
    "bind to the authorization. The wallet then signs exactly this.</div>" +
    '<dl class="kv"><dt>Asset</dt><dd>' + esc(sel.assetLabel) + "</dd>" +
    '<dt>Recipient</dt><dd class="mono small">' + esc(sel.receiver || "—") + "</dd>" +
    "<dt>Amount</dt><dd>" + esc(sel.amount || "—") + "</dd>" +
    "<dt>Network</dt><dd>" + esc(WALLET.network) + "</dd></dl>";
}

async function connectWallet(network) {
  const accountEl = document.getElementById("w-account");
  accountEl.textContent = "connecting…";
  try {
    if (!WALLET.connector) {
      WALLET.connector = new window.TraceSettleWallet.NearConnector({ network: network });
      // The connector can move between wallets/accounts; the approved account
      // must always be the one the wallet is currently reporting, or an
      // authorization could be bound to a stale identity.
      WALLET.connector.on("wallet:signIn", (t) => {
        const accounts = (t && t.accounts) || [];
        setWalletAccount(accounts.length ? accounts[0].accountId : null);
      });
      WALLET.connector.on("wallet:signOut", () => setWalletAccount(null));
      WALLET.connector.on("selector:walletsChanged", () => { refreshWalletAccount(); });
    }
    await WALLET.connector.connect();
    if (!WALLET.accountId) { await refreshWalletAccount(); }
    setWalletAccount(WALLET.accountId);
  } catch (err) {
    accountEl.textContent = "connection failed";
    document.getElementById("wallet-output").innerHTML =
      '<div class="note bad">' + esc(err && err.message ? err.message : String(err)) + "</div>";
  }
}

async function refreshWalletAccount() {
  if (!WALLET.connector) return;
  try {
    const connected = await WALLET.connector.getConnectedWallet();
    if (connected && connected.accounts && connected.accounts.length) {
      WALLET.accountId = connected.accounts[0].accountId;
    }
  } catch (ignore) { /* no restored session */ }
}

function setWalletAccount(accountId) {
  WALLET.accountId = accountId || null;
  const accountEl = document.getElementById("w-account");
  const sendBtn = document.getElementById("w-send");
  const disconnectBtn = document.getElementById("w-disconnect");
  const connectBtn = document.getElementById("w-connect");
  if (accountEl) accountEl.textContent = WALLET.accountId || "not connected";
  if (sendBtn) sendBtn.disabled = !WALLET.accountId;
  if (disconnectBtn) disconnectBtn.hidden = !WALLET.accountId;
  if (connectBtn) connectBtn.hidden = !!WALLET.accountId;
}

async function disconnectWallet() {
  try {
    if (WALLET.connector && typeof WALLET.connector.disconnect === "function") {
      await WALLET.connector.disconnect();
    }
  } catch (ignore) { /* the session is being discarded regardless */ }
  setWalletAccount(null);
  hideWalletPreview();
  const out = document.getElementById("wallet-output");
  if (out) out.innerHTML = "";
}

async function sendWalletOperation() {
  const out = document.getElementById("wallet-output");
  const sendBtn = document.getElementById("w-send");
  if (!WALLET.accountId || !WALLET.connector) {
    out.innerHTML = '<div class="note bad">Connect a wallet first.</div>';
    return;
  }
  const sel = currentWalletSelection();
  if (!sel.receiver || !sel.amount) {
    out.innerHTML = '<div class="note bad">A recipient and an amount are required.</div>';
    return;
  }
  sendBtn.disabled = true;
  out.innerHTML = loading("Authorizing the operation against policy…");
  try {
    const prepared = await api("POST", "/api/guard/near/wallet/prepare", {
      service_id: "treasury-agent",
      account_id: WALLET.accountId,
      receiver_id: sel.receiver,
      asset: sel.asset,
      amount: sel.amount,
    });
    const decision = (prepared.decision || {}).decision || "UNKNOWN";
    if (!prepared.authorized) {
      out.innerHTML = '<div class="card"><div class="kv"><dt>Authorization</dt><dd>' +
        status(decision) + "</dd></div>" +
        '<div class="small">The operation was not authorized, so nothing is sent to the wallet. ' +
        "No authorization means nothing to sign.</div>" + decisionFindings(prepared.decision) + "</div>";
      return;
    }
    const confirmed = await confirmWalletOperation(prepared);
    if (!confirmed) {
      out.innerHTML = '<div class="note sim">Nothing was sent. The wallet was not asked to sign, ' +
        "and the authorization expires unused.</div>";
      return;
    }
    out.innerHTML = '<div class="card"><div class="kv"><dt>Authorization</dt><dd>' + status("ALLOW") +
      "</dd><dt>Amount</dt><dd>" + esc(prepared.amount_human) + "</dd>" +
      '<dt>Recipient</dt><dd class="mono small">' + esc(prepared.destination) + "</dd></div>" +
      '<div class="small">The wallet will now ask you to approve this exact transfer. ' +
      "The authorization is bound to these parameters.</div></div>" +
      loading("Waiting for the wallet to sign and send…");
    let outcome;
    try {
      const wallet = await WALLET.connector.wallet();
      outcome = await wallet.signAndSendTransaction(prepared.wallet_request);
    } catch (werr) {
      out.innerHTML = '<div class="note bad">The wallet did not send the transaction: ' +
        esc(werr && werr.message ? werr.message : String(werr)) + "</div>";
      return;
    }
    const txHash = extractTxHash(outcome);
    if (!txHash) {
      out.innerHTML = '<div class="note bad">The wallet returned no transaction hash, ' +
        "so settlement cannot be independently verified.</div>";
      return;
    }
    out.innerHTML = loading("Verifying settlement against the on-chain record…");
    const verified = await api("POST", "/api/guard/near/wallet/verify", {
      prepare_id: prepared.prepare_id,
      tx_hash: txHash,
    });
    out.innerHTML = renderWalletVerification(verified);
  } catch (err) {
    out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
  } finally {
    sendBtn.disabled = !WALLET.accountId;
  }
}

/* A blocking confirmation of the exact parameters, shown after the server has
   authorized and before the wallet is asked to sign. It never replaces the
   server-side decision; it is a last human check on what will be signed. */
function confirmWalletOperation(prepared) {
  const asset = (prepared.asset && (prepared.asset.symbol || prepared.asset.identifier)) || "";
  const message = `Authorize and send this transfer?

Amount:    ${prepared.amount_human} ${asset}
Recipient: ${prepared.destination}
Network:   ${prepared.network || WALLET.network}

The wallet will sign exactly these parameters.`;
  return Promise.resolve(window.confirm(message));
}

function extractTxHash(outcome) {
  if (!outcome) return null;
  if (outcome.transaction && outcome.transaction.hash) return outcome.transaction.hash;
  if (outcome.transaction_outcome && outcome.transaction_outcome.id) return outcome.transaction_outcome.id;
  return null;
}

function decisionFindings(decision) {
  const list = (decision && decision.findings) || [];
  if (!list.length) return "";
  return '<div class="small">Findings: ' + esc(list.map((f) => f.code).join(", ")) + "</div>";
}

function renderWalletVerification(verified) {
  const v = verified.verification || {};
  const checks = (v.checks || []).map((c) =>
    "<tr><td>" + esc(c.name) + '</td><td class="' + (c.ok ? "s-ALLOW" : "s-BLOCK") + '">' +
    (c.ok ? "pass" : "fail") + '</td><td class="small">' + esc(c.detail) + "</td></tr>").join("");
  const explorer = (WALLET.info && WALLET.info.explorer) || {};
  const base = explorer[WALLET.info && WALLET.info.network] || "";
  return '<div class="card"><div class="kv"><dt>Settlement</dt><dd>' + status(v.state) +
    '</dd><dt>Transaction</dt><dd class="mono small">' + esc(verified.tx_hash) + "</dd>" +
    '<dt>Independent evidence</dt><dd class="small">' + esc(v.note || "") + "</dd></div>" +
    (base ? '<div class="small"><a href="' + esc(base + verified.tx_hash) +
      '" target="_blank" rel="noopener noreferrer">View the transaction on the explorer</a></div>' : "") +
    '<table class="table"><caption class="small">Checks performed on the on-chain record</caption>' +
    "<thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>" + checks +
    "</tbody></table>" +
    '<div class="small muted">The wallet success message is not evidence. The state above comes ' +
    "from the on-chain record, checked field by field against the authorized intent.</div></div>";
}

/* ---- NEAR Intents lifecycle ---- */
let IN = { intentId: null, busy: false, idemKey: null };

async function loadIntents() {
  const out = document.getElementById("intents-create-output");
  out.innerHTML = "";
  // The submit control is bound once, through the form's submit event only.
  // Binding both an onclick on the button and an onsubmit on the form made a
  // single click create two intents (two POSTs) — a real duplicate-submission bug.
  document.getElementById("intents-create").onsubmit = (e) => { e.preventDefault(); createIntent(); };
  // A durable record must be actionable after a reload, so the list is a resume
  // affordance: the click handler lives on the container, which survives the
  // innerHTML rewrite the render performs.
  document.getElementById("intents-create-output").onclick = onIntentListClick;
  const list = await api("GET", "/api/guard/near/lifecycle");
  document.getElementById("i-dry-quote").onclick = () => stepIntent("quote", { dry: true }, "intents-step-output");
  document.getElementById("i-live-quote").onclick = () => stepIntent("quote", { dry: false }, "intents-step-output");
  document.getElementById("i-status").onclick = () => stepIntent("status", {}, "intents-assurance-output");
  document.getElementById("i-verify-origin").onclick = () => stepIntent("verify-origin", {}, "intents-assurance-output");
  document.getElementById("i-verify-destination").onclick = () => stepIntent("verify-destination", {}, "intents-assurance-output");
  document.getElementById("i-assurance").onclick = () => stepIntent("assurance", {}, "intents-assurance-output");
  document.getElementById("i-list").onclick = listIntents;
  document.getElementById("i-tokens").onclick = loadTokens;
  document.getElementById("i-deposit").onclick = recordDeposit;
  document.getElementById("i-approve").onclick = () => decideQuote(true);
  document.getElementById("i-reject").onclick = () => decideQuote(false);
  if (list && list.intents && list.intents.length) {
    out.innerHTML = renderIntentResumeList(list.intents);
  }
}

function intentFormPayload() {
  return {
    service_id: document.getElementById("i-service").value,
    operation: document.getElementById("i-op").value,
    chain: document.getElementById("i-chain").value,
    asset: document.getElementById("i-asset").value,
    amount: document.getElementById("i-amount").value,
    origin_asset: document.getElementById("i-origin").value,
    destination_asset: document.getElementById("i-dest").value,
    recipient: document.getElementById("i-recipient").value,
    refund_to: document.getElementById("i-recipient").value,
    scope: "INTENTS",
  };
}

async function createIntent() {
  const out = document.getElementById("intents-create-output");
  const submit = document.getElementById("i-submit");
  if (IN.busy) return;
  IN.busy = true;
  if (submit) submit.disabled = true;
  // The idempotency key is derived from the exact transaction parameters, so a
  // double click, a retry, or a resend of the *same* transaction resolves to one
  // intent on the server. Changing any field is a new transaction with a new key.
  const payload = intentFormPayload();
  IN.idemKey = await payloadKey(payload);
  out.innerHTML = loading("Authorizing…");
  try {
    const data = await api("POST", "/api/guard/near/lifecycle", {
      transaction: payload,
      idempotency_key: IN.idemKey,
    });
    IN.intentId = data.intent_id;
    const d = data.decision || {};
    out.innerHTML = '<div class="card"><h3>Intent ' + esc(data.intent_id) + "</h3>" +
      '<div class="kv"><dt>Outcome</dt><dd>' + status(d.outcome) +
      "</dd><dt>Permits signing</dt><dd>" + esc(data.permits_signing) +
      "</dd><dt>State</dt><dd>" + esc(data.state) +
      '</dd><dt>Summary</dt><dd class="small">' + esc(d.summary || "") + "</dd></div></div>" +
      (data.created === false ? '<div class="note">This is the same transaction as an existing intent; no duplicate was created.</div>' : "");
    // Surface the durable list again so this intent is resumable after a reload.
    try {
      const list = await api("GET", "/api/guard/near/lifecycle");
      if (list && list.intents && list.intents.length) out.innerHTML += renderIntentResumeList(list.intents);
    } catch (e) { /* the decision card already rendered; the list is a convenience */ }
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
  finally { IN.busy = false; if (submit) submit.disabled = false; }
}

async function payloadKey(payload) {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return "ui-" + Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
  } catch (e) {
    // crypto.subtle needs a secure context; the loopback console is one, but fall
    // back to a deterministic string so a non-secure context still deduplicates.
    let h = 0;
    for (let i = 0; i < canonical.length; i++) { h = (h * 31 + canonical.charCodeAt(i)) | 0; }
    return "ui-fallback-" + (h >>> 0).toString(16);
  }
}

async function stepIntent(action, body, targetId) {
  const out = document.getElementById(targetId || "intents-step-output");
  if (!IN.intentId) { out.innerHTML = '<div class="note bad">Create an intent first.</div>'; return; }
  if (IN.busy) return;
  IN.busy = true;
  out.innerHTML = loading("Running " + action + "…");
  try {
    const data = await api("POST", "/api/guard/near/lifecycle/" + IN.intentId + "/" + action, body || {});
    if (action === "quote" && data.ok && data.deposit_address) {
      renderHandoff(data);
      const exp = data.expiry || {};
      out.innerHTML = '<div class="card"><h3>Live quote</h3>' +
        '<p class="small">Review the amounts and the expiry below, then approve or reject.</p>' +
        '<div class="kv"><dt>Expiry</dt><dd>' + status(exp.usable ? "VALID" : (exp.reason || "BLOCK")) +
        " " + esc(exp.detail || "") + "</dd></div>" +
        '<pre class="small">' + esc(JSON.stringify(data, null, 2)) + "</pre></div>";
    } else if (action === "status") {
      out.innerHTML = renderLifecycleStatus(data);
    } else if (action === "verify-origin") {
      out.innerHTML = renderOriginVerification(data);
    } else if (action === "verify-destination") {
      out.innerHTML = renderDestinationVerification(data);
    } else if (action === "assurance") {
      out.innerHTML = renderAssurance(data);
    } else {
      out.innerHTML = '<div class="card"><h3>' + esc(action) + "</h3>" +
        '<pre class="small">' + esc(JSON.stringify(data, null, 2)) + "</pre></div>";
    }
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
  finally { IN.busy = false; }
}

/* ---- wallet handoff: the user funds the deposit address themselves ---- */
function renderHandoff(data) {
  const host = document.getElementById("i-handoff");
  const wrap = document.getElementById("i-deposit-form-wrap");
  const q = data.quote || {};
  const fees = [
    ["Amount in", q.amount_in_formatted != null ? q.amount_in_formatted : "—"],
    ["Expected amount out", q.amount_out_formatted != null ? q.amount_out_formatted : "—"],
    ["Minimum received", q.min_amount_out != null ? q.min_amount_out : "—"],
    ["Withdraw fee (base units)", q.withdraw_fee != null ? q.withdraw_fee : "—"],
    ["Refund fee (base units)", q.refund_fee != null ? q.refund_fee : "—"],
    ["Estimated time", q.time_estimate != null ? (q.time_estimate + " s") : "—"],
    ["Quote expires", q.deadline != null ? q.deadline : "not stated by the provider"],
  ].map(function (r) { return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>"; }).join("");
  host.innerHTML = '<div class="card"><h3>Fund this deposit address</h3>' +
    '<p class="small">Send the quoted amount from your own wallet to this address. This product never signs, ' +
    'sends, or holds funds — the transfer is yours.</p>' +
    '<div class="kv"><dt>Deposit address</dt><dd><code class="mono" id="i-deposit-address">' + esc(data.deposit_address) + "</code> " +
    '<button class="act" type="button" id="i-copy" style="padding:2px 8px">Copy</button></dd>' +
    (data.deposit_memo ? '<dt>Deposit memo</dt><dd><code class="mono">' + esc(data.deposit_memo) + "</code></dd>" : "") +
    "</div>" +
    '<p class="small muted">Copy the address exactly. After you send the transfer, paste its transaction hash below ' +
    'so the provider can pre-verify the deposit.</p>' +
    '<div class="kv">' + fees + "</div></div>";
  const copy = document.getElementById("i-copy");
  if (copy) copy.onclick = function () {
    const text = data.deposit_address;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { copy.textContent = "Copied"; },
        function () { copy.textContent = "Select above"; });
    } else { copy.textContent = "Select above"; }
  };
  // A live quote must be explicitly approved before a deposit can be recorded.
  const approveWrap = document.getElementById("i-approve-wrap");
  if (approveWrap) approveWrap.hidden = false;
  const depositWrap = document.getElementById("i-deposit-form-wrap");
  if (depositWrap) depositWrap.hidden = true;
  if (wrap) wrap.hidden = true;
}

/* ---- status and assurance: plain language, not raw JSON ---- */
function renderLifecycleStatus(data) {
  const s = data.status || data.provider_status || "UNKNOWN";
  const st = data.state || "";
  const rows = [];
  rows.push(["Provider status", status(String(s).toUpperCase())]);
  if (st) rows.push(["Lifecycle state", status(st)]);
  if (data.deposit_address) rows.push(["Deposit address", "<code>" + esc(data.deposit_address) + "</code>"]);
  if (data.deposit_tx_hash) rows.push(["Recorded deposit hash", "<code>" + esc(data.deposit_tx_hash) + "</code>"]);
  if (data.quote_approved != null) rows.push(["Quote approved", data.quote_approved ? "Yes" : "No"]);
  const ov = (data.lifecycle && data.lifecycle.origin_verification) || data.origin_verification;
  if (ov) rows.push(["Origin-chain deposit check", status(ov.level || "UNKNOWN")]);
  const dv = (data.lifecycle && data.lifecycle.destination_verification) || data.destination_verification;
  if (dv) rows.push(["Destination-chain delivery check", status(dv.level || "UNKNOWN")]);
  if (data.updated_at) rows.push(["Observed", fmtAt(data.updated_at)]);
  return '<div class="card"><h3>Provider status</h3>' +
    '<p class="small muted">This is what the provider reports. A provider success is not proof that ' +
    "funds reached their destination — run Settlement assurance for that.</p>" +
    '<div class="kv">' + rows.map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + v + "</dd>").join("") +
    "</div></div>";
}

function renderOriginVerification(data) {
  const v = data.origin_verification || data;
  const level = v.level || "UNKNOWN";
  const headlines = {
    VERIFIED: "Independently verified on the origin chain: the transaction succeeded and pays the deposit address.",
    UNCONFIRMED: "Found, but a required check did not hold — insufficient evidence, not a failure.",
    CONTRADICTORY: "Confirmed to be something other than this deposit (a revert, or a different recipient).",
    NOT_FOUND: "The claimed hash is not present on the origin chain — a missing record, not proof of failure.",
    UNAVAILABLE: "The origin chain could not be queried, so the claim was not checked.",
    UNSUPPORTED: "No public source is configured for this origin chain, so the claim cannot be checked here.",
  };
  const checks = v.checks || {};
  const rows = Object.keys(checks).map((k) =>
    "<dt>" + esc(k) + '</dt><dd><code class="mono">' + esc(JSON.stringify(checks[k])) + "</code></dd>").join("");
  return '<div class="card"><h3>Origin-chain deposit check</h3>' +
    '<div class="kv"><dt>Verdict</dt><dd>' + status(level) +
    "</dd><dt>Chain</dt><dd>" + esc(v.chain || "—") +
    "</dd><dt>Transaction</dt><dd>" + (v.evidence_url
      ? '<a href="' + esc(v.evidence_url) + '" rel="noopener noreferrer" target="_blank"><code class="mono">' + esc(v.tx_hash || "") + "</code></a>"
      : '<code class="mono">' + esc(v.tx_hash || "") + "</code>") +
    "</dd></div>" +
    '<p class="small">' + esc(headlines[level] || v.summary || "") + "</p>" +
    (v.summary && headlines[level] ? '<p class="small muted">' + esc(v.summary) + "</p>" : "") +
    (rows ? '<details><summary class="small">Checks performed</summary><div class="kv">' + rows + "</div></details>" : "") +
    ((v.limitations || []).length
      ? '<ul class="small muted">' + v.limitations.map((l) => "<li>" + esc(l) + "</li>").join("") + "</ul>" : "") +
    "</div>";
}

function renderDestinationVerification(data) {
  const v = data.destination_verification || data;
  const level = v.level || "UNKNOWN";
  const headlines = {
    VERIFIED: "Independently verified on the destination chain: the transaction succeeded and transferred the expected asset to the intended recipient.",
    UNCONFIRMED: "Found, but a required check did not hold (not yet final, or an amount that differs) — insufficient evidence, not a failure.",
    CONTRADICTORY: "Confirmed to be something other than this delivery (a revert, a different recipient, or a different token).",
    NOT_FOUND: "The claimed hash is not present on the destination chain — a missing record, not proof of failure.",
    UNAVAILABLE: "The destination chain could not be queried, so the claim was not checked.",
    UNSUPPORTED: "No public source is configured for this destination chain, so the claim cannot be checked here.",
  };
  const checks = v.checks || {};
  const rows = Object.keys(checks).map((k) =>
    "<dt>" + esc(k) + '</dt><dd><code class="mono">' + esc(JSON.stringify(checks[k])) + "</code></dd>").join("");
  return '<div class="card"><h3>Destination-chain delivery check</h3>' +
    '<div class="kv"><dt>Verdict</dt><dd>' + status(level) +
    "</dd><dt>Chain</dt><dd>" + esc(v.chain || "—") +
    "</dd><dt>Transaction</dt><dd>" + (v.evidence_url
      ? '<a href="' + esc(v.evidence_url) + '" rel="noopener noreferrer" target="_blank"><code class="mono">' + esc(v.tx_hash || "") + "</code></a>"
      : '<code class="mono">' + esc(v.tx_hash || "") + "</code>") +
    "</dd></div>" +
    '<p class="small">' + esc(headlines[level] || v.summary || "") + "</p>" +
    (v.summary && headlines[level] ? '<p class="small muted">' + esc(v.summary) + "</p>" : "") +
    (rows ? '<details><summary class="small">Checks performed</summary><div class="kv">' + rows + "</div></details>" : "") +
    ((v.limitations || []).length
      ? '<ul class="small muted">' + v.limitations.map((l) => "<li>" + esc(l) + "</li>").join("") + "</ul>" : "") +
    "</div>";
}

function renderAssurance(data) {
  const a = data.assurance || data;
  const level = a.level || "UNKNOWN";
  const verified = a.independently_verified === true;
  const stages = a.stages || [];
  const headlines = {
    SETTLEMENT_VERIFIED: "Settlement verified — the origin deposit and the destination delivery are both independently confirmed.",
    DESTINATION_DELIVERY_VERIFIED: "Destination delivery verified — the destination leg is confirmed; the origin deposit was not independently confirmed.",
    ORIGIN_DEPOSIT_VERIFIED: "Origin deposit verified — the origin leg is confirmed; the destination delivery is not yet verified.",
    REFUNDED: "Refund independently confirmed on-chain — the funds came back, not to the destination.",
    FAILED: "Failed: decisive evidence independently establishes the transaction did not complete.",
    PARTIAL: "Partial: the destination is confirmed but received less than the quote expected.",
    PENDING: "Pending: the deposit is confirmed and the swap is still progressing.",
    REPORTED_ONLY: "Reported only — the provider's claim is not independently confirmed.",
    CONTRADICTORY: "Contradictory: independent sources disagree; the conflict is preserved.",
    UNAVAILABLE: "Unavailable: the evidence sources could not be reached, so no conclusion is made.",
    UNKNOWN: "Unknown: the available evidence does not establish the outcome.",
  };
  const headline = headlines[level] ||
    "Not independently verified — the provider's report alone does not establish receipt.";
  const evidence = (a.evidence || []);
  const byId = {};
  evidence.forEach((e) => { byId[e.id] = e; });
  const basisCell = (ids) => {
    if (!ids || !ids.length) return '<span class="muted">—</span>';
    return ids.map((id) => {
      const e = byId[id];
      const label = e ? (e.source + " " + (e.event_type || "")) : id;
      const url = e && e.evidence_url;
      return url ? '<a href="' + esc(url) + '" rel="noopener noreferrer" target="_blank">' + esc(label) + "</a>" : esc(label);
    }).join("<br>");
  };
  let html = '<div class="card"><h3>Settlement assurance</h3>' +
    '<div class="kv"><dt>Level</dt><dd>' + status(level) + "</dd>" +
    "<dt>Independently verified</dt><dd>" + (verified ? "Yes" : "No") + "</dd></div>" +
    '<p class="small ' + (verified ? "muted" : "") + '">' + esc(headline) + "</p>" +
    (a.summary ? '<p class="small muted">' + esc(a.summary) + "</p>" : "") +
    (a.conflicting_evidence && a.conflicting_evidence.length
      ? '<div class="note bad">Conflicting evidence: ' +
        a.conflicting_evidence.map(esc).join("; ") + "</div>" : "") +
    (a.shortfall && a.shortfall !== "0"
      ? '<div class="note">Shortfall vs the quote: ' + esc(a.shortfall) + " base units.</div>" : "") +
    (stages.length ? "<table><thead><tr><th>Stage</th><th>State</th><th>Basis</th><th>Independent evidence</th></tr></thead><tbody>" +
      stages.map((x) => "<tr><td>" + esc(x.name || x.stage || "") + "</td><td>" +
        status(x.state || x.classification || "UNKNOWN") + '</td><td class="small wrap">' +
        esc(x.detail || x.basis || "") + '</td><td class="small">' +
        basisCell(x.supporting_evidence_ids) + "</td></tr>").join("") + "</tbody></table>" : "");
  if (evidence.length) {
    const simulated = evidence.some((e) => e.provenance === "SIMULATED");
    html += (simulated ? '<div class="note sim">At least one evidence item is simulated test data.</div>' : "") +
      '<details><summary class="small">Independent evidence (' + evidence.length + ' items)</summary>' +
      '<table><thead><tr><th>Source</th><th>Class</th><th>Method</th><th>Reference</th></tr></thead><tbody>' +
      evidence.map((e) => "<tr><td>" + esc(e.source) + "</td><td>" + status(e.verification) +
        '</td><td class="small wrap">' + esc(e.verification_method || e.event_type || "") +
        '</td><td class="small">' + (e.evidence_url
          ? '<a href="' + esc(e.evidence_url) + '" rel="noopener noreferrer" target="_blank"><code class="mono">' + esc(e.tx_hash || e.source_record_id || e.id) + "</code></a>"
          : '<code class="mono">' + esc(e.tx_hash || e.source_record_id || e.id) + "</code>") +
        "</td></tr>").join("") + "</tbody></table></details>";
  }
  html += (a.limitations && a.limitations.length
      ? '<ul class="small muted">' + a.limitations.map((l) => "<li>" + esc(l) + "</li>").join("") + "</ul>" : "") +
    "</div>";
  return html;
}

async function decideQuote(approve) {
  const out = document.getElementById("i-approve-output");
  if (!IN.intentId) { out.innerHTML = '<div class="note bad">Create an intent and request a live quote first.</div>'; return; }
  if (IN.busy) return;
  IN.busy = true;
  out.innerHTML = loading(approve ? "Approving…" : "Rejecting…");
  try {
    const data = await api("POST", "/api/guard/near/lifecycle/" + IN.intentId + "/approve", { approve: approve });
    out.innerHTML = '<div class="note ' + (approve ? "ok" : "bad") + '">' +
      esc(approve ? "Quote approved. You may now fund the deposit address and record the hash."
        : "Quote rejected. No deposit can be recorded against this quote.") + "</div>";
    // Only an approved quote reveals the deposit-hash form.
    const depositWrap = document.getElementById("i-deposit-form-wrap");
    if (depositWrap) depositWrap.hidden = !approve;
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
  finally { IN.busy = false; }
}

async function recordDeposit() {
  const out = document.getElementById("intents-step-output");
  const hashEl = document.getElementById("i-deposit-hash");
  const hash = (hashEl && hashEl.value || "").trim();
  if (!IN.intentId) { out.innerHTML = '<div class="note bad">Create an intent and request a live quote first.</div>'; return; }
  if (!hash) { out.innerHTML = '<div class="note bad">Enter the deposit transaction hash from your wallet.</div>'; return; }
  if (IN.busy) return;
  IN.busy = true;
  out.innerHTML = loading("Recording deposit…");
  try {
    const data = await api("POST", "/api/guard/near/lifecycle/" + IN.intentId + "/deposit", { deposit_tx_hash: hash });
    out.innerHTML = '<div class="card"><h3>Deposit recorded</h3>' +
      '<pre class="small">' + esc(JSON.stringify(data, null, 2)) + "</pre></div>";
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
  finally { IN.busy = false; }
}

async function listIntents() {
  const out = document.getElementById("intents-step-output");
  out.innerHTML = loading("Loading…");
  try {
    const data = await api("POST", "/api/guard/near/lifecycle/list", {});
    const rows = (data.intents || []).map((i) =>
      '<tr><td class="small">' + esc(i.intent_id) + "</td><td>" + esc(i.state) +
      '</td><td class="small">' + esc(i.provider_status || "—") + "</td></tr>").join("");
    out.innerHTML = '<div class="panel"><h3>Intents (' + esc(data.owner) + ")</h3>" +
      '<table class="table"><thead><tr><th>Id</th><th>State</th><th>Provider status</th></tr></thead>' +
      "<tbody>" + (rows || '<tr><td colspan="3">none</td></tr>') + "</tbody></table></div>";
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

// The owner's durable intents, as a resume list. Each row carries the stored
// state, so a reload resumes an existing intent instead of abandoning it.
function renderIntentResumeList(intents) {
  const rows = intents.map((i) =>
    '<tr><td class="small">' + esc(i.intent_id) + "</td><td>" + status(i.state) +
    '</td><td class="small">' + esc(i.provider_status || "—") +
    '</td><td><button class="act" type="button" data-intent-id="' + esc(i.intent_id) +
    '" data-state="' + esc(i.state) + '">Resume</button></td></tr>').join("");
  return '<div class="card"><h3>Resume a recorded intent</h3>' +
    '<p class="small muted">Each row is a durable record. Resume re-selects it so the quote, ' +
    "approval, deposit, status and assurance steps below run against it — no new intent is created.</p>" +
    '<table class="table"><thead><tr><th>Id</th><th>State</th><th>Provider status</th><th></th></tr></thead>' +
    "<tbody>" + rows + "</tbody></table></div>";
}

function onIntentListClick(e) {
  const btn = e.target.closest("button[data-intent-id]");
  if (!btn) return;
  resumeIntent(btn.getAttribute("data-intent-id"), btn.getAttribute("data-state"));
}

async function resumeIntent(intentId, state) {
  const out = document.getElementById("intents-create-output");
  IN.intentId = intentId;
  IN.idemKey = null;
  out.innerHTML = loading("Loading intent " + intentId + "…");
  let record = null;
  try {
    const data = await api("POST", "/api/guard/near/lifecycle/" + intentId + "/get", {});
    record = data.intent || null;
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; return; }
  if (!record) { out.innerHTML = '<div class="note bad">No such intent.</div>'; return; }

  out.innerHTML = '<div class="card"><h3>Intent ' + esc(intentId) + "</h3>" +
    '<div class="kv"><dt>State</dt><dd>' + status(record.state || state || "UNKNOWN") +
    "</dd><dt>Provider status</dt><dd>" + esc(record.provider_status || "—") +
    "</dd><dt>Deposit address</dt><dd>" +
    (record.deposit_address ? "<code>" + esc(record.deposit_address) + "</code>" : "—") +
    "</dd><dt>Quote approved</dt><dd>" + (record.quote_approved ? "Yes" : "No") +
    "</dd></div>" +
    '<div class="actions"><button class="act" type="button" id="i-refresh-record">Refresh this record</button></div></div>' +
    '<div id="i-refresh-output" aria-live="polite"></div>';

  // Restore the parts of the journey the stored evidence supports, so the
  // operator continues from where the transaction actually is.
  const q = record.quote || null;
  if (record.deposit_address && q && q.quote) {
    renderHandoff({
      ok: true,
      deposit_address: record.deposit_address,
      deposit_memo: record.deposit_memo || null,
      quote: q.quote,
      expiry: record.quote_expiry || {},
      dry: false,
    });
  }
  const approveWrap = document.getElementById("i-approve-wrap");
  if (approveWrap) approveWrap.hidden = !(record.deposit_address && !record.quote_approved);
  const depositWrap = document.getElementById("i-deposit-form-wrap");
  if (depositWrap) depositWrap.hidden = !(record.deposit_address && record.quote_approved);
  const refresh = document.getElementById("i-refresh-record");
  if (refresh) refresh.onclick = async () => {
    const ro = document.getElementById("i-refresh-output");
    ro.innerHTML = loading("Reading the provider status…");
    try {
      const d = await api("POST", "/api/guard/near/lifecycle/" + intentId + "/status", {});
      ro.innerHTML = renderLifecycleStatus(d);
    } catch (err) { ro.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
  };
}

async function loadTokens() {
  const el = document.getElementById("intents-tokens");
  el.innerHTML = loading("Loading assets…");
  try {
    const data = await api("GET", "/api/guard/near/lifecycle/tokens");
    el.innerHTML = '<div class="note">' + esc(data.message) + "</div>" +
      '<table class="table"><thead><tr><th>Asset id</th><th>Chain</th><th>Symbol</th></tr></thead><tbody>' +
      (data.assets || []).slice(0, 40).map((a) => '<tr><td class="small">' + esc(a.asset_id) +
        "</td><td>" + esc(a.blockchain) + "</td><td>" + esc(a.symbol) + "</td></tr>").join("") +
      "</tbody></table>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function loadLab() {
  const el = document.getElementById("lab-scenarios");
  el.innerHTML = loading("Loading scenarios…");
  try {
    const data = await api("GET", "/api/guard/scenarios");
    document.getElementById("lab-output").innerHTML =
      '<div class="note sim">' + esc(data.note) + "</div>";
    el.innerHTML = '<div class="grid two">' + data.scenarios.map((s) =>
      '<div class="card"><h2>' + esc(s.title) + '</h2><p class="small">' + esc(s.narrative) +
      '</p><div class="kv small"><dt>Expected</dt><dd>' + status(s.expected_decision) +
      '</dd></div><div class="actions"><button class="act primary" type="button" ' +
      'data-scenario="' + esc(s.id) + '">Run simulation</button></div></div>').join("") + "</div>";
    el.querySelectorAll("button[data-scenario]").forEach((b) => {
      b.addEventListener("click", () => runScenario(b.getAttribute("data-scenario"), data.scenarios));
    });
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}
async function runScenario(id, scenarios) {
  const s = scenarios.find((x) => x.id === id);
  const out = document.getElementById("lab-output");
  out.innerHTML = loading("Running simulation: " + s.title + "…");
  const steps = [];
  try {
    const transaction = Object.assign({}, s.transaction);
    const evaluated = await api("POST", "/api/guard/evaluate",
      { transaction: transaction, simulated: true, return_authorization: true });
    steps.push({ label: "Guard evaluation", decision: evaluated, authorization: evaluated.authorization });

    if (s.signing === "with_authorization") {
      const r = await api("POST", "/api/guard/sign",
        { transaction: transaction, authorization: evaluated.authorization, simulated: true });
      steps.push({ label: "Signer, with the issued authorization", sign: r });
    } else if (s.signing === "without_authorization") {
      const r = await api("POST", "/api/guard/sign",
        { transaction: transaction, authorization: null, simulated: true });
      steps.push({ label: "Signer, with no authorization", sign: r });
    } else {
      const none = await api("POST", "/api/guard/sign",
        { transaction: transaction, authorization: null, simulated: true });
      steps.push({ label: "Signer, with no authorization", sign: none });
      if (evaluated.authorization) {
        const other = Object.assign({}, transaction, {
          destination: "0xb741c00f6d63b6ded0ccada1a82bcbadc38a572b", amount: "42",
        });
        const sub = await api("POST", "/api/guard/sign",
          { transaction: other, authorization: evaluated.authorization, simulated: true });
        steps.push({ label: "Signer, with a valid token minted for different parameters", sign: sub });
        const tampered = JSON.parse(JSON.stringify(evaluated.authorization));
        tampered.parameters.destination = "0x1111111111111111111111111111111111111111";
        const forged = await api("POST", "/api/guard/sign",
          { transaction: transaction, authorization: tampered, simulated: true });
        steps.push({ label: "Signer, with an edited token (signature no longer covers it)", sign: forged });
        const ok = await api("POST", "/api/guard/sign",
          { transaction: transaction, authorization: evaluated.authorization, simulated: true });
        steps.push({ label: "Signer, with the correct authorization", sign: ok });
      }
    }
    out.innerHTML = '<div class="note sim">Simulated scenario: ' + esc(s.title) +
      ". No real transaction was created.</div>" +
      steps.map((st) => {
        if (st.decision) { return renderDecision(st.decision, st.authorization, null); }
        return '<div class="panel"><h2>' + esc(st.label) + "</h2>" +
          '<div class="kv"><dt>Outcome</dt><dd>' + status(st.sign.outcome) +
          "</dd><dt>Authorization state</dt><dd>" + status(st.sign.state) +
          "</dd><dt>Detail</dt><dd>" + esc(st.sign.detail) + "</dd></div></div>";
      }).join("");
    loadOverview();
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

/* ---- investigations ---- */
async function loadInvestigationHistory() {
  const el = document.getElementById("inv-history");
  if (!el) return;
  el.innerHTML = loading("Loading saved investigations…");
  try {
    const data = await api("GET", "/api/guard/investigations");
    if (!data.enabled) {
      el.innerHTML = '<div class="note">' + esc(data.note || "Durable history is not configured.") + "</div>";
      return;
    }
    const rows = (data.investigations || []);
    if (!rows.length) { el.innerHTML = empty("No saved investigations yet."); return; }
    el.innerHTML = "<table><thead><tr><th>Investigation</th><th>Identifier</th><th>Outcome</th>" +
      "<th>Observed</th><th></th></tr></thead><tbody>" + rows.map((r) =>
      '<tr><td class="small"><code>' + esc(r.investigation_id) + "</code></td>" +
      '<td class="small wrap"><code>' + esc(r.identifier) + "</code></td>" +
      "<td>" + status(r.outcome) + '</td><td class="small">' + fmtAt(r.created_at) + "</td>" +
      '<td><button class="act" type="button" data-inv-open="' + esc(r.investigation_id) + '">View</button></td></tr>'
    ).join("") + "</tbody></table>";
    el.querySelectorAll("button[data-inv-open]").forEach((b) => {
      b.addEventListener("click", () => openStoredInvestigation(b.getAttribute("data-inv-open")));
    });
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function openStoredInvestigation(investigationId) {
  const out = document.getElementById("inv-result");
  out.innerHTML = loading("Loading stored report…");
  try {
    const data = await api("GET", "/api/guard/investigations/" + encodeURIComponent(investigationId));
    out.innerHTML = '<div class="note">Stored report — the conclusion is the one recorded at the ' +
      "time of the investigation, reconstructed from its recorded evidence.</div>" +
      renderInvestigation(data.investigation);
  } catch (err) { out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

async function submitInvestigation(ev) {
  ev.preventDefault();
  const id = document.getElementById("inv-id").value.trim();
  const out = document.getElementById("inv-result");
  const btn = document.getElementById("inv-submit");
  if (!id) { out.innerHTML = '<div class="note bad">Enter an identifier.</div>'; return; }
  out.innerHTML = loading("Investigating…");
  btn.disabled = true;
  try {
    const res = await fetch("api/investigate?format=full", {
      method: "POST", headers: headers(), body: JSON.stringify({ identifier: id }),
    });
    const body = await res.json();
    if (!res.ok) { out.innerHTML = '<div class="note bad">' + esc(body.error || ("HTTP " + res.status)) + "</div>"; return; }
    S.investigations.unshift({ id: id, outcome: body.data.outcome, at: body.data.created_at });
    S.investigations = S.investigations.slice(0, 8);
    out.innerHTML = renderInvestigation(body.data);
    loadInvestigationHistory();
  } catch (err) {
    out.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
  } finally { btn.disabled = false; }
}
function renderInvestigation(d) {
  const simulated = (d.evidence || []).some((e) => e.provenance === "SIMULATED");
  let html = simulated ? '<div class="note sim"><strong>Simulated evidence present.</strong> At least one item is simulated test data.</div>' : "";
  html += '<div class="panel"><h2>Conclusion</h2><div class="kv">' +
    "<dt>Outcome</dt><dd>" + status(d.outcome) + "</dd>" +
    "<dt>Last confirmed stage</dt><dd>" + esc(d.last_confirmed_stage || "none") + "</dd>" +
    "<dt>Identifier</dt><dd><code>" + esc(d.input.identifier) + "</code></dd>" +
    "<dt>Identifier type</dt><dd>" + esc(d.input.identifier_type) + "</dd>" +
    "<dt>Investigation</dt><dd><code>" + esc(d.investigation_id) + "</code></dd>" +
    "<dt>Observed at</dt><dd>" + fmtAt(d.created_at) + "</dd></div><p>" + esc(d.summary) + "</p></div>";
  html += '<div class="panel"><h2>Settlement timeline</h2><table><thead><tr><th>Stage</th>' +
    "<th>State</th><th>Explanation</th></tr></thead><tbody>" +
    (d.stages || []).map((s) => "<tr><td>" + esc(s.stage) + "</td><td>" + status(s.state) +
      '</td><td class="wrap">' + esc(s.summary) + "</td></tr>").join("") + "</tbody></table></div>";
  const assurance = d.settlement_assurance;
  if (assurance) {
    let a = '<div class="panel"><h2>Settlement assurance</h2><div class="kv">' +
      "<dt>Assurance level</dt><dd>" + status(assurance.level) + "</dd>" +
      "<dt>Independently verified</dt><dd>" + (assurance.independently_verified ? "yes" : "no") + "</dd>" +
      "<dt>Provider claimed success</dt><dd>" + (assurance.provider_claimed_success ? "yes" : "no") + "</dd>" +
      (assurance.partial_settlement ? "<dt>Partial settlement</dt><dd>yes</dd>" : "") +
      "</div><p>" + esc(assurance.summary) + "</p>";
    a += '<table><thead><tr><th>Settlement stage</th><th>State</th><th>Confirmed</th>' +
      "<th>Detail</th></tr></thead><tbody>" +
      (assurance.stages || []).map((s) => "<tr><td>" + esc(s.name) + "</td><td>" + status(s.state) +
        "</td><td>" + (s.confirmed ? "yes" : "no") + '</td><td class="wrap">' + esc(s.detail) +
        "</td></tr>").join("") + "</tbody></table>";
    if ((assurance.limitations || []).length) {
      a += "<ul>" + assurance.limitations.map((l) => "<li>" + esc(l) + "</li>").join("") + "</ul>";
    }
    html += a + "</div>";
  }
  const sources = d.sources || [];
  if (sources.length) {
    html += '<div class="panel"><h2>Provider status and source availability</h2><table><thead><tr>' +
      "<th>Source</th><th>Status</th><th>Detail</th></tr></thead><tbody>" +
      sources.map((s) => "<tr><td>" + esc(s.source) + "</td><td>" + status(s.status) +
        '</td><td class="wrap">' + esc(s.message || "") + "</td></tr>").join("") + "</tbody></table></div>";
  }
  const evidence = (d.evidence || []).slice().sort((a, b) =>
    String(a.timestamp || "").localeCompare(String(b.timestamp || "")) || a.id.localeCompare(b.id));
  if (evidence.length) {
    html += '<div class="panel"><h2>Evidence</h2><table><thead><tr><th>Stage</th><th>Event</th>' +
      "<th>Source</th><th>Class</th><th>Method</th><th>Hash</th></tr></thead><tbody>" +
      evidence.map((e) => "<tr><td>" + esc(e.stage) + "</td><td>" + esc(e.event_type) + "</td><td>" +
        esc(e.source) + "</td><td>" + status(e.verification) + '</td><td class="wrap">' +
        esc(e.verification_method || "") + '</td><td><code class="mono">' + esc(e.tx_hash || "") +
        "</code></td></tr>").join("") + "</tbody></table></div>";
  }
  const notes = (d.notes || []).concat(d.known_limitations || []);
  if (notes.length) {
    html += '<div class="panel"><h2>Notes and limitations</h2><ul>' +
      notes.map((n) => "<li>" + esc(n) + "</li>").join("") + "</ul></div>";
  }
  return html;
}
function renderInvestigations() {
  const el = document.getElementById("overview-investigations");
  if (!S.investigations.length) {
    el.innerHTML = empty("No investigations in this session. Run one from the Investigations tab.");
    return;
  }
  el.innerHTML = '<ul class="plain">' + S.investigations.map((i) =>
    "<li><code>" + esc(i.id) + "</code> " + status(i.outcome) +
    ' <span class="small muted">' + fmtAt(i.at) + "</span></li>").join("") + "</ul>";
}

/* ---- incidents ---- */
async function loadIncidents(filter) {
  const el = document.getElementById("incidents-body");
  el.innerHTML = loading("Loading incidents…");
  try {
    const q = filter ? ("?status=" + encodeURIComponent(filter) + "&limit=100") : "?limit=100";
    const data = await api("GET", "/api/guard/incidents" + q);
    renderIncidentList(el, data.incidents || [], false);
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}
function renderIncidentList(el, incidents, compact) {
  if (!incidents.length) { el.innerHTML = empty("No incidents in this view."); return; }
  el.innerHTML = "<table><thead><tr><th>Severity</th><th>Status</th><th>Incident</th>" +
    (compact ? "" : '<th class="hide-sm">Service</th><th class="hide-sm">Occurrences</th><th>Updated</th>') +
    "</tr></thead><tbody>" + incidents.map((i) => {
      let row = "<tr><td>" + sev(i.severity) + "</td><td>" + status(i.status) + "</td><td>" +
        "<div>" + esc(i.title) + '</div><div class="small muted"><code>' + esc(i.code) +
        "</code> · " + esc(i.incident_id) + '</div><div class="small">' + esc(i.detail) + "</div>" +
        (compact ? "" : incidentActions(i)) + "</td>";
      if (!compact) {
        row += '<td class="hide-sm">' + esc(i.service_id || "") + '</td><td class="hide-sm">' +
          esc(i.occurrence_count) + '</td><td class="hide-sm">' + fmtAt(i.updated_at) + "</td>";
      }
      return row + "</tr>";
    }).join("") + "</tbody></table>";
  el.querySelectorAll("button[data-incident-status]").forEach((b) => {
    b.addEventListener("click", async () => {
      try {
        await api("POST", "/api/guard/incidents/" + b.getAttribute("data-incident") + "/status",
          { status: b.getAttribute("data-incident-status") });
        loadIncidents("OPEN");
      } catch (err) { alert(err.message); }
    });
  });
}
function incidentActions(i) {
  if (i.status === "RESOLVED") { return ""; }
  const next = i.status === "OPEN" ? "ACKNOWLEDGED" : "RESOLVED";
  return '<div class="actions"><button class="act" type="button" data-incident="' + esc(i.incident_id) +
    '" data-incident-status="' + next + '">Mark ' + next.toLowerCase() + "</button></div>";
}

/* ---- policies ---- */
async function loadPolicies() {
  const controls = document.getElementById("controls-body");
  const policy = document.getElementById("policy-body");
  controls.innerHTML = loading("Loading…"); policy.innerHTML = loading("Loading…");
  try {
    const data = await api("GET", "/api/guard/policy");
    const p = data.policy;
    controls.innerHTML = "<table><caption>Seven deterministic controls. The decision is the " +
      "strictest control outcome; a control can only make the outcome stricter.</caption>" +
      "<thead><tr><th>Control</th><th>Enforces</th></tr></thead><tbody>" +
      [["Identity allowlist", "the requesting service is registered, enabled, and permitted this operation, chain and asset"],
       ["Destination policy", "the destination is not denied, and either approved or explicitly reviewed"],
       ["Amount limits", "the amount is within the per-transaction limit; above the threshold it needs approval"],
       ["Velocity", "request rate, blocked-request rate, and rolling window volume stay within limits"],
       ["Rejected authorization attempts", "repeated refusals at the signing boundary hold the service"],
       ["Client-asserted approval", "client-supplied approval or bypass flags are ignored and reported"],
       ["Request integrity", "required parameters are present and internally consistent"],
      ].map(([n, d]) => "<tr><td>" + esc(n) + '</td><td class="wrap">' + esc(d) + "</td></tr>").join("") +
      "</tbody></table>";
    policy.innerHTML = '<div class="kv">' +
      "<dt>Policy</dt><dd>" + esc(p.name) + " (" + esc(p.policy_id) + ", v" + esc(p.version) + ")</dd>" +
      "<dt>Per-transaction limit</dt><dd>" + esc(p.per_transaction_limit || "none") + "</dd>" +
      "<dt>Approval threshold</dt><dd>" + esc(p.approval_threshold || "none") + "</dd>" +
      "<dt>Approvals required</dt><dd>" + esc(p.min_approvals) + "</dd>" +
      "<dt>Window</dt><dd>" + esc(p.window_seconds) + "s, max " + esc(p.max_requests_per_window) +
        " requests, max " + esc(p.max_blocked_per_window) + " blocked</dd>" +
      "<dt>Authorization TTL</dt><dd>" + esc(p.authorization_ttl_seconds) + "s</dd>" +
      "<dt>Unlisted destinations</dt><dd>" +
        (p.allow_unlisted_destinations ? "require approval" : "refused") + "</dd>" +
      "<dt>Approved destinations</dt><dd><code>" + esc((p.approved_destinations || []).join(", ") || "none") + "</code></dd>" +
      "<dt>Denied destinations</dt><dd><code>" + esc((p.blocked_destinations || []).join(", ") || "none") + "</code></dd>" +
      "</div>";
    if ((p.services || []).length) {
      policy.innerHTML += "<h3>Service identities</h3><table><thead><tr><th>Service</th><th>Operations</th>" +
        "<th>Chains</th><th>Assets</th><th>Max / tx</th><th>Max / window</th></tr></thead><tbody>" +
        p.services.map((s) => "<tr><td>" + esc(s.service_id) + "</td><td>" + esc((s.allowed_operations || []).join(", ")) +
          "</td><td>" + esc((s.allowed_chains || []).join(", ")) + "</td><td>" + esc((s.allowed_assets || []).join(", ")) +
          "</td><td>" + esc(s.max_amount_per_transaction || "none") + "</td><td>" +
          esc(s.max_amount_per_window || "none") + "</td></tr>").join("") + "</tbody></table>";
    }
  } catch (err) {
    controls.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
    policy.innerHTML = "";
  }
}

/* ---- integrations ---- */
async function loadIntegrations() {
  const el = document.getElementById("integration-body");
  const sources = document.getElementById("sources-body");
  el.innerHTML = loading("Loading…"); sources.innerHTML = loading("Loading…");
  try {
    const m = await api("GET", "/api/guard/metrics");
    el.innerHTML = '<p class="small">A signing integration calls the guard, receives an ' +
      "authorization only for an ALLOW decision, then validates it before signing. The reference " +
      "signer shipped here is a working adapter; a real signer keeps the same validation and " +
      'replaces only the simulated executor.</p><div class="kv">' +
      "<dt>Endpoint</dt><dd><code>POST /api/guard/evaluate</code> then <code>POST /api/guard/sign</code></dd>" +
      "<dt>Authorization TTL</dt><dd>" + esc(m.authorization.ttl_seconds) + " seconds</dd>" +
      "<dt>Key identifier</dt><dd><code>" + esc(m.authorization.key_id) + "</code></dd>" +
      "<dt>Key origin</dt><dd>" + (m.authorization.ephemeral_key
        ? "ephemeral, generated at start-up (no key configured)"
        : "configured via TRACESETTLE_GUARD_AUTH_KEY") + "</dd>" +
      "<dt>Enforcement</dt><dd>the signer refuses unless validation is exactly VALID</dd></div>";
    sources.innerHTML = '<table><caption>All external sources are public, read-only, and keyless.</caption>' +
      "<thead><tr><th>Source</th><th>Purpose</th><th>Access</th></tr></thead><tbody>" +
      [["1Click API", "NEAR Intents swap status, keyed on the deposit address", "HTTPS GET, no key"],
       ["Solver relay", "intent settlement status", "JSON-RPC POST, no key"],
       ["NEAR RPC", "settlement transaction and DIP-4 intent events", "JSON-RPC POST, no key"],
       ["EVM RPC", "origin and destination receipt verification", "JSON-RPC POST, no key"],
       ["Esplora (mempool.space / blockstream.info)", "Bitcoin origin and refund verification", "HTTPS GET, no key"],
      ].map(([n, p, a]) => "<tr><td>" + esc(n) + '</td><td class="wrap">' + esc(p) + "</td><td>" +
        esc(a) + "</td></tr>").join("") + "</tbody></table>";
  } catch (err) {
    el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>";
    sources.innerHTML = "";
  }
}

/* ---- audit ---- */
async function loadAudit(verify) {
  const body = document.getElementById("audit-body");
  const v = document.getElementById("audit-verification");
  body.innerHTML = loading("Loading audit records…");
  try {
    const data = await api("GET", "/api/guard/audit?limit=100" + (verify ? "&verify=1" : ""));
    if (data.verification) {
      const ok = data.verification.ok;
      v.innerHTML = '<div class="note' + (ok ? "" : " bad") + '">Chain verification: ' +
        (ok ? "intact" : "BROKEN") + " over " + esc(data.verification.length) + " records — " +
        esc(data.verification.reason) +
        (ok ? "" : " (first inconsistency at record " + esc(data.verification.broken_at) + ")") + "</div>";
    } else { v.innerHTML = ""; }
    const records = data.records || [];
    if (!records.length) { body.innerHTML = empty("No audit records yet."); return; }
    body.innerHTML = "<table><caption>Newest first. Each record's digest covers the previous " +
      "record's digest, so an edit or removal breaks the chain from that point.</caption>" +
      "<thead><tr><th>#</th><th>When</th><th>Event</th><th>Actor</th><th>Outcome</th>" +
      '<th class="hide-sm">Detail</th><th class="hide-sm">Digest</th></tr></thead><tbody>' +
      records.map((r) => "<tr><td>" + esc(r.sequence) + "</td><td>" + fmtAt(r.recorded_at) +
        "</td><td><code>" + esc(r.event_type) + "</code></td><td>" + esc(r.actor) + "</td><td>" +
        status(r.outcome) + '</td><td class="wrap hide-sm">' + esc(r.detail) +
        '</td><td class="hide-sm"><code class="mono">' + esc(String(r.digest).slice(0, 16)) +
        "…</code></td></tr>").join("") + "</tbody></table>";
  } catch (err) { body.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

/* ---- settings ---- */
async function loadSettings() {
  const el = document.getElementById("settings-body");
  el.innerHTML = loading("Loading…");
  try {
    const m = await api("GET", "/api/guard/metrics");
    el.innerHTML = '<div class="kv">' +
      "<dt>Tool</dt><dd>TRACESETTLE v__VERSION__</dd>" +
      "<dt>Mode</dt><dd>read-only for settlements; pre-execution evaluation for transfers</dd>" +
      "<dt>Policy</dt><dd>" + esc(m.policy.name) + " (" + esc(m.policy.policy_id) + ")</dd>" +
      "<dt>Authorization key</dt><dd><code>" + esc(m.authorization.key_id) + "</code> — " +
        (m.authorization.ephemeral_key ? "ephemeral" : "configured") + "</dd>" +
      "<dt>Audit records</dt><dd>" + esc(m.audit.length) + "</dd>" +
      '<dt>Audit head digest</dt><dd><code class="mono">' + esc(m.audit.head_digest) + "</code></dd>" +
      "<dt>Open incidents</dt><dd>" + esc(m.counts.open_incidents || 0) + "</dd></div>" +
      '<p class="small muted">The authorization signing key is never displayed. Configure one with ' +
      "<code>TRACESETTLE_GUARD_AUTH_KEY</code> (hex or base64, at least 32 bytes) to keep " +
      "authorizations valid across restarts.</p>";
  } catch (err) { el.innerHTML = '<div class="note bad">' + esc(err.message) + "</div>"; }
}

/* ---- wiring ---- */
document.querySelectorAll('nav.tabs button[role="tab"]').forEach((b) => {
  b.addEventListener("click", () => showTab(b.id.replace("tab-", "")));
});
document.getElementById("apikey").addEventListener("input", (e) => {
  S.key = e.target.value.trim();
  if (S.tab === "overview") { loadOverview(); }
});
document.getElementById("guard-form").addEventListener("submit", submitGuard);
document.getElementById("g-reset").addEventListener("click", () => { document.getElementById("guard-form").reset(); });
document.getElementById("inv-form").addEventListener("submit", submitInvestigation);
document.getElementById("inv-history-refresh").addEventListener("click", loadInvestigationHistory);
document.querySelectorAll("button[data-incident-filter]").forEach((b) => {
  b.addEventListener("click", () => loadIncidents(b.getAttribute("data-incident-filter")));
});
document.getElementById("audit-verify").addEventListener("click", () => loadAudit(true));
document.getElementById("audit-refresh").addEventListener("click", () => loadAudit(false));

const initial = (location.hash || "#overview").replace("#", "");
showTab(document.getElementById("tab-" + initial) ? initial : "overview");
</script>
</body>
</html>
"""
