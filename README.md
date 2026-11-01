# TRACESETTLE

**Blockchain Transaction Security & Settlement Assurance.**

> Prevent unauthorized transactions. Detect suspicious activity. Verify every settlement.

TRACESETTLE has two halves that share one idea: do not trust a claim you have not
checked.

1. **Transaction security (new).** A pre-execution **Transaction Guard** evaluates a
   transaction request against a policy, a **Risk Engine** explains what is wrong,
   and an **Authorization Firewall** issues a short-lived, transaction-bound
   authorization that a **reference signer** independently validates before it will
   execute anything. If the authorization is missing, expired, replayed, or bound to
   different parameters, the signer refuses and nothing is executed.

2. **Settlement verification (existing).** A read-only cross-chain settlement
   investigator for NEAR Intents. It takes one identifier, gathers what public
   sources actually say about a 1Click swap, separates what is **independently
   verified** from what is **merely reported**, flags contradictions and gaps, and
   prints an evidence-backed report.

TRACESETTLE never signs a real transaction, never submits one, never holds funds,
and never asks for a private key or seed phrase. The reference signer simulates
execution; it is the *enforcement boundary*, not a wallet.

**Hackathon track: `security` (AI Security & Defense)** — the track that names
policy engines and spending limits for agents, i.e. "give AI money without giving
it the keys to everything". See [Submission](#hackathon-submission).

## The problem

Two failures, one root cause.

**Unauthorized transactions.** Protecting a private key is not enough. An attacker
who can make an otherwise legitimate system *authorize* an illegitimate transfer
causes the damage without ever touching the key. The defenses that matter are the
ones at the authorization boundary: who is asking, for how much, to where, how
often, and whether the approval that arrived is actually bound to this transaction.

**Unverified settlement.** When a cross-chain swap goes wrong, the evidence is
scattered: a 1Click status record, an origin-chain receipt, a NEAR transaction, a
destination-chain receipt. Each source speaks a different vocabulary (`SUCCESS`,
`SETTLED`, `FINAL`, `0x1`). The common failure mode is treating an upstream
service's word as ground truth. A status of `FAILED` is not proof funds were lost.
A `refundedAmount` of `0` is not proof no refund can occur. A transaction hash is
not proof the event it describes happened.

## What it does

### Transaction security

For every transaction request, seven deterministic controls run — all of them,
never short-circuiting — and produce one explained decision.

| Decision | Meaning | Authorization issued |
| --- | --- | --- |
| `ALLOW` | every control passed | yes |
| `REQUIRE_APPROVAL` | a human decision is needed | no |
| `HOLD` | rate or volume anomaly; retry later | no |
| `BLOCK` | a blocking finding | no |

Controls: service identity and its allowed operations/chains/assets; destination
denylist and allowlist; per-transaction amount limits and an approval threshold;
request rate, blocked-request rate and rolling per-asset volume; repeated rejected
authorization attempts; caller-supplied approval flags; and request integrity.

Every decision carries a decision id, timestamp, request reference, the policy and
version, every control result with the policy that produced it, the findings, a
human-readable explanation, and an audit record.

An `ALLOW` decision mints an **authorization**: an HMAC-SHA256-signed statement
bound to the exact `service_id`, `operation`, `chain`, `asset`, `amount` and
`destination`, with an expiry (90s default) and a single-use nonce. The signer
re-derives the binding from the transaction it was asked to sign. A genuine,
unexpired, unused authorization minted for a *different* transaction is refused as
`WRONG_PARAMETERS` — which is the whole point of binding it to the transaction
rather than merely authenticating the caller.

Amounts are exact `Decimal`s: a limit of `0.3` admits `0.3` and refuses
`0.30000000000000004`. Severity is compared by an explicit rank, never by the
severity's string value (`"MEDIUM"` sorts after `"HIGH"` alphabetically).

Ten structural guarantees are checked by *running the real code*, on demand, at
`GET /api/guard/invariants` — including `refusal_never_reaches_the_executor` and
`authorization_is_single_use`. Each checker is also mutation-tested: the guarded
behaviour is deliberately broken and the checker must notice. A checker that
cannot fail proves nothing.

### Settlement verification

For each transaction stage TRACESETTLE records evidence, then classifies it:

| Classification | Meaning |
| --- | --- |
| `CONFIRMED` | Independently verified from an authoritative source (chain RPC, event logs). |
| `REPORTED` | A service says so, but it was not independently checked. |
| `MISSING` | Not found. Explicitly **not** proof the stage failed. |
| `UNAVAILABLE` | The source needed to check could not be reached. |
| `INCOMPLETE` | The source answered, but a required search could not be completed. Insufficient evidence, not proof of absence. |
| `CONTRADICTORY` | Two pieces of evidence materially disagree. |
| `SIMULATED` | Clearly-labelled test evidence, never a live finding. |

Each evidence item also carries a `verification_method` field stating how its
classification was reached (for example a locally recomputed transaction id, a
script-level recipient match, or a plain upstream report).

Stages: `SOURCE_CHAIN_DEPOSIT`, `BRIDGE_DEPOSIT_CREDIT`, `NEAR_SETTLEMENT`,
`DESTINATION_CHAIN_DELIVERY`, and `REFUND`.

A stage is confirmed **only** by its decisive evidence, never by a neighbouring
signal:

- source deposit: the origin-chain transaction executed;
- bridge deposit credit: an on-chain bridge transfer to `intents.near` carries a
  `BRIDGED_FROM` memo naming **this** deposit's origin transaction hash (for a
  Bitcoin origin, a bridge `utxo_added` event names the origin Bitcoin txid);
- settlement: the investigated intent hash appears in on-chain intent-execution
  event logs (a NEAR transaction merely being included or final is not enough);
- destination delivery: the expected asset transfer to the expected recipient
  appears in the destination receipt logs;
- refund: a **confirmed** on-chain transaction pays the address recorded on-chain
  for this intent's withdrawal. A reported refund alone never confirms it.

Correlation uses explicit identifiers only (intent hash, deposit address,
recipient address, transaction hash). Amount and timestamp similarity are never
used to link stages.

## Try it: do X → see Y

No API keys, no paid services, no database. Python 3.11+ standard library only —
TRACESETTLE has **zero runtime dependencies**. The development tools are separate
and pinned in `requirements-dev.txt`.

**0. Set up a clean environment (development tools only).**

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` pins `pytest` and `pyflakes` (and pytest's transitive
dependencies). You only need it to run the checks below; the tool itself runs on
a bare interpreter.

**1. Run the tests.**

```sh
python -m pytest tests/ --collect-only -q   # 661 tests collected
python -m pytest tests/ -q                  # 661 passed
```
→ `661 passed`.

**2. Prove the enforcement boundary: a permitted request executes, a suspicious
one cannot.**

```sh
python3 -m tracesettle serve --port 8080 &
```

Then open `http://127.0.0.1:8080/console`, go to **Transaction Guard**, and run
the three scenarios. Or drive it with `curl`:

```sh
# a) Legitimate: evaluated, authorized, then executed by the reference signer.
AUTH=$(curl -sS -X POST http://127.0.0.1:8080/api/guard/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"1250.50",
       "destination":"0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"},
       "return_authorization":true}')
echo "$AUTH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("decision:",d["decision"])'
```
→ `decision: ALLOW`.

```sh
# b) Suspicious: 480,000 to an unapproved address.
curl -sS -X POST http://127.0.0.1:8080/api/guard/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"480000",
       "destination":"0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"}}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["decision"],[f["code"] for f in d["findings"]], "authorization:", d.get("authorization"))'
```
→ `BLOCK ['UNAPPROVED_DESTINATION', 'AMOUNT_EXCEEDS_LIMIT'] authorization: None`.

```sh
# c) The bypass attempt: no authorization at all.
curl -sS -X POST http://127.0.0.1:8080/api/guard/sign \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"480000",
       "destination":"0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"},
       "authorization":null}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["outcome"],d["state"])'
```
→ `REFUSED MISSING`. The executor was never called.

**3. See the structural guarantees hold on the running build.**

```sh
curl -sS http://127.0.0.1:8080/api/guard/invariants \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("all hold:",d["all_hold"]);[print(" ",i["name"]) for i in d["invariants"]]'
```
→ `all hold: True` and the ten invariant names.

**4. Investigate a real, known-good swap from the command line.**

```sh
python3 -m tracesettle investigate 0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B
```
→ a Markdown report whose outcome is `SETTLED_VERIFIED`, with the source
deposit, bridge deposit credit, NEAR settlement, and destination delivery each
marked `CONFIRMED` and each linking to its real explorer page.

**5. See conservative handling of an unknown address.**

```sh
python3 -m tracesettle investigate 0x000000000000000000000000000000000000dEaD
```
→ outcome `NOT_FOUND`, and the report says plainly that not found is not proof
the swap failed.

**6. See that a reported-only settlement is not called verified.**

```sh
python3 -m tracesettle investigate 7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG --json
```
→ outcome `SETTLED_REPORTED_ONLY`: the intent hash path can read a service
statement but cannot reach the whole path, and the report says so.

**7. See how a real reported Bitcoin refund is handled.**

```sh
python3 -m tracesettle investigate bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm
```
→ the tool reads the intent's on-chain withdrawal recipient and looks for a
**confirmed** Bitcoin transaction paying that address, using the provider's
transaction list first and the address's own confirmed history as a fallback. A
payout is confirmed only when it is tied to the intent by an explicit identifier
and the tool validates it itself (raw bytes fetched, txid recomputed, recipient
script matched). Whether that is possible depends on what the provider exposes,
which changes over time:

- When the provider names the refund transaction (as its record did on
  2026-10-19), the tool validates it and the refund reads `CONFIRMED`; the outcome
  is `REFUND_VERIFIED` and the evidence records `discovery: "explicit"`.
- When the provider names no transaction and the address has several confirmed
  payouts, no payout can be tied to the intent by an explicit identifier: the
  refund stays a reported claim and the stage reads `UNAVAILABLE` with reason
  `AMBIGUOUS_REFUND_PAYOUT`. Confirming one of the payouts would be a guess, so the
  tool does not.

Either way the tool never picks a payout by amount or timestamp, and a reported
refund alone never confirms the stage. When a Bitcoin source is unreachable the
refund likewise stays `UNAVAILABLE` (a source problem, not a failed refund). The
demo states the outcome it actually observed in that run rather than a fixed
verdict.

**8. Run the web interface.**

```sh
python3 -m tracesettle serve --host 127.0.0.1 --port 8000
```
→ open `http://127.0.0.1:8000`, enter a deposit address, press **Investigate**,
and read the evidence in chronological order with links to every source record.
Copy or download the report as JSON or Markdown.

To expose the interface beyond loopback, set an API key first so
`POST /api/investigate` requires it:

```sh
TRACESETTLE_API_KEY=… TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
  python3 -m tracesettle serve --host 0.0.0.0 --port 8000
```
→ requests without a matching `X-API-Key` header receive `401`; `GET /` and
`GET /api/health` stay open. Binding a public interface without both credentials
now **refuses to start** (see **Fail-closed startup** below). See **Interface
hardening** below for the concurrency, rate-limit, and cache settings.

**9. Or run all three settlement cases at once.**

```sh
python3 demo/demonstrate.py
```
→ prints the verified swap, the intent-hash-only lookup, and a real refunded
swap side by side, with the decisive evidence for each confirmed stage. The third
case shows how a refund is handled: the tool reports the level the evidence
actually supports and never upgrades a reported refund to a confirmed one without
a transaction it validated itself. It uses live public endpoints; if one is
unreachable it says so and does not fabricate a result. The upstream record can
change between runs, so the third case states what it observed in that run rather
than a fixed verdict.

**10. If a public endpoint is down, replay the captured evidence.**

```sh
python3 demo/demonstrate.py --offline
```
→ runs the same analysis over the **real captures** in `evidence/raw/`, with no
network access. It substitutes only the network transport, so the adapter,
engine, and report code is the real code. The run is labelled `OFFLINE REPLAY`
and states the capture date; it does not show that an endpoint is answering now.

## Supported input and honest limits

| Identifier | What it can do |
| --- | --- |
| 1Click deposit address (EVM, NEAR, TRON, Bitcoin) | Full path: source, settlement, destination, refund. |
| Intent hash | Settlement status only (solver relay). No reverse lookup exists. |
| Origin-chain transaction hash | Not supported. The 1Click status endpoint is keyed on the deposit address; there is no documented reverse lookup. |

Deposit addresses are recognised by their exact encoding, not by length or a
leading character: EVM `0x`+40 hex, NEAR account ids, TRON mainnet Base58Check
(version byte `0x41`), and Bitcoin legacy Base58Check (P2PKH/P2SH) plus segwit
(bech32/bech32m). A Solana public key is a 32-byte base58 value, which is the
same encoding a NEAR transaction hash and an intent hash use; every 32-byte
base58 value is 43-44 characters, so the three are indistinguishable from the
string alone. Such a value is therefore never routed as a deposit address: it is
reported as `UNKNOWN` with a note naming all three possibilities, and is offered
the intent-hash path. `is_solana_address` recognises the encoding for a caller
that already knows the chain, but no automatic routing is performed.

Other limits, stated in every report:

- 1Click status is a service statement, reported and not independently verified.
- Only chains with a configured public RPC can be independently verified.
- **Free public RPCs prune history.** The default endpoints keep roughly a
  two-day window, so an older transaction returns a null receipt (EVM) or
  `UNKNOWN_TRANSACTION` (NEAR) even though it exists. Each chain therefore
  carries archive-capable fallbacks (`eth.drpc.org`, `…drpc.org` per chain, and
  `eth-mainnet.public.blastapi.io`; NEAR uses `archival-rpc.mainnet.near.org`).
  A fallback answer is validated by exactly the same checks as the primary, so a
  fallback never weakens verification. When every endpoint misses, the stage stays
  `NOT_FOUND`; when an endpoint is unreachable, it stays `UNAVAILABLE` — never
  `FAILED`. Set `TRACESETTLE_NEAR_RPC_FALLBACK_URL` to a paid archive node for a
  reliable historical NEAR lookup; the free archive is deprecated and rate-limits
  hard (HTTP 429), in which case the stage is `UNAVAILABLE`, not confirmed.
- A missing record or a 404 is not evidence that a transaction failed.
- A reported failure is not proof funds were lost.
- A reported refund of zero is not proof no refund can occur.
- Simulated test evidence is always labelled.
- **Bitcoin refunds are only confirmed when the payout is unambiguous.** For a real
  refunded BTC→TRON swap (`bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm`), the tool
  confirms the refund only when exactly one confirmed payout matches the on-chain
  withdrawal recipient, or when the provider itself names the transaction and it
  validates. When the provider names no transaction and the recipient has several
  confirmed payouts, the payout cannot be tied to this intent by an explicit
  identifier: the refund stays a reported claim and the stage reads `UNAVAILABLE`
  (`AMBIGUOUS_REFUND_PAYOUT`). The tool never picks a payout by amount or timestamp,
  and a reported refund alone never confirms the stage.
- The reported refund amount and the observed on-chain payout may differ. Both
  figures are stated and the difference is disclosed, not reconciled; a lower
  payout is expected because network and bridge fees are deducted.
- The bridge credit is confirmed from an on-chain `BRIDGED_FROM` memo that names
  the origin transaction hash. That memo is emitted by the bridge service, so it is
  strong identifier-based, on-chain corroboration — **not** cryptographic proof of
  the whole settlement. The report states this in the evidence item's limitations.

## Architecture

Two layers. The security layer gates what may be executed; the settlement layer
verifies what was. They share one principle: never trust a claim you have not
checked.

```
                        ┌───────────── security layer ─────────────┐
transaction request ──▶ │ guard/rules.py      7 controls, all run  │
                        │ guard/policy.py     policy + version     │
                        │ guard/model.py      explained Decision   │
                        │ guard/authorization.py  transaction-bound │
                        │                     HMAC authorization    │
                        │ guard/signer.py     reference signer:     │
                        │                     validate, then execute │
                        │ guard/audit.py      hash-chained records  │
                        │ guard/monitor.py    counters + incidents  │
                        │ guard/invariants.py 10 checked guarantees │
                        └────────────────────┬─────────────────────┘
                                             │ ALLOW + authorization
                                             ▼
                                     execution or refusal
                                     (SimulatedExecutor: no chain)

identifier
   │
   ▼
identifiers.py ── classify + validate
   │
   ▼
investigation.py ── orchestrates adapters, correlates via explicit ids
   │
   ├── adapters/oneclick.py      1Click status      (reported)
   ├── adapters/solver_relay.py  intent status      (reported)
   ├── adapters/near_rpc.py      NEAR tx + logs     (authoritative)
   ├── adapters/evm_rpc.py       EVM receipts       (authoritative)
   └── adapters/btc_rpc.py       Bitcoin tx + addr  (authoritative)
   │
   ▼
model.py ── normalized EvidenceItem stream
   │
   ▼
reconcile.py ── deterministic engine, 11 safety invariants
   │
   ▼
report.py ── JSON + Markdown investigation report
   │
   ▼
ui.py / __main__.py ── web interface + CLI
```

The engine is deterministic: identical evidence produces an identical result.
No LLM decides whether a transaction is confirmed. The security controls are
equally deterministic: identical requests against an identical policy produce
identical decisions.

## Files

| Path | Role |
| --- | --- |
| `tracesettle/identifiers.py` | Identifier classification and validation. |
| `tracesettle/base58.py` | Shared Base58/Base58Check decoding (used by classification and Bitcoin script decoding). |
| `tracesettle/model.py` | Evidence model: stages, states, outcomes, safety invariants. |
| `tracesettle/assets.py` | `nep141:` asset id parsing to chain/contract. |
| `tracesettle/config.py` | Public chain RPC map (with archive fallbacks), explorer URL builders, guard settings. |
| `tracesettle/httpclient.py` | Timeouts, bounded retries, error classification. |
| `tracesettle/adapters/` | One adapter per data source (1Click, solver relay, NEAR, EVM, Bitcoin). |
| `tracesettle/reconcile.py` | Deterministic reconciliation engine. |
| `tracesettle/investigation.py` | Orchestrator. |
| `tracesettle/report.py` | Report generation. |
| `tracesettle/ui.py` | Standard-library web interface, guard routes, console. |
| `tracesettle/ratelimit.py` | Token buckets for per-IP and per-host limits. |
| `tracesettle/cache.py` | Bounded TTL cache with single-flight. |
| `tracesettle/serviceauth.py` | Per-service credential registry (hashed secrets, constant-time). |
| `tracesettle/securityconfig.py` | Fail-closed startup validation for the network interface. |
| `tracesettle/__main__.py` | CLI (`investigate`, `serve`, `credentials`). |
| `tracesettle/guard/model.py` | Transaction request, policy, decision, finding, authorization models. |
| `tracesettle/guard/policy.py` | Default policy and JSON override loading. |
| `tracesettle/guard/rules.py` | The seven deterministic controls. |
| `tracesettle/guard/authorization.py` | Issuing, validating, expiring, single-use nonces. |
| `tracesettle/guard/signer.py` | Reference signer + simulated executor (the enforcement boundary). |
| `tracesettle/guard/audit.py` | Hash-chained, verifiable audit log. |
| `tracesettle/guard/monitor.py` | Security counters and incident records. |
| `tracesettle/guard/service.py` | Orchestration: controls → authorization → monitor → audit. |
| `tracesettle/guard/invariants.py` | The twelve structural guarantees, checked by execution. |
| `tracesettle/guard/api.py` | Guard HTTP routing and JSON serialization. |
| `tracesettle/guard/console.py` | The security operations console page. |
| `docs/TRANSACTION_SECURITY.md` | The security layer in full, including what it does not do. |
| `Dockerfile` / `.dockerignore` | Minimal non-root container image (healthcheck probes `/api/health`). |
| `.github/workflows/ci.yml` | CI: tests, static analysis, Docker build + runtime, demo determinism. |
| `demo/demonstrate.py` | Read-only walkthrough (live, or `--offline` replay of captures). |
| `demo/replay_opener.py` | Offline transport that replays `evidence/raw/` through the real code. |
| `tests/` | 661 tests. `evidence/raw/` fixtures are real captures; `tests/fixtures/synthetic/` are clearly labelled synthetic. |
| `PHASE1_FEASIBILITY.md` | Phase 1 feasibility and API verification. |
| `submission/` | Hackathon artifacts: API payload shape, technical summary, demo post draft, publication checklist. |
| `docs/official/` | NEAR documentation captured during Phase 1. |
| `requirements-dev.txt` | Development-only tool pins (`pytest`, `pyflakes`). Not needed at runtime. |

## Runtime dependencies

**None.** TRACESETTLE imports only the Python standard library at runtime
(`json`, `urllib`, `http.server`, `hashlib`, and similar). `requirements-dev.txt`
exists solely for the test and lint tooling and must not be installed to run the
tool. Supported interpreter: CPython 3.11+; verified on 3.13.15.

## Security and reliability

- No private keys, seed phrases, signing, or transaction submission anywhere.
- All external input is validated (type, length, control characters).
- Every upstream request has a timeout and a bounded retry budget; 4xx errors
  are not retried.
- Rate limits and upstream errors are classified, not hidden.
- No secrets are read, written, logged, or sent to the client.
- Errors returned to the client never contain internal details.
- The app stays usable when a source is down, marking evidence `UNAVAILABLE`.
- A blockchain hash commitment is never treated as proof the underlying event is
  true.

### Interface hardening

The web interface is hardened against resource exhaustion and abuse, with every
limit configurable by environment variable:

- **Client socket timeouts.** Each connection has a read timeout
  (`TRACESETTLE_CLIENT_TIMEOUT`, default 10s), so a slow or idle client cannot
  hold a worker thread open (slowloris).
- **Hard concurrency cap.** At most `TRACESETTLE_MAX_CONCURRENCY` (default 16)
  connections are served at once. Excess connections get an immediate
  `503 Service Unavailable` with `Retry-After` instead of being queued. The
  concurrency slot is released on every path, including errors.
- **Bounded request bodies.** `Content-Length` is checked against an 8 KiB cap
  *before* the body is read; an oversized or missing body is `413`, never
  buffered.
- **API-key authentication.** Set `TRACESETTLE_API_KEY` to require an `X-API-Key`
  header on `POST /api/investigate` (constant-time comparison; the key is never
  logged or echoed). Unset, the endpoint is open — the default for loopback use.
- **Per-IP rate limiting.** `TRACESETTLE_RATE_LIMIT_PER_MINUTE` /
  `_BURST` bound each client IP (keyed on the socket peer, so a spoofed
  `X-Forwarded-For` cannot bypass it); over-budget requests get `429` with
  `Retry-After`.
- **Per-host upstream budgets.** `TRACESETTLE_HOST_RATE_LIMIT_*` cap calls per
  upstream host, so one client cannot exhaust a free public endpoint's shared
  rate limit for everyone.
- **Bounded upstream caching.** Read-only GET responses (1Click status, Esplora
  transaction and address endpoints) are cached for
  `TRACESETTLE_CACHE_TTL` seconds (default 45) and keyed on the exact URL, so
  distinct investigations never share an entry. Only successful responses are
  cached; failures, timeouts, and incomplete results are never stored. Concurrent
  identical misses are coalesced into one upstream call.
- **No version disclosure.** The `Server` header is `TRACESETTLE`; the Python
  build and package version are not disclosed.

### Security-layer hardening

The guard layer adds its own boundary controls, all configurable by environment
variable and all documented in `docs/TRANSACTION_SECURITY.md`:

- **Fail-closed authorization.** No authorization, or any invalid one, means no
  execution. There is no "assume approved" path.
- **Transaction-bound, single-use, short-lived.** An authorization names the exact
  parameters it approved, carries a 90-second default expiry, and its nonce is
  consumed atomically on first successful use.
- **Constant-time secret comparison.** The API key is compared with
  `hmac.compare_digest`; the authorization signature is verified with
  `hmac.compare_digest`.
- **No key material in any response.** The signing key is never returned, logged,
  or included in metrics; the console never receives it. Asserted by the
  `no_key_material_in_output` invariant.
- **Client assertions are never trusted.** A caller-supplied `approved` or
  `skip_checks` flag produces a finding and a downgraded decision, never ALLOW.
- **Bounded guard bodies.** Guard request bodies are capped by
  `TRACESETTLE_GUARD_MAX_BODY_BYTES` (8 KiB) and rejected before being read.
- **Per-client rate limiting on guard routes**, keyed on the socket peer address
  so a spoofed `X-Forwarded-For` cannot bypass it; `429` carries `Retry-After`.
- **Bounded in-memory state.** Audit records, monitor events, incidents, and the
  replay-nonce store all have explicit caps, so a flood cannot exhaust memory.
- **Structural invariants, checked by execution.** Twelve guarantees at
  `GET /api/guard/invariants`, each mutation-tested so a checker that cannot fail
  is treated as a defect.
- **Honest audit claim.** In-place modification of an audit record is detectable;
  a whole-log rewrite with recomputed digests is *not*, and the README says so
  rather than claiming tamper-proofness.

### Per-service authentication

The guard's policy layer evaluates a transaction for the service named in the
request. Left there, one service could name another and inherit its policy. Each
service can therefore be issued a credential, and a guard request must resolve to
the identity its credential was issued for:

- **The credential is the identity.** A caller presents its credential in the
  `X-Service-Credential` header. The credential resolves to exactly one
  `service_id`; a request whose declared `service_id` differs is refused with
  `403`, so editing the field cannot adopt another identity. This is asserted by
  the `service_identity_cannot_be_forged` invariant.
- **Only hashes are stored.** The plaintext secret is shown once at mint time and
  never stored; the store keeps a one-way `sha256:` hash. This is asserted by the
  `service_credentials_are_hashed_at_rest` invariant. The store is written
  `0600`.
- **Constant-time comparison**, over every credential, so the check does not leak
  which credential matched or how many exist. A refused request gets a generic
  `401`; the credential is never logged or echoed.
- **Expiry, revocation, and rotation.** A credential can expire or be revoked
  (either is refused), and rotation issues a new secret and revokes the old one.
- **Mint and manage from the CLI** — no secret is ever committed:

  ```sh
  python3 -m tracesettle credentials mint treasury-agent --store /etc/tracesettle/credentials.json
  TRACESETTLE_SERVICE_CREDENTIALS=/etc/tracesettle/credentials.json \
  TRACESETTLE_REQUIRE_SERVICE_AUTH=1 python3 -m tracesettle serve --host 0.0.0.0 --port 8000
  ```
  → `mint` prints the secret exactly once; `credentials list` and
  `credentials revoke <id>` never print a secret. The store's read-modify-write is
  serialised with an exclusive `<store>.lock`, so concurrent `mint`/`revoke`
  commands cannot lose a change or restore a just-revoked credential. With
  `TRACESETTLE_REQUIRE_SERVICE_AUTH=1` and no store, the server refuses to start.
  Configure the store with `TRACESETTLE_SERVICE_CREDENTIALS` (a path) or
  `TRACESETTLE_SERVICE_CREDENTIALS_JSON` (inline JSON, for platforms without a
  mounted file). When no store is configured, the loopback development workflow
  is unchanged.

### Fail-closed startup

Authentication is not optional on a public interface: the process refuses to
start rather than expose protected endpoints without it.

- **A public bind requires credentials, with no override.** Binding any
  non-loopback host (for example `0.0.0.0`) without both `TRACESETTLE_API_KEY`
  and `TRACESETTLE_GUARD_AUTH_KEY` exits with status `2` and a message naming the
  missing variables. Only a value that provably parses as a loopback address is
  treated as local, so an unknown or empty host fails closed. There is no
  environment variable that relaxes this: a public bind without credentials
  always refuses to start, so a deployment mistake cannot expose the endpoints.
- **`TRACESETTLE_REQUIRE_SERVICE_AUTH` is enforced.** Setting it without a
  credential store refuses to start on any binding.
- **The container inherits this.** The image binds `0.0.0.0`, so it now requires
  both credentials; the CI job proves it starts with them and refuses without
  them.

`POST /api/investigate` returns the structured report (`{"data": ...}`) by
default. `?format=json`, `?format=markdown`, and `?format=full` (all three, as
earlier versions returned) select other representations.

## Deploy

A minimal image is included. It runs as a non-root user and probes
`/api/health`. Because the image binds `0.0.0.0`, it now requires both
credentials (see **Fail-closed startup**):

```sh
docker build -t tracesettle .
docker run --rm -p 8000:8000 \
  -e TRACESETTLE_API_KEY=change-me \
  -e TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
  tracesettle
curl http://127.0.0.1:8000/api/health
```
→ the same image with neither credential exits `2` with
`refusing to start: ... requires authentication` instead of serving.

`serve` reads its defaults from the environment, so the image needs no flags on
a container platform: `TRACESETTLE_HOST` (default `127.0.0.1`; the image sets
`0.0.0.0`) and `PORT` or `TRACESETTLE_PORT` (default `8000`). Always set both
`TRACESETTLE_API_KEY` and `TRACESETTLE_GUARD_AUTH_KEY` before exposing the
interface.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to `master`.
It performs no deployment, publish, or release, and needs no repository secrets:

- the full test suite (`python -m pytest tests/ -q`);
- static analysis (`python -m pyflakes tracesettle/ tests/ demo/`);
- byte-compilation of every module;
- the offline demo run twice, asserted byte-identical (determinism);
- a gate that fails if any non-standard-library import appears in the package;
- a Docker build, a non-root runtime check (uid `10001`), a `/api/health`
  probe, a graceful-shutdown check, and a check that the image **refuses to
  start** without credentials.

The workflow grants `contents: read` only, pins every third-party action to an
immutable commit SHA (not a moving tag), and cancels superseded runs.

## Tests

```sh
python3 -m pytest tests/ -q          # all 661
python3 -m pytest tests/test_guard_authorization.py -q
python3 -m pytest tests/test_guard_invariants.py -q
python3 -m pytest tests/test_guard_end_to_end.py -q
python3 -m pytest tests/test_safety_invariants.py -q
python3 -m pytest tests/test_serviceauth.py tests/test_serviceauth_http.py -q
python3 -m pytest tests/test_securityconfig.py tests/test_failclosed_startup.py -q
python3 -m pytest tests/test_ui.py -q
```

Test coverage includes successful settlement, a failed intent with a verified
refund, a failed intent without a verified refund, a confirmed source with
incomplete downstream evidence, conflicting or unavailable status information,
invalid identifiers, malformed responses, API timeouts, missing fields, and
unreliable correlation. It also covers the Bitcoin refund path: an ambiguous
refund address history that must stay unconfirmed, a single verified on-chain
refund, a confirmed payout to the wrong address, an unreachable Bitcoin source,
a source returning raw bytes that do not match the claimed txid (contradictory),
raw bytes that are merely unavailable (a limitation, not a contradiction), an
address history that cannot be shown to be complete (insufficient evidence,
reported as unknown rather than unavailable), an address history whose page
budget stops mid-chain, a multi-page history that ends naturally, amount
denomination and fee handling, and a missing on-chain withdrawal recipient.
`tests/test_safety_invariants.py` fails the build if the engine ever claims a
refund or a destination delivery without the required evidence, and adds
state-transition invariants (reported never becomes confirmed, unavailable never
becomes confirmed, incomplete never becomes confirmed, contradictions surface).

Tests exercise the real adapter and engine code. Only the network transport is
substituted, and real Phase 1 captures are loaded from `evidence/raw/` rather
than recreated. Synthetic fixtures live in `tests/fixtures/synthetic/` and are
labelled as such.

The guard tests make no network calls at all: the controls, the authorization
authority, the replay store, the audit log, the monitor, the reference signer and
the API are all the real code. The one substitution is the executor, which is the
real `SimulatedExecutor` with a call counter — so "the signer refused" is asserted
as "the executor was never called". Coverage includes valid authorization, an
unapproved destination, amount limits, velocity and window-volume limits, an
unauthorized service identity, an expired authorization, replay, parameter
substitution, a missing authorization, a bad signature, a token from an untrusted
key, an edited token, a token bound to another service, signer enforcement, audit
records and chain verification, incident creation and resolution, provider and
RPC failure handling on the settlement side, and the end-to-end vertical slice
for both the permitted and the refused path.

## Read-only guarantee

TRACESETTLE cannot recover, reverse, freeze, or move funds. It cannot report a
refund or a delivery without verifiable on-chain evidence. When the evidence is
insufficient it says so and returns an explicit unknown.

The security layer adds one honest boundary to that guarantee. TRACESETTLE
cannot stop an arbitrary blockchain transaction. It can refuse to release a
transaction through a signer that calls it, explain why, record the attempt, and
verify the settlement afterward. Enforcement requires the signer to call the
boundary; the reference signer shows what that looks like, and it simulates
execution rather than signing anything.

## Hackathon submission

- **Track: `security` (AI Security & Defense).** The track's own hint is "spending
  limits, policy engines, sandboxed wallets... give AI money without giving it the
  keys to everything", which is precisely what the Transaction Guard and
  Authorization Firewall are. A secondary `defi` track could be claimed through the
  NEAR Intents settlement verification, but the primary contribution is security.
- **No artificial AI.** No LLM is used, and none was added to qualify for an AI
  category. Every decision is a deterministic, testable rule; the whole point is
  that a model must not be able to talk its way past the boundary.
- **Deadline: 2026-11-14T23:59:00Z.** The repository must be public by then; the
  submission is a single form POST and cannot be edited afterward.
- **Not yet done:** making the repository public, posting the demo on X, and sending
  the submission. All three require explicit human confirmation.
