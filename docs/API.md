# TRACESETTLE HTTP API

Everything TRACESETTLE exposes over HTTP, in one page, so an evaluator can drive
the security boundary directly rather than through the UI.

The runtime is Python standard library only. There is no database requirement, no
paid service and no key needed for the read-only surface. The server is started
with:

```sh
python3 -m tracesettle serve --port 8080
```

Two postures exist, and which one is in force changes who may call what:

| Posture | How it is set | Who can call the guard |
| --- | --- | --- |
| Operator (default) | `TRACESETTLE_API_KEY` set | Callers presenting that key |
| Public demonstration | `TRACESETTLE_PUBLIC_DEMO=1` **and** the key set | Anyone, but only for the exact read-only allowlist below |

`GET /` and `GET /api/health` are always open. Everything else under
`/api/guard/` requires the `X-API-Key` header unless it is on the public
allowlist and the flag is on. A non-loopback bind without credentials refuses to
start (exit 2); there is no override.

## Authentication

- **API key** — header `X-API-Key: <TRACESETTLE_API_KEY>`. Gates the operator
  routes.
- **Service credential** — header `X-Service-Credential: <credential>`, for the
  service-facing routes. It resolves to exactly one service identity; a request
  whose declared `service_id` disagrees is refused `403`. Mint credentials with
  `python3 -m tracesettle credentials mint`.

A refusal is always an HTTP status with a small JSON body; the body never names
an internal path, a stack trace or a secret.

## Read-only routes

| Method | Path | Auth | Returns |
| --- | --- | --- | --- |
| GET | `/` | none | Landing page (HTML) |
| GET | `/api/health` | none | `{"status": "ok", ...}` |
| GET | `/demo` | public flag | Six-scene demonstration page (HTML) |
| GET | `/evaluate` | public flag | Independent evaluation page (HTML) |
| GET | `/JUDGE_GUIDE` | public flag | The judge guide, rendered (HTML) |
| GET | `/console` | none | Operator console (HTML) |
| GET | `/api/guard/policy` | key | The live policy in force |
| GET | `/api/guard/metrics` | key | Counters and backend state |
| GET | `/api/guard/incidents` | key | Open security incidents |
| GET | `/api/guard/audit` | key | The hash-chained audit log |
| GET | `/api/guard/invariants` | key | The structural invariants and whether each holds |
| GET | `/api/guard/safeguards` | key | Durable safeguards learned from findings |
| GET | `/api/guard/scenarios` | key | The guard control scenarios |
| GET | `/api/guard/judge/scenarios` | public flag | The independent evaluation matrix |
| GET | `/api/guard/investigations` | key | Stored settlement investigations |

The NEAR routes (`/api/guard/near/scenarios`, `.../behaviours`,
`.../prompt-injection`, `.../policy-scope`, `.../agent-demo`,
`.../settlement-check`, `.../access-keys`, `.../custody`) are read-only analyses
of shipped fixtures and real chain reads; the public demonstration exposes a
subset of them. The state-changing NEAR routes (`.../agent-evaluate`,
`.../execution/*`, `.../wallet/*`, `.../lifecycle*`, `.../custody/prepare`,
`.../custody/execute`) always require a key or a service credential.

## The agent integration

A scoped, keyless sandbox integration lets an external agent (or an independent
judge) submit payment intents to the real enforcement boundary. It is served only
when `TRACESETTLE_PUBLIC_DEMO=1`; otherwise every `/api/agent/*` route is `404`.

| Method | Path | Auth | Returns |
| --- | --- | --- | --- |
| POST | `/api/agent/connect` | none (rate-limited) | A short-lived sandbox credential |
| POST | `/api/agent/evaluate` | sandbox credential | The enforcement decision (+ an authorization for `ALLOW`) |
| POST | `/api/agent/execute` | sandbox credential | The signer result and the executor call count |
| POST | `/api/agent/approval` | sandbox credential **+** approval secret | A payload-bound approval |
| GET | `/api/agent/evidence` | sandbox credential | This credential's own decisions and receipts |
| POST | `/api/agent/revoke` | sandbox credential | Revokes the credential |
| GET | `/api/agent/settlement` | none | The reference NEAR testnet settlement read |
| GET | `/api/agent/config` | none | Scope, limits and the honest-scope note |
| GET | `/api/agent/openapi.json` | none | The OpenAPI 3.1 contract |

The credential is presented in the `X-Sandbox-Credential` header. It resolves to a
`sandbox-<label>` identity and can only ever reach the **sandbox policy** — a
fixed set of approved destinations with a low per-transaction limit and an
approval threshold. A request that names any other `service_id` is refused `403`.
The approval secret is **separate** from the API credential, so an agent cannot
self-approve. The credential is durable (backed by the guard-state store, so it
survives a restart), expiring, revocable, and rate-limited per client IP and per
credential. Execution uses the simulated executor: nothing is signed or
broadcast, and every response states this.

## The evaluation matrix

```sh
curl -sS http://127.0.0.1:8080/api/guard/judge/scenarios | python3 -m json.tool
```

Returns `{"summary": {...}, "scenarios": [...]}`. Each scenario states:

- `decision` — `ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`, `HOLD`, `UNKNOWN`, or a
  verifier verdict such as `WRONG_PARAMETERS`, `EXPIRED`, `REPLAYED`;
- `signer_calls` — how many times the signer was reached (0 for every refusal);
- `broadcast` — whether anything was broadcast (always `false` for simulations);
- `simulated` / `real` — whether the scenario is a controlled simulation or a
  live read-only chain check;
- `evidence` — the specific facts the scenario checked.

The same matrix is produced offline by `python3 -m tracesettle judge` (add
`--json` for machine output). That command exits non-zero only on a real defect;
an environmental `UNAVAILABLE` (no outbound network) is reported, not failed.

## Evaluate a transaction

```sh
curl -sS -X POST http://127.0.0.1:8080/api/guard/evaluate \
  -H "X-API-Key: $TRACESETTLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"service_id":"agent-1","operation":"transfer","chain":"near",
       "asset":"NEAR","amount":"0.1","destination":"merchant.testnet"}'
```

The body is the transaction the agent proposes. The decision is deterministic;
no model is consulted. All controls run on every request, so the response carries
the whole picture rather than the first reason found. With
`"return_authorization": true` a permitted request also returns a
transaction-bound authorization (HMAC over the canonical parameters, single-use
nonce, expiry).

`POST /api/guard/sign` consumes that authorization. The signer re-derives the
binding from the transaction it is asked to sign, so an authorization minted for
a different transaction is refused `WRONG_PARAMETERS`, and a replayed nonce is
refused. `POST /api/guard/near/agent-evaluate` is the same boundary specialised
for a NEAR Intents agent policy.

## Request and response shape

- Every request body is JSON, read within an 8 KiB cap (`413` if larger).
- Every response body is JSON except the HTML pages.
- A malformed body is `400`; a missing or wrong key is `401`; a wrong service
  identity is `403`; an unknown route is `404`; an overloaded server is `503`
  with `Retry-After`.

## What is not exposed

- No route signs, broadcasts or moves funds without an explicit authorization
  and, for the opt-in execution path, a verified TEE attestation.
- No route returns a private key, a seed phrase or the signing key.
- No route accepts a client-supplied policy or approval flag as authoritative.

See `README.md` for the full behaviour and `JUDGE_GUIDE.md` for a guided
evaluation.
