# TRACESETTLE — production deployment package

Everything needed to deploy TraceSettle as a hardened, read-only transaction
authorization and settlement-investigation service. Prepared against master
`1bd7d8f23226fb403d4854483e1a2f1e27c47cf3` (PR #6 merged).

**Status: preparation complete and locally verified. Nothing here has been
deployed.** Deployment requires explicit authorization; several steps need an
external account, payment, or an owner action (see `PRODUCTION_ACCEPTANCE_CHECKLIST.md` §H).

## Contents

| File | Purpose |
| --- | --- |
| `ARCHITECTURE.md` | Components, why PostgreSQL, connection-pooling rules, startup behaviour, honesty boundaries. |
| `.env.production.example` | Configuration template — placeholders only. |
| `DEPLOYMENT_RUNBOOK.md` | Build, provision, configure, deploy, verify. |
| `ROLLBACK_RUNBOOK.md` | Revert the app and handle schema compatibility. |
| `INCIDENT_RESPONSE.md` | PostgreSQL outage, migration lock, restart, NEAR outage, audit divergence, credential compromise. |
| `MONITORING.md` | What observability exists (verified) vs future work; alerts and thresholds. |
| `COST_ESTIMATE.md` | Platform + PostgreSQL + RPC selection and monthly cost. |
| `NEAR_ARCHIVAL_RPC.md` | Live provider probe results and recommendation. |
| `AUDIT_ANCHORING.md` | Design/proposal for external anchoring — **not implemented**. |
| `PRODUCTION_ACCEPTANCE_CHECKLIST.md` | Verified checklist of what is done and what remains. |

There is deliberately **no separate production Dockerfile**: the existing
`Dockerfile` already meets the requirements (non-root, healthcheck, graceful
shutdown, optional PostgreSQL driver via build arg, no secrets). Use it with
`--build-arg TRACESETTLE_WITH_POSTGRES=1`.

## Mandatory configuration (summary)

| Variable | Role | Notes |
| --- | --- | --- |
| `TRACESETTLE_API_KEY` | Public API auth | header `X-API-Key`; gates `/api/investigate` and `/api/guard/*`. |
| `TRACESETTLE_GUARD_AUTH_KEY` | Token signing key | ≥32 bytes hex/base64; **stable across restarts**; identical on all instances. |
| `TRACESETTLE_GUARD_STATE_BACKEND=postgresql` | Shared state | required for more than one instance. |
| `TRACESETTLE_GUARD_STATE_PG_DSN` | Database DSN | secret; **direct or session-mode** connection. |
| `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` | Fail-closed guard | refuses to start on any other backend. |
| `TRACESETTLE_NEAR_RPC_URL` | Primary NEAR RPC | recent transactions. |
| `TRACESETTLE_NEAR_RPC_FALLBACK_URL` | Archival NEAR RPC | historical transactions. |

Full list with defaults and roles: `.env.production.example`. Every name there
was checked against `tracesettle/config.py`.

## Key and secret management

### `TRACESETTLE_GUARD_AUTH_KEY`

Verified from `tracesettle/guard/authorization.py`:

- **Format:** hex (`[0-9a-fA-F]`, even length) or base64. Minimum **32 bytes**;
  a shorter key is **refused at start-up** (not stretched).
- **Stability:** it signs authorization tokens. It **must** be stable across
  restarts and **identical on every instance** — a new key invalidates all
  outstanding tokens and breaks cross-instance verification.
- **Absence:** with no key, a fresh **ephemeral** key is generated and flagged
  (`authorization.ephemeral_key: true` in metrics). Correct for local dev,
  **not** for production.
- **Rotation impact:** rotating the key invalidates every outstanding token
  (fail-safe direction) and is disruptive; do it deliberately
  (`INCIDENT_RESPONSE.md` §F).
- **Exposure:** the key value is never logged or returned; only a derived
  `key_id` (`k-<sha256[:16]>`) is exposed.

Generate (once, locally, never committed):

```sh
python3 -c "import secrets;print(secrets.token_hex(32))"
```

### `TRACESETTLE_API_KEY`

- Any long random string. Sent by clients as `X-API-Key`.
- Gates `POST /api/investigate` and every `/api/guard/*` endpoint. `GET /` and
  `GET /api/health` stay open (liveness only).
- Do not silently replace an existing production key, and do not rotate without
  authorization.

### Storing the secrets

- Store them **only** in the hosting platform's secret manager (environment
  variables). Never in Git, image layers, docs, screenshots, shell history, or
  deploy logs.
- This repository contains only placeholders. Do not commit a filled-in copy.

## Docker build (production)

```sh
docker build \
  --build-arg TRACESETTLE_WITH_POSTGRES=1 \
  -t tracesettle:production-candidate .
```

- No credentials in build arguments or layers; the driver is the only extra.
- Runs as uid `10001`; healthcheck probes `/api/health`; shuts down gracefully.

## Recommended infrastructure (see `COST_ESTIMATE.md`)

- **Host:** Render (paid, always-on web service). Free tiers sleep/expire.
- **PostgreSQL:** Render Postgres Basic-256mb (~$6/mo), direct connection; or Neon
  free (direct host, not `-pooler`) to start.
- **NEAR archive RPC:** paid archive node; the free archive endpoint is
  deprecated and rate-limited.
- **Audit anchoring:** proposed via OpenTimestamps — not implemented.

## Honest limitations

- No real-funds execution: the executor is a `SimulatedExecutor`.
- The audit chain is tamper-evident, not tamper-proof, and **not** externally
  anchored yet.
- Historical NEAR lookups need a paid archive node to be reliable.
- A previously exposed GitHub credential remains an **open, owner-side**
  revocation item.
