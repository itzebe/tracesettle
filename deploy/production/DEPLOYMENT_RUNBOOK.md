# TRACESETTLE — deployment runbook

Steps to deploy the prepared production image. **Nothing here has been executed
against production.** Run each step only after deployment is authorized.

## 0. Prerequisites

- A container host with **always-on** instances, a health check, graceful
  shutdown, and environment-variable secrets (see `COST_ESTIMATE.md` for the
  recommended platform).
- A PostgreSQL database reachable over a **direct or session-mode** connection
  (see `ARCHITECTURE.md` §3). Transaction-mode poolers are not compatible.
- Two secrets generated locally and stored only in the platform secret manager:
  - `TRACESETTLE_API_KEY`
  - `TRACESETTLE_GUARD_AUTH_KEY`
- The image built from this repo at a pinned commit.

## 1. Generate the secrets (once)

```sh
# Guard signing key — 32 bytes, hex. MUST stay stable across restarts.
python3 -c "import secrets;print(secrets.token_hex(32))"

# Public API key — any long random string.
python3 -c "import secrets;print(secrets.token_urlsafe(32))"
```

Do not print these into logs, do not commit them, and do not reuse the guard key
from a development run (a dev run without a key uses an *ephemeral* key that
changes on restart).

## 2. Build the production image

```sh
# From the repository root, at the pinned commit.
docker build \
  --build-arg TRACESETTLE_WITH_POSTGRES=1 \
  -t tracesettle:production-candidate .

# Confirm it is non-root and carries the driver.
docker inspect tracesettle:production-candidate --format 'User={{.Config.User}}'
docker run --rm --entrypoint python tracesettle:production-candidate \
  -c "import psycopg; print('psycopg', psycopg.__version__)"
```

Expected: `User=tracesettle`, `psycopg 3.3.6`. The image contains no secrets
(only non-secret `ENV`: `TRACESETTLE_HOST=0.0.0.0`, `PORT=8000`).

## 3. Smoke-test locally before deploying

```sh
KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
docker run --rm -p 8000:8000 \
  -e TRACESETTLE_API_KEY=throwaway \
  -e TRACESETTLE_GUARD_AUTH_KEY="$KEY" \
  -e TRACESETTLE_GUARD_STATE_BACKEND=postgresql \
  -e TRACESETTLE_GUARD_REQUIRE_POSTGRES=1 \
  -e TRACESETTLE_GUARD_STATE_PG_DSN="postgresql://USER:PASS@HOST:5432/DB" \
  tracesettle:production-candidate
# in another shell:
curl -s http://127.0.0.1:8000/api/health
curl -s -H "X-API-Key: throwaway" http://127.0.0.1:8000/api/guard/metrics
```

Expected health: `{"status":"ok","tool":"TRACESETTLE",...,"read_only":true}`.
Metrics must report `state.backend: "postgresql"` and `state.durable: true`.

Also confirm the two fail-closed paths (they must exit non-zero, not serve):

```sh
# no credentials -> refuse
docker run --rm tracesettle:production-candidate            # exit 2
# PG required but not configured -> refuse
docker run --rm -e TRACESETTLE_API_KEY=x \
  -e TRACESETTLE_GUARD_AUTH_KEY="$KEY" \
  -e TRACESETTLE_GUARD_REQUIRE_POSTGRES=1 \
  tracesettle:production-candidate                          # exit 2
```

## 4. Provision PostgreSQL

- Create a managed PostgreSQL instance in the same region as the app.
- Note the **direct** connection string (or session-pooler on `:5432`).
- Set `ssl` as the provider requires; keep certificate verification on.
- Create the database and a least-privilege role for the app (the app creates its
  own tables on first start; it needs DDL on its own schema).
- Record the connection budget: `instances x 2` connections is ample.

## 5. Set environment variables on the platform

Use `.env.production.example` as the checklist. Mandatory for a public deploy:

| Variable | Value |
| --- | --- |
| `TRACESETTLE_API_KEY` | generated in step 1 |
| `TRACESETTLE_GUARD_AUTH_KEY` | generated in step 1 (stable) |
| `TRACESETTLE_GUARD_STATE_BACKEND` | `postgresql` |
| `TRACESETTLE_GUARD_STATE_PG_DSN` | the direct connection string |
| `TRACESETTLE_GUARD_REQUIRE_POSTGRES` | `1` |
| `TRACESETTLE_NEAR_RPC_URL` | `https://free.rpc.fastnear.com` |
| `TRACESETTLE_NEAR_RPC_FALLBACK_URL` | your paid archive endpoint |

Optional: `TRACESETTLE_GUARD_AUDIT_LOG=/data/audit.jsonl` plus a persistent volume
mounted at `/data` owned by uid `10001`.

## 6. Deploy

- Deploy the image by digest (immutable) rather than a mutable tag.
- Health check path: `/api/health`.
- One instance is sufficient; add instances only because of load, since
  PostgreSQL makes them share state safely.

## 7. Post-deploy verification

```sh
curl -s https://<host>/api/health
# unauthorized call must be 401
curl -s -o /dev/null -w '%{http_code}\n' https://<host>/api/guard/metrics
# authorized call must be 200 and report postgresql + durable
curl -s -H "X-API-Key: $TRACESETTLE_API_KEY" https://<host>/api/guard/metrics
```

Confirm: health `200`; unauthenticated guard read `401`; authorized metrics show
`state.backend: "postgresql"` and `state.durable: true`. Then run one investigation
through `POST /api/investigate` and confirm it returns a report.

## 8. Record the deployment

- Note the image digest, the commit SHA, and the deploy time.
- Preserve the audit log's current head digest externally (see
  `AUDIT_ANCHORING.md` §7) — anchoring is not automated yet.

## 9. Rollback

See `ROLLBACK_RUNBOOK.md`.
