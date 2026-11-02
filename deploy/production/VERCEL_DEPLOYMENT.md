# TRACESETTLE on Vercel — Hobby (zero-budget) deployment

How to run TraceSettle as a read-only settlement-investigation and transaction-
authorization service on **Vercel Hobby** using the **Container Runtime** (an OCI
image built from a Dockerfile and run as an autoscaling Vercel Function).

This guide is for the *host*. For the application's own configuration (every
environment variable, the guard key format, the honest limits), see
`README.md` and the rest of `deploy/production/`. Nothing here has been deployed;
no Vercel project has been created for this repository.

**Verdict up front:** a Vercel Hobby demonstration deployment is feasible and has
been verified locally end to end. Vercel Hobby is a **non-commercial, fair-use**
tier, so this is a demonstration/limited deployment, not a production one. Two
zero-budget caveats are called out in §8 and §10.

## 1. Files this deployment adds

| File | Role |
| --- | --- |
| `Dockerfile.vercel` | The Vercel image. A `Dockerfile.vercel` selects Vercel's Container preset, so Vercel builds *this* file rather than the generic root `Dockerfile`. |
| `vercel.json` | Pins the container to `Dockerfile.vercel` and routes all traffic to it, so the built image is unambiguous even if a framework is ever detected. |
| `.dockerignore` (updated) | Adds `.vercel` (local CLI state) to the build-context exclusions. |
| `.gitignore` (updated) | Adds `.vercel/` (local CLI state; can hold org/project ids). |

The existing production `Dockerfile` is **unchanged**: `Dockerfile.vercel` is an
additive, Vercel-specific variant, not a replacement. The build context is the
repository root, so both files coexist.

## 2. Why a second Dockerfile

`Dockerfile.vercel` differs from the production `Dockerfile` in exactly two ways,
both required by Vercel:

1. **The PostgreSQL driver is always installed.** The production image makes the
   driver opt-in (`--build-arg TRACESETTLE_WITH_POSTGRES=1`). Vercel's container
   build passes **no Docker build arguments** (the `services` schema has no
   `buildArgs` key — verified against `https://openapi.vercel.sh/vercel.json`),
   so the driver is baked in unconditionally. It is the single optional runtime
   extra; the runtime stays standard-library-only and imports it lazily.
2. **It defaults to port 80.** Vercel routes container traffic to port `80`
   unless the project `PORT` environment variable overrides it. `PORT` is still
   read first, so both work.

Everything else (non-root uid 10001, `0.0.0.0` bind, `python -m tracesettle
serve`, the healthcheck, no secrets in the image) is identical to production.

## 3. Why `vercel.json` is present

A root `Dockerfile` is enough when Vercel detects no other framework, and a
`Dockerfile.vercel` takes precedence over a *detected framework*. This repository
has no framework files (`package.json`, `pyproject.toml`, `requirements.txt`), so
detection would already fall through to a Dockerfile. The `vercel.json` is
present for one reason: to state **explicitly** that the container is built from
`Dockerfile.vercel`, so the image can never be built from the generic root
`Dockerfile` (which would silently drop the PostgreSQL driver and disable durable
guard state). It is validated against the official schema:

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "services": {
    "tracesettle": { "root": ".", "runtime": "container", "entrypoint": "Dockerfile.vercel" }
  },
  "rewrites": [{ "source": "/(.*)", "destination": { "service": "tracesettle" } }]
}
```

A single service plus a catch-all rewrite means every public path (`/`,
`/console`, `/api/health`, `/api/investigate`, `/api/guard/*`) reaches the app
unchanged. No path is intercepted.

## 4. Configuration to set in the Vercel project

Set these as Vercel **environment variables** (Project → Settings → Environment
Variables). None is committed; the repository carries placeholders only.

| Variable | Value | Why |
| --- | --- | --- |
| `TRACESETTLE_API_KEY` | a long random string | **Required.** Vercel binds a public interface, so the server refuses to start without it. Gates `/api/investigate` and `/api/guard/*` (header `X-API-Key`). |
| `TRACESETTLE_GUARD_AUTH_KEY` | ≥32 bytes, hex or base64 | **Required.** Signs authorization tokens. Must be stable across restarts and identical on every instance. Generate once: `python3 -c "import secrets;print(secrets.token_hex(32))"`. |
| `TRACESETTLE_GUARD_STATE_BACKEND` | `postgresql` | Durable guard state (spent nonces, revocation, velocity). |
| `TRACESETTLE_GUARD_STATE_PG_DSN` | a Postgres DSN | The database. See §6. |
| `TRACESETTLE_GUARD_REQUIRE_POSTGRES` | `1` | Fail closed: refuse to start on any other backend. |
| `TRACESETTLE_NEAR_RPC_FALLBACK_URL` | a NEAR **archive** RPC | Historical NEAR lookups. See §8. |
| `PORT` | *(leave unset)* | Only set this to move off port 80. |

Do **not** set `TRACESETTLE_AUDIT_LOG_PATH`: a Vercel Function filesystem is
read-only except `/tmp`, and `/tmp` is ephemeral. The audit log is intentionally
left unset. The append-only audit chain is not durable on Vercel (see §8).

## 5. Deploy

1. Create the project and link it (once):
   ```sh
   vercel link            # choose the itzebe scope, create a new project named tracesettle
   ```
2. Confirm the framework preset is Container (Vercel selects it automatically
   for a repository with no detected framework):
   ```sh
   vercel project update --framework container --yes
   ```
3. Add the environment variables from §4 (`vercel env add`, or the dashboard),
   for the **Production** environment.
4. Deploy:
   ```sh
   vercel deploy --prod
   ```
   Vercel builds `Dockerfile.vercel`, pushes the image to Vercel Container
   Registry (VCR), and runs it as a Function.
5. Verify (replace the host with the deployment URL):
   ```sh
   curl -s https://<deployment>/api/health
   # -> {"status": "ok", "tool": "TRACESETTLE", "version": "0.2.0", "read_only": true}
   curl -s -o /dev/null -w '%{http_code}\n' https://<deployment>/
   # -> 200
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<deployment>/api/investigate
   # -> 401   (no API key)
   curl -s -o /dev/null -w '%{http_code}\n' -H 'X-API-Key: <key>' https://<deployment>/api/guard/metrics
   # -> 200
   ```

For local orchestration of the same container, `vercel dev --local` builds
`Dockerfile.vercel` and runs it as a Function. It requires the Docker CLI and
daemon. Export the §4 variables into the shell first (with `--local` there is no
linked project for `vercel env pull` to populate), and point the DSN at an
address the container can reach (see §6).

## 6. The database

The guard's durable state (spent nonces, idempotency, revocation, velocity) needs
a shared PostgreSQL when more than one instance can serve a request. Vercel
Functions autoscale and scale to zero, so **there is more than one instance in
practice** and shared state is required — hence `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1`.

- The application uses **session-scoped advisory locks** (`pg_advisory_xact_lock`,
  `pg_advisory_lock`). Use a **direct** connection (or session pooling), not a
  transaction-pooling pooler, or the locks are released between statements.
- On the **Hobby** plan the project has no built-in database, so provide an
  external Postgres. Free serverless Postgres tiers exist (for example Neon's
  free plan, whose direct connection host is what this app needs), but they are
  outside Vercel and are a separate account. **No database is included by this
  guide and none was created.**
- If the database is unreachable, the server **refuses to start** (fail closed)
  rather than silently falling back to per-instance memory.

## 7. Port and lifecycle behaviour on Vercel

| Behaviour | Value | Consequence here |
| --- | --- | --- |
| Port | `80` by default | The image defaults `PORT=80`; override via the project `PORT` variable. |
| Scale to zero | 5 min idle (production), 30 s (preview) | Cold start builds on first request; the image is a small `python:3.13-slim`, so this is seconds, not minutes. |
| Shutdown signal | `SIGTERM`, 30 s grace | The app installs a `SIGTERM` handler and stops cleanly (measured < 1 s). |
| Filesystem | read-only except `/tmp`, ephemeral | The audit log is left unset; nothing else is written. |
| Max duration | 300 s (Hobby default and maximum) | An investigation is a handful of bounded RPC reads, far under this. |
| Memory | up to 2 GB (Hobby) | The app is small; the default allocation is ample. |

## 8. Zero-budget caveats (read these)

- **Hobby is non-commercial, fair-use.** Deploying this on Hobby is a
  demonstration, not commercial production. If this is used commercially, the
  plan must change.
- **Vercel Container Registry storage is billed at $0.10/GB**, and the Hobby
  included-usage table does not list a container-registry allowance. A
  `python:3.13-slim` image with `psycopg[binary]` is a few hundred MB, so storage
  cost is cents, but it is not a documented free allowance. Confirm the current
  allowance on the Vercel pricing page before relying on it.
- **Historical NEAR lookups are best-effort.** Only the deprecated, rate-limited
  free archive (`archival-rpc.mainnet.near.org`) is free; every other free NEAR
  provider is non-archival. Set `TRACESETTLE_NEAR_RPC_FALLBACK_URL` to a paid
  archive node for reliable historical verification (see
  `NEAR_ARCHIVAL_RPC.md`).
- **The audit chain is not durable on Vercel.** With no writable volume the
  append-only audit log is off; anchoring is unimplemented.
- **Per-client rate limiting degrades behind the Vercel edge.** The app keys the
  per-client limit on the TCP peer address and deliberately does not trust
  `X-Forwarded-For` (so a spoofed header cannot bypass it). Behind Vercel's proxy
  the peer is the proxy, so that limit becomes effectively per-instance. Vercel's
  own Firewall is the layer to add per-client controls.
- **Container Runtime is beta.**

## 9. What was verified locally

Performed against this branch, with a real Docker daemon and a real PostgreSQL:

| Check | Result |
| --- | --- |
| `docker build -f Dockerfile.vercel` | builds; `psycopg 3.3.6` present; `USER=tracesettle`; `EXPOSE 80` |
| Default `PORT=80`, health on `/api/health` | `200` |
| `PORT=8080` override | serves on 8080 |
| Unauthenticated `/api/investigate` | `401` |
| Guard metrics with the API key | `200`; `state.backend=postgresql`, `state.durable=true` |
| Guard evaluate through the container | `200`; a denylisted destination returns `decision=BLOCK` |
| Guard sign with no authorization | `200`; `outcome=REFUSED`, `state=MISSING` (never signs) |
| Read-only root filesystem (`--read-only`) with Postgres | health `200` |
| `SIGTERM` shutdown | exits in < 1 s |
| Missing credentials on a public bind | refuses to start, exit 2 |
| `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` without a DSN | refuses to start, exit 2 |
| Unreachable DSN | refuses to start, exit 2 |
| `vercel dev --local` (official local container orchestration) | builds `Dockerfile.vercel`, runs it; `/` `200`, `/api/health` `200`, `/console` `200`, unauthenticated guard `401`, authenticated guard `200`, malformed body `400` |
| `vercel.json` | validates against `https://openapi.vercel.sh/vercel.json` |
| Full test suite | `741 passed` |
| `pyflakes`, `compileall`, offline demo determinism | clean, OK, byte-identical |

## 10. Honest limitations

- Not deployed, and no Vercel project was created. This is a prepared,
  locally-verified configuration.
- Hobby-only, non-commercial, beta runtime; no SLA.
- A shared PostgreSQL is required for durable guard state and is a separate
  account (see §6); none is provisioned here.
- Historical NEAR verification needs a paid archive node to be reliable.
- The audit log is not durable and anchoring is unimplemented.
- A previously exposed GitHub credential remains an **open, owner-side**
  revocation item (see `INCIDENT_RESPONSE.md`).

## 11. Rollback

Delete the deployment in the Vercel dashboard, or `vercel remove tracesettle`.
Nothing in the repository or any database is changed by a rollback. The generic
`Dockerfile` remains valid for any other container host (Render, Fly, Cloud Run).
