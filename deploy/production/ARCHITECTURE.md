# TRACESETTLE — production architecture

Read-only NEAR Intents settlement investigator plus a transaction authorization
guard. This document describes the production topology, the components, and the
runtime requirements. It reflects the code at `master` (merge commit
`1bd7d8f23226fb403d4854483e1a2f1e27c47cf3`, PR #6 merged).

## 1. Components

```
                      +-------------------------------+
   clients  --X-API-Key-->|  TRACESETTLE container      |
   (X-API-Key)            |  python -m tracesettle serve|
                           |                             |
                           |  ui.py  (http.server)       |
                           |   - GET /                   |
                           |   - GET /api/health         |
                           |   - POST /api/investigate   |---> upstream read-only
                           |   - /api/guard/*            |     JSON-RPC / REST
                           |                             |
                           |  guard/  authorization guard|
                           |   - policy, signer, audit   |
                           |   - state backend ----------|---> PostgreSQL (shared)
                           +-----------------------------+
```

- **`tracesettle/ui.py`** — the only process. A standard-library `http.server`.
  Serves the investigator page, `GET /api/health`, `POST /api/investigate`, and
  the `/api/guard/*` endpoints. It binds `TRACESETTLE_HOST`:`PORT`.
- **Investigator** (`investigation.py`, `reconcile.py`, `adapters/`) — read-only.
  It queries 1Click status, the solver relay, NEAR RPC, EVM RPC, and Bitcoin
  (Esplora) endpoints, then reconciles evidence deterministically. It never
  signs, submits, or moves funds.
- **Guard** (`guard/`) — the transaction authorization firewall. Evaluates a
  requested transaction against a policy, issues a signed single-use
  authorization, and only then allows the reference signer to "execute" (a
  `SimulatedExecutor` that records the request and never broadcasts). See the
  honesty note in section 5.
- **Guard state** (`guard/state.py`, `guard/state_pg.py`) — durable nonces,
  spending counters, revocations, and idempotency keys. Shared across instances
  through PostgreSQL.

## 2. Why PostgreSQL (and only for more than one instance)

The guard's security properties — a nonce is single-use, a spending window is
summed, a revocation is seen everywhere, an idempotency key yields one
authorization — must hold **across** instances. SQLite gives that only within one
process/host. PostgreSQL gives an atomic read-decide-write critical section across
hosts, serialised with a transaction-scoped advisory lock
(`pg_advisory_xact_lock`) plus a bounded `lock_timeout`.

- `TRACESETTLE_GUARD_STATE_BACKEND=postgresql` + `TRACESETTLE_GUARD_STATE_PG_DSN`
  select it. The driver (`psycopg`) is imported lazily.
- `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` refuses to start on any other backend.
  There is no override, so a deployment cannot silently lose shared state.
- A broken/unreachable store **fails closed** (`HOLD`, no authorization) and never
  falls back to process memory. A *dropped* connection is not a broken store: the
  next call reconnects, so a transient blip does not take an instance out of
  service.

Single-instance deployments may run SQLite (`TRACESETTLE_GUARD_STATE_DB`) or
in-memory state; that is the local-development posture and is not the production
target.

## 3. Connection-pooling compatibility (important)

Two different locks are used, and both must survive on the same backend
connection:

| Lock | Scope | Where | Pooler constraint |
| --- | --- | --- | --- |
| `pg_advisory_lock` (session) | one session | schema migration only | requires a **direct or session**-mode connection |
| `pg_advisory_xact_lock` | one transaction | per decision | transaction-scoped, but the *client* still needs its prepared statements to work — see below |

Two independent things break under a **transaction-mode** pooler:

1. The migration lock is session-scoped and is taken across the whole
   inspect-and-migrate sequence. A transaction-mode pooler remaps the backend
   connection at every transaction boundary, so a session lock acquired on one
   backend is not held by the next statement — the migration mutex silently stops
   protecting anything.
2. `psycopg` (the driver) prepares statements after 5 executions by default. Under
   a transaction-mode pooler those named prepared statements belong to a backend
   that the next transaction may not use, so a second connection gets
   `DuplicatePreparedStatement: prepared statement "_pg3_0" already exists` — a
   guard decision fails, not just the migration. **Reproduced** in this review
   against PgBouncer 1.26.1 in `pool_mode=transaction` with
   `max_prepared_statements=0` (the managed-pooler default): two concurrent
   clients produced `DuplicatePreparedStatement` on the second.

Therefore:

- **Use a direct connection or a session-mode pooler** for
  `TRACESETTLE_GUARD_STATE_PG_DSN` — for the migration lock *and* for the
  prepared statements the decision path uses.
- Do **not** use a transaction-mode pooler endpoint:
  - Neon: avoid the `-pooler` host (PgBouncer, `pool_mode=transaction`); use the
    direct host. **Neon's own documentation lists "Session-level advisory locks"
    among the features not supported with pooled connections**, and says to "use
    the direct connection string for tools that need session state (…,
    migrations …)". This is the reason the free Neon path must use the direct host.
  - Supabase: use the direct connection (`:5432` direct, or the **session**
    pooler on `:5432`); avoid the transaction pooler on `:6543`.
  - Render: avoid the PgBouncer pooled URL on `:6432`; use the direct URL. (Render
    Free Postgres does not offer managed pooling at all, but it expires in 30 days.)
- Connection **counts** stay tiny: one connection per instance handles a decision
  at a time; the store is not a connection-pooling workload. Size the database
  connection budget for `instances x (1 + 1 spare)`, not for request concurrency.

## 3a. Zero-budget connection notes

- **Neon Free** is the recommended card-free PostgreSQL. Use the **direct**
  connection string (no `-pooler`). Free compute **suspends after 5 minutes of
  inactivity** and resumes on the next connection, adding a cold start to the
  first guard decision after idle. This is acceptable for a demonstration; it is
  not a continuous-enforcement posture.
- The migration takes the session advisory lock once at start-up, and the
  per-decision lock is transaction-scoped (`pg_advisory_xact_lock`). That makes
  the *lock* pooler-safe, but a transaction-mode pooler is still unusable: the
  decision path's prepared statements do not survive the backend remap (see §3,
  reproduced against PgBouncer). **Both** the start-up migration **and** the
  per-decision path therefore require the direct/session connection.

## 4. Startup behaviour (fail-closed)

`securityconfig.py` runs **before** the listener opens:

- A loopback bind (`127.0.0.1`, `::1`, `localhost`) needs nothing — local dev.
- Any non-loopback bind (including `0.0.0.0`, `::`, or an unresolved host) is
  public and is **refused** unless both `TRACESETTLE_API_KEY` and
  `TRACESETTLE_GUARD_AUTH_KEY` are set. There is no environment override.
- `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` with a non-PostgreSQL backend is refused.
- An unopenable PostgreSQL store is refused (exit `2`); the DSN is never printed.
- `TRACESETTLE_REQUIRE_SERVICE_AUTH=1` without a credential store is refused.

The container image binds `0.0.0.0`, so it inherits every rule above.

## 5. Honesty boundaries (what is and is not real)

- **No real-funds execution.** The signer's executor is a `SimulatedExecutor`
  (`guard/signer.py`). It records the transaction it was asked to execute and is
  labelled simulated. No NEAR signing or broadcasting exists.
- **The investigator is read-only.** The only non-GET upstream calls are
  JSON-RPC reads.
- **The audit chain is tamper-evident, not tamper-proof.** In-place edits,
  reorders, and deletions are detectable by recomputation (`AuditLog.verify`).
  An attacker who can rewrite the whole log can recompute a consistent chain.
  Detecting that needs an external anchor over the head digest — see
  `AUDIT_ANCHORING.md`. Anchoring is **not implemented**; only the head digest is
  exposed.
- **NEAR historical lookups are best-effort.** Free NEAR nodes are non-archival;
  see `NEAR_ARCHIVAL_RPC.md`.

## 6. Data and secrets

- No payment data is stored. Guard state holds nonces, counters, revocation ids,
  and idempotency keys. The audit log holds event metadata (ids, outcomes), not
  key material — the design asserts `no_key_material_in_output`.
- Secrets (`TRACESETTLE_API_KEY`, `TRACESETTLE_GUARD_AUTH_KEY`, the DSN, service
  credentials) live only in the platform secret manager. They are never baked
  into the image, never logged, and never returned by an endpoint.

## 7. Deployment shape

One container image, one process, one PostgreSQL database, and (optionally) a
persistent volume for the audit log. The image is non-root (uid `10001`), exposes
`8000`, has a `/api/health` healthcheck, and shuts down gracefully. See
`DEPLOYMENT_RUNBOOK.md` for the concrete steps.

Under the **zero-budget** constraint the shape is the same, with two caveats:

- **Host:** Render **Free** web service — card-free and permanent, but it **spins
  down after 15 minutes of inactivity** and wakes in about a minute. A sleeping
  process enforces nothing, so this is a **demonstration/limited** deployment, not
  a continuously-enforcing production one.
- **Storage:** a free host filesystem is **ephemeral**. The on-disk audit log is
  lost on restart/spin-down, and Neon Free compute suspends after 5 minutes idle.
  A persistent volume and always-on compute both require a paid plan, which is out
  of scope.

For a full production posture you would need always-on compute and a persistent
volume; neither is available at $0. See `COST_ESTIMATE.md` §6–§7.
