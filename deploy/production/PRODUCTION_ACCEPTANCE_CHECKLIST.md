# TRACESETTLE — production acceptance checklist

Every box below was verified locally on 2026-11-01 against master
`1bd7d8f23226fb403d4854483e1a2f1e27c47cf3`. Items that require an account,
payment, or authorization are marked **[post-authorization]** and were **not**
performed.

## A. Image build

- [x] `docker build --build-arg TRACESETTLE_WITH_POSTGRES=1 -t tracesettle:production-candidate .` succeeds.
- [x] `psycopg 3.3.6` importable in the image.
- [x] Runs as non-root: `User=tracesettle`, container `uid=10001`.
- [x] `EXPOSE 8000`; `TRACESETTLE_HOST=0.0.0.0`, `PORT=8000` set in the image.
- [x] No secrets in image env or layers (only the non-secret vars above).
- [x] Healthcheck present, probing `/api/health`.

## B. Runtime behaviour

- [x] Health endpoint returns `200` `{"status":"ok","tool":"TRACESETTLE",...,"read_only":true}`.
- [x] Guard metrics reachable with `X-API-Key`; unauthorized read returns `401`.
- [x] With PostgreSQL configured, `state.backend="postgresql"`, `state.durable=true`.
- [x] Graceful shutdown: exit `0` within 1 s of `docker stop`.
- [x] Non-root user cannot be assumed; container runs as uid `10001`.

## C. Fail-closed startup

- [x] No credentials on the public bind → exit `2`, message
      `refusing to start: binding a public interface (host='0.0.0.0') requires authentication`.
- [x] `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` with a non-PostgreSQL backend → exit `2`.
- [x] PostgreSQL backend with an unreachable DSN → exit `2`
      (`refusing to start: cannot connect to the PostgreSQL state database`), DSN not printed.

## D. PostgreSQL shared state

- [x] Migration serialised by a session advisory lock across the inspect-and-migrate
      sequence (first-deploy race fixed in `65e96c5`).
- [x] Cross-instance replay refused; shared spend window enforced; revocation visible
      across instances; idempotency single across instances (24/24 PG tests, 0 skipped).
- [x] Connection pooling compatibility documented: **direct or session mode** required;
      transaction-mode poolers break the migration lock (`ARCHITECTURE.md` §3).

## E. Code quality and safety

- [x] Full suite with live PostgreSQL: **740 passed**.
- [x] PostgreSQL integration: **24 passed, 0 skipped**.
- [x] `pyflakes` clean; `compileall` OK.
- [x] Structural security invariants: **16/16 hold**.
- [x] Offline demo byte-identical across runs (determinism preserved).

## F. Configuration package

- [x] `.env.production.example` — placeholders only, no real values.
- [x] Every variable it lists exists in `tracesettle/config.py` (no invented names).
- [x] Mandatory/optional/secret roles documented.
- [x] Secret-scan of all new files: no credential-shaped strings.

## G. Documentation

- [x] `ARCHITECTURE.md`, `DEPLOYMENT_RUNBOOK.md`, `ROLLBACK_RUNBOOK.md`,
      `INCIDENT_RESPONSE.md`, `MONITORING.md`, `COST_ESTIMATE.md`,
      `NEAR_ARCHIVAL_RPC.md`, `AUDIT_ANCHORING.md` present and internally consistent.
- [x] `AUDIT_ANCHORING.md` states clearly that anchoring is **not implemented**.
- [x] `NEAR_ARCHIVAL_RPC.md` records the live probe results and marks untested
      providers **UNVERIFIED**.

## H. Not performed (requires authorization / external account)

- [ ] **[post-authorization]** Build the image with the real production secrets and deploy it.
- [ ] **[post-authorization]** Provision managed PostgreSQL and set the DSN.
- [ ] **[post-authorization]** Set a stable `TRACESETTLE_GUARD_AUTH_KEY` and `TRACESETTLE_API_KEY` in the platform secret manager.
- [ ] **[post-authorization]** Point the NEAR fallback at a paid archive node.
- [ ] **[post-authorization]** Implement external audit-chain anchoring (`AUDIT_ANCHORING.md`).
- [ ] **[post-authorization]** Owner: revoke/rotate the previously exposed GitHub credential.

## I. Verdict

Production **preparation** is complete and locally verified. Deployment itself
remains pending authorization, and several prerequisites depend on external
accounts, payment, or owner actions (section H). No production resource was
created or changed.
