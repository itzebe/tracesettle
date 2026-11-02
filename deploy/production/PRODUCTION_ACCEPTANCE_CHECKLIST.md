# TRACESETTLE — zero-budget acceptance checklist

Every item below was verified locally on 2026-11-01 against master
`1bd7d8f23226fb403d4854483e1a2f1e27c47cf3`. Items that require an account,
payment, or authorization are marked **[post-authorization]** and were **not**
performed. No purchase, subscription, or credit card is required by anything in
the recommended architecture.

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
- [x] Container runs as uid `10001`.

## C. Fail-closed startup

- [x] No credentials on the public bind → exit `2`.
- [x] `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` with a non-PostgreSQL backend → exit `2`.
- [x] PostgreSQL backend with an unreachable DSN → exit `2`, DSN not printed.

## D. PostgreSQL shared state

- [x] Migration serialised by a session advisory lock across the inspect-and-migrate
      sequence.
- [x] Cross-instance replay refused; shared spend window enforced; revocation visible
      across instances; idempotency single across instances (24/24 PG tests, 0 skipped).
- [x] Connection pooling compatibility documented: **direct or session mode** required
      for the migration lock; Neon documents session advisory locks as unsupported on
      the pooled connection (`ARCHITECTURE.md` §3).

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
- [x] No paid service is recommended anywhere in the package.

## G. Documentation

- [x] `ARCHITECTURE.md`, `DEPLOYMENT_RUNBOOK.md`, `ROLLBACK_RUNBOOK.md`,
      `INCIDENT_RESPONSE.md`, `MONITORING.md`, `COST_ESTIMATE.md`,
      `NEAR_ARCHIVAL_RPC.md`, `AUDIT_ANCHORING.md` present and internally consistent.
- [x] `AUDIT_ANCHORING.md` states clearly that anchoring is **not implemented**.
- [x] `NEAR_ARCHIVAL_RPC.md` records the live probe results and states the free
      archival gap as unresolved.
- [x] The free host, free database, and free-archive limitations are stated, not
      hidden.

## H. Capability matrix (honest)

| Capability | Result | Basis |
| --- | --- | --- |
| Free application hosting | **Verified** | Render Free web service — docs: "No payment is required" |
| Free PostgreSQL | **Verified** | Neon Free — docs: "no credit card required", "no time limits" |
| Session advisory locks | **Verified on direct connection**; **Unsupported** on transaction-mode poolers | Neon docs list "Session-level advisory locks" as unsupported on pooled connections |
| Free NEAR archival RPC | **Unverified / Unavailable** | only the deprecated, rate-limited `archival-rpc.mainnet.near.org` resolves historical tx |
| Persistent storage | **Limited** | free host filesystem is ephemeral; a persistent volume needs a paid host |
| Security guarantees | **Preserved** | no guard property is weakened by this architecture |
| Always-on enforcement | **Unavailable for free** | card-free hosts sleep (Render 15 min; Koyeb/Northflank require a card) |
| Production readiness | **Not ready** | a free deployment is a demonstration |

## I. Not performed (requires authorization / external account)

- [ ] **[post-authorization]** Deploy to a card-free host with real secrets.
- [ ] **[post-authorization]** Provision Neon Free and set the **direct** DSN.
- [ ] **[post-authorization]** Implement external audit-chain anchoring (`AUDIT_ANCHORING.md`).
- [ ] **[post-authorization]** Owner: revoke/rotate the previously exposed GitHub credential.

## J. Verdict

**A free demonstration deployment is feasible** (Render Free + Neon Free + the
deprecated free NEAR archive) and every repository-side artifact is verified.

**A production-grade deployment is not possible at $0.** Two capabilities cannot
be met without paying: **always-on compute** (every card-free host found sleeps or
scales to zero) and a **reliable NEAR archive** (the only free one is deprecated
and rate-limited). Persistent audit storage is likewise a paid capability. None of
these were purchased or provisioned. No production resource was created or changed.
