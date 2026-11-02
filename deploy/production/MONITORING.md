# TRACESETTLE — monitoring and alerting plan

Every "available today" item below is **verified in code**; the source is named.
Anything not implemented is listed as future work — no metric is claimed that
does not exist.

## 1. Observability that exists today (verified)

| Signal | Source | How to read it |
| --- | --- | --- |
| Liveness | `GET /api/health` | `ui.py` — always `200` with `{"status":"ok",...,"read_only":true}` while the process runs. **Does not probe the database.** |
| Decision counters | `GET /api/guard/metrics` → `counts` | `guard/monitor.py` — `evaluated`, `ALLOW`, `REQUIRE_APPROVAL`, `HOLD`, `BLOCK`, `authorizations_issued`, `signings_executed`, `signer_refusals`, `open_incidents`. |
| Open incidents | `GET /api/guard/metrics` → `open_incidents_by_severity`; `GET /api/guard/incidents?status=OPEN` | `guard/monitor.py` — rule-driven, deterministic incidents. |
| State backend posture | `GET /api/guard/metrics` → `state.backend`, `state.durable`, `state.note` | `guard/service.py:metrics()` — `postgresql` / `true` / "durable shared state across instances". |
| Signing key posture | `metrics` → `authorization.key_id`, `authorization.ephemeral_key` | `guard/service.py` — `ephemeral_key: true` means `TRACESETTLE_GUARD_AUTH_KEY` is unset (not production). |
| Audit-chain length + head | `metrics` → `audit.length`, `audit.head_digest` | `guard/audit.py:head_digest` — the value to anchor externally. |
| Audit records | `GET /api/guard/audit?limit=N` | `guard/api.py` — recent records. |
| Application log | process stdout/stderr | `ui.py` — all client errors are generic; internals go to the server log only. No keys or raw identifiers are logged. |
| Container health | Docker `HEALTHCHECK` → `/api/health` | `Dockerfile` |

All `GET /api/guard/*` reads require `X-API-Key` when one is configured.

## 2. What does **not** exist (do not assume it)

- **No readiness endpoint.** There is no `/api/ready` and `/api/health` does not
  check PostgreSQL. Liveness and database health are not distinguished by the app.
- **No metrics endpoint in Prometheus/OpenMetrics format.** Metrics are JSON via
  `/api/guard/metrics`, not a scrape target.
- **No structured (JSON) log stream** — logs are plain text to stdout/stderr.
- **No built-in external anchor or anchor check** for the audit head digest
  (see `AUDIT_ANCHORING.md`).
- **No per-request latency/error histograms.**
- **No alert delivery** — no webhook/email; alerting is the platform's job.

These are the concrete gaps the monitoring plan below works around with
platform-native tools.

## 3. Alerts

### Critical (page)

| Alert | Condition | Source | Recovery |
| --- | --- | --- | --- |
| Process down | health check failing for > 1 min | platform health check on `/api/health` | restart; see `INCIDENT_RESPONSE.md` §C |
| Startup refused | container exits with code `2` repeatedly | platform deploy logs | fix the named missing variable/DSN; see §A/§B of the incident runbook |
| Store not PostgreSQL | `state.backend != "postgresql"` or `state.durable == false` | `/api/guard/metrics` poll | fix backend env; a non-durable store loses replay protection on restart |
| Guard failing closed | `counts.HOLD` rising while `counts.evaluated` is flat, or guard calls erroring | `/api/guard/metrics` + platform logs | database connectivity; see §A |

### Warning (ticket)

| Alert | Condition | Source | Recovery |
| --- | --- | --- | --- |
| Ephemeral signing key | `authorization.ephemeral_key == true` | `/api/guard/metrics` | set a stable `TRACESETTLE_GUARD_AUTH_KEY` and redeploy |
| Signer refusals | `counts.signer_refusals` > 0 sustained | `/api/guard/metrics` | investigate the refusals (`/api/guard/audit`) |
| Open incidents | `open_incidents_by_severity` non-empty | `/api/guard/metrics` | review `/api/guard/incidents?status=OPEN` |
| Blocks/denials | `counts.BLOCK` or `counts.HOLD` jumps | `/api/guard/metrics` | review audit records; may be an attack |
| Rate limiting | `429` responses on `/api/*` | platform access logs / `Retry-After` headers | confirm the limit is intended; raise it if legitimate |
| Audit log growth | `audit.length` at `TRACESETTLE_GUARD_AUDIT_MAX_RECORDS` | `/api/guard/metrics` | export and rotate the audit volume (the chain stays intact on disk) |
| NEAR archive degradation | settlement stages reported `UNAVAILABLE` for historical tx | investigation reports | see §D of the incident runbook; check archive `429`s |

## 4. Dashboard (suggested panels)

Poll `/api/guard/metrics` every 30–60 s and chart:

1. Decisions over time, split by `ALLOW / REQUIRE_APPROVAL / HOLD / BLOCK`.
2. `authorizations_issued` vs `signings_executed` vs `signer_refusals`.
3. `state.backend` and `state.durable` (must be `postgresql` / `true`).
4. `authorization.ephemeral_key` (must be `false`).
5. `open_incidents_by_severity`.
6. `audit.length` and `audit.head_digest` (the head changes ⇒ new events).
7. Container health status and restart count (platform).
8. PostgreSQL connection count and `429`/error rate (platform/database).

## 5. Suggested thresholds

- Process restart count > 2 in 10 min → critical.
- `HOLD` rate > 5% of `evaluated` over 10 min → critical (likely store outage).
- `signer_refusals` > 0 in 15 min → warning.
- `open_incidents` (any severity) > 0 → warning; CRITICAL severity → critical.
- `ephemeral_key == true` at any time in production → warning immediately.
- `state.durable == false` in production → critical.
- NEAR archive `UNAVAILABLE` for > 30 min → warning.

## 6. What not to log

- Never log `TRACESETTLE_API_KEY`, `TRACESETTLE_GUARD_AUTH_KEY`, the DSN, or
  service credentials. The code already keeps them out of responses and generic
  error messages.
- Never log full identifiers of user transactions beyond what the audit log
  records (ids, outcomes) — the design keeps raw key material out of output
  (`no_key_material_in_output`).

## 7. Future work (proposed, not implemented)

- A `/api/ready` that probes the state store (cheap `SELECT 1`), so readiness
  reflects database health.
- Prometheus/OpenMetrics exposition alongside the JSON metrics.
- Structured JSON logging.
- Automated audit-head anchoring + divergence monitoring
  (`AUDIT_ANCHORING.md`).
