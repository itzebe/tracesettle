# TRACESETTLE — zero-budget architecture and cost

**Constraint: $0. No purchases, no paid subscriptions, no paid infrastructure, no
credit-card commitments, and no service that requires payment to continue.**

This document replaces the earlier paid-tier plan. Everything recommended here is
free **without** a payment method. A free trial that becomes paid is not free and
is excluded. A "free tier" that requires a credit card at sign-up is excluded
unless the owner explicitly authorizes the card.

Verified against provider documentation on 2026-11-01. Where a claim is a probe
result from this environment it says so; where it is from provider docs it is
quoted.

## 1. What TraceSettle actually needs

| Need | Why | Free-satisfiable? |
| --- | --- | --- |
| Docker/container host running Python | the only process | Yes (with caveats, §2) |
| Environment variables / secrets | API key, signing key, DSN | Yes |
| Health check + graceful shutdown | deploy safety | Yes |
| **Always-on** process | the guard must enforce continuously | **No free, card-free option found** |
| PostgreSQL, **direct/session** connection | shared state + session advisory lock in migration | Yes (Neon free) |
| Persistent storage for the audit log | tamper-evident record | Limited (ephemeral filesystem on free hosts) |
| Historical NEAR archival RPC | old settlement evidence | **No verified free permanent option** |

The two hard blockers are **always-on** and **free archival NEAR**. Everything
else has a genuine free answer.

## 2. Free hosting — what exists, and the trap

| Platform | Card required? | Free tier permanent? | Sleeps / scales to zero? | Docker? | Persistent disk? | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **Render** (Free web service) | **No** — docs: "No payment is required" | Yes, no expiry | **Yes** — spins down after 15 min idle, ~1 min to wake | Yes | No on free (ephemeral FS) | **Best card-free option; demonstration/limited only** |
| Koyeb (Free instance) | **Yes** — since Feb 2026 a card with a $29 hold is required | Yes | Yes — scales to zero after 1 h | Yes | No | Excluded (card) |
| Northflank (Sandbox) | **Yes** — card requested at sign-up as anti-abuse verification | Yes | No — always-on | Yes | Limited | Excluded (card) |
| Oracle Cloud (Always Free) | **Yes** for most users — docs: "most users need a mobile phone number and a credit card to create an account" | Yes | No | Yes (VM) | Yes | Excluded (card) |
| Fly.io | Yes — no free tier for new orgs | No (2-hour trial) | — | Yes | Yes | Excluded (trial + card) |
| Railway | Trial credit only | No | — | Yes | Yes | Excluded (trial) |
| Google Cloud Run / App Engine | Billing account (card) required | Free allowance only | Yes (scale to zero) | Yes | No | Excluded (card) |

**Conclusion.** The only genuinely card-free, permanent container host found is
**Render's Free web service**. It is **not always-on**: it spins down after 15
minutes without traffic and takes about a minute to wake. That makes it suitable
for a **demonstration or limited deployment**, not for a service that must
enforce authorization continuously.

## 3. Free PostgreSQL

| Provider | Card? | Permanent free? | Session advisory locks? | Pauses / scales to zero? | Storage | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **Neon** (Free) | **No** — docs: "no credit card required" | Yes, "no time limits" | **Yes on the direct host**; **no** on the `-pooler` (transaction mode) | Yes — compute suspends after 5 min idle | 1 GB/project, 100 CU-hours/month | **Recommended** |
| Supabase (Free) | No | Yes, with caveats | Yes on direct `:5432` or **session** pooler `:5432`; **no** on `:6543` (transaction) | Pauses after inactivity (restore manually) | 500 MB/project, 2 active projects | Viable alternative |
| Render PostgreSQL (Free) | No | **No — expires 30 days after creation** | Direct only (no managed pooling on free) | — | 1 GB | **Excluded (30-day expiry)** |

**Recommendation: Neon Free, direct connection string.**
- Neon's own docs state that **session-level advisory locks are not supported on
  the pooled (transaction-mode) connection** and that you must "use the direct
  connection string for tools that need session state (…, migrations …)". TraceSettle's
  migration takes a **session-scoped** advisory lock, so the DSN must be the
  **direct** host (no `-pooler` suffix).
- A transaction-mode pooler is unusable for a second, independent reason: the
  `psycopg` driver prepares statements after 5 executions, and those named
  prepared statements do not survive the pooler's backend remap — a second
  connection raises `DuplicatePreparedStatement` on a guard decision. Reproduced
  against PgBouncer 1.26.1 (`pool_mode=transaction`). So the direct host is
  required for the decision path too, not only the migration.
- Neon Free is permanent and needs no card. Its limits (1 GB, 100 CU-hours/month,
  5 GB egress/month, scale-to-zero after 5 min) are ample for a low-traffic guard,
  but scale-to-zero adds a cold start to the first request after idle.

**Not chosen:** Render Free Postgres expires after 30 days — it cannot host a
continuous guard.

## 4. Free NEAR archival RPC — no verified permanent option

Probed read-only on 2026-11-01 (single request each, public endpoints, no keys,
within rate limits):

| Endpoint | Result for historical tx `5E3Gdbhw…ypFb` | Interpretation |
| --- | --- | --- |
| `archival-rpc.mainnet.near.org` | **OK** (6 receipts, 9 logs, 3.6 s) | archival — but **deprecated and rate-limited** |
| `free.rpc.fastnear.com` | `UNKNOWN_TRANSACTION` | non-archival (the default primary) |
| `rpc.mainnet.near.org`, `near.drpc.org`, `rpc.fastnear.com`, `near-mainnet.gateway.tatum.io` | `UNKNOWN_TRANSACTION` | non-archival |
| `1rpc.io/near` | "the method tx does not exist/is not available" | `tx` disabled |
| `near.blockpi.network/…/public` | HTTP 503 "Apikey no…" | key required |
| `near.lava.build` | HTTP 410 "This endpoint has been discontinued." | discontinued |
| `rpc.ankr.com/near` | `Unauthorized: … API key` | key required |
| `near.nownodes.io` | HTTP 422 "Missing API_key" | key required |
| `archival-rpc.mainnet.pagoda.co`, `rpc.mainnet.pagoda.co` | HTTP 403 (rate-limit body) | blocked here |
| `allthatnode`, `getblock`, `chainstack`, `blastapi`, `nownodes` public hosts | DNS not resolvable / 404 | no public endpoint |

**Conclusion.** The **only** endpoint that resolved the historical transaction
without an account or key was `archival-rpc.mainnet.near.org`, the already-default
fallback, which NEAR documents as **deprecated and hard rate-limited**. No
genuinely free, permanent, key-free archival provider was verified. This is an
**unresolved limitation**, not a solved problem. See `NEAR_ARCHIVAL_RPC.md`.

## 5. Cost

| Line | Free path | Cost |
| --- | --- | --- |
| Application host | Render Free web service | **$0** |
| PostgreSQL | Neon Free (direct connection) | **$0** |
| Audit log storage | ephemeral filesystem on free host (lost on restart) | **$0** |
| NEAR archival RPC | deprecated free archive only (rate-limited) | **$0** |
| Monitoring | platform-native + a free uptime check | **$0** |
| Audit anchoring | OpenTimestamps (free; not implemented) | **$0** |
| **Total** | | **$0** |

There is no paid tier recommended anywhere in this package. If a capability
cannot be met for $0, it is documented as an unresolved limitation rather than
priced.

## 6. Honest capability matrix

| Capability | Result |
| --- | --- |
| Free application hosting | **Verified** (Render Free; card-free, permanent) |
| Free PostgreSQL | **Verified** (Neon Free; card-free, permanent) |
| Session advisory locks | **Verified on Neon direct connection**; unsupported on any transaction-mode pooler |
| Free NEAR archival RPC | **Unverified / Unavailable** — only a deprecated rate-limited endpoint works |
| Persistent storage | **Limited** — free host filesystem is ephemeral; audit log does not survive restart |
| Security guarantees | **Preserved** (no guarantee is weakened by this architecture) |
| Always-on enforcement | **Unavailable for free** — the free host sleeps, the free database scales to zero |
| Production readiness | **Not ready** — a free deployment is a demonstration, not production |

## 7. What this means

A **free demonstration deployment is feasible**: Render Free (card-free) + Neon
Free (card-free) + the deprecated free NEAR archive. It demonstrates the
investigator, the guard's ALLOW/BLOCK/REQUIRE_APPROVAL decisions, signer
authorization, PostgreSQL shared state, and the fail-closed behaviour.

A **production-grade deployment is not genuinely possible at $0**: the guard must
be always-on to enforce continuously, and every card-free host found either sleeps
or scales to zero; the only free archival NEAR endpoint is deprecated and
rate-limited. Those two gaps are the reason. See `PRODUCTION_ACCEPTANCE_CHECKLIST.md`.
