# TRACESETTLE — platform selection and cost estimate

All figures are published list prices read 2026-11-01 and are estimates, not
quotes. Distinguish carefully:

- **Permanent free** — no time limit, no expiry.
- **Trial** — time- or credit-limited; not a production option.
- **Paid** — a real recurring cost.

## 1. Hosting platform selection

Requirements that decide this: **always-on** (no sleep — the guard must hold
state and enforce continuously), a **persistent PostgreSQL connection**, stable
configuration across restarts, secrets in environment variables, a health check,
graceful shutdown, Docker, and optionally a persistent volume for the audit log.

| Platform | Always-on | Docker | Health check | Graceful shutdown | Secrets | Persistent volume | Free tier | Smallest always-on cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Render** | Yes on paid | Yes | Yes | Yes | Yes | Yes | Free web **sleeps after 15 min**; free PG **expires in 30 days** | Web Starter **$7/mo** |
| Fly.io | Yes | Yes | Yes | Yes | Yes | Yes | None for new orgs (2-hour trial) | Machine **~$1.94–2.19/mo** (256 MB) |
| Railway | Yes | Yes | Yes | Yes | Yes | Yes | 30-day trial; limited free plan | Hobby **$5/mo** + usage |

### Recommendation: Render

**Why Render.** It is a managed container platform whose paid tier gives exactly
what TraceSettle needs with the least operational work: always-on web services,
native Docker deploys, a `/api/health` health check, graceful shutdown, secrets
as environment variables, persistent disks, and a **managed PostgreSQL in the same
region** so the app uses the internal network. The critical exclusions are all on
the **free** tier (which sleeps and expires a database), so the plan is a small
paid one, not the free tier.

**Runner-up: Fly.io.** Cheaper compute (~$2/mo for a 256 MB machine) but its
managed Postgres starts at $38/month, so you would run PostgreSQL elsewhere
(e.g. Neon) and accept a second vendor and more ops. Reasonable if cost matters
more than simplicity.

**Rejected: the free tiers of all three** — a sleeping web service and a database
that expires after 30 days cannot host a continuous authorization guard.

## 2. PostgreSQL provider selection

| Provider | Free tier | Permanent free? | Session advisory lock | Notes |
| --- | --- | --- | --- | --- |
| **Render PostgreSQL** | 1 GB, **expires 30 days**, no backups | No | Yes via **direct** URL (avoid pooled `:6432`) | same-vendor, same-region; Basic-256mb **$6/mo** |
| Neon | 0.25 CU, scale-to-zero, 0.5 GB | Yes (limited) | Yes on the **direct** host; **no** on the `-pooler` (transaction mode) | free is usable but scale-to-zero adds cold-start; Launch **~$19/mo** |
| Supabase | 500 MB, pauses after ~1 week idle | Yes (limited) | Yes on direct `:5432` or **session** pooler `:5432`; **no** on `:6543` | Pro **$25/mo**; free pauses |
| Railway PostgreSQL | metered | Trial only | Yes on direct | a few $/mo |

**Recommendation:** **Render PostgreSQL (Basic-256mb, ~$6/mo)** when Render is the
host — one vendor, same region, direct connection, no scale-to-zero. If you want
a free start, **Neon** (direct host, not `-pooler`) works; accept scale-to-zero
and treat it as non-production until upgraded.

**Connection-pooling rule (applies to every provider):** use a **direct** or
**session-mode** connection. A **transaction-mode** pooler remaps the backend
connection between transactions and breaks the session-level advisory lock used
during migration. See `ARCHITECTURE.md` §3.

## 3. NEAR archival RPC

- Free: `archival-rpc.mainnet.near.org` — permanent free, but **deprecated and
  hard rate-limited**. Acceptable only at very low historical-lookup volume.
- Paid: a NEAR archive plan from QuickNode/Chainstack (~**$49/mo**) or metered
  dRPC/GetBlock (a few dollars at low volume). See `NEAR_ARCHIVAL_RPC.md`.

## 4. Monitoring

- Platform-native metrics/logs: **$0**.
- An external uptime check on `/api/health`: free tiers exist (**$0**).
- A managed observability vendor is optional; budget **$0–25/mo**.

## 5. Estimated monthly operating cost

| Line | Free-tier path | Recommended paid path |
| --- | --- | --- |
| App host | $0 (but sleeps — not production) | Render Web Starter **$7** |
| PostgreSQL | $0 (Neon free, scale-to-zero) | Render PG Basic-256mb **$6** |
| Audit volume (~1 GB) | $0 | Render disk **~$0.25** |
| NEAR archive RPC | $0 (deprecated free) | $0 free, or **~$49** paid |
| Monitoring | $0 | **$0** |
| **Total** | **$0** (with caveats) | **~$13/mo** free-archive, **~$62/mo** paid-archive |

**Bottom line:** the honest production floor is about **$13/month** (Render web +
Render Postgres + a small audit disk) using the deprecated free NEAR archive; add
**~$49/month** for a reliable paid NEAR archive. The `$0` path is not production:
the app host sleeps and the free databases expire or pause.

## 6. Not done here

No account created, no plan purchased, no payment details entered, no resource
provisioned. These are post-authorization steps.
