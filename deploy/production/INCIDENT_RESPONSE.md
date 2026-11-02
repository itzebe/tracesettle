# TRACESETTLE — incident response and recovery runbook

Each scenario states: how to detect it, the expected (already-implemented)
behaviour, how to recover, and how to confirm state is consistent. Nothing here
requires changing code; these are operational procedures.

---

## A. PostgreSQL outage

**Detect.** Guard endpoints returning `HOLD` (no authorization); the process exits
at start-up with `refusing to start: cannot connect to the PostgreSQL state
database` (exit `2`). Note `/api/health` is **liveness only** — it does not probe
the database — so it may stay `200` while the store is down; the authoritative
signals are guard `HOLD` responses and the provider's database connection alarm.
Metrics stop advancing.

**Expected behaviour.** The store **fails closed**: a broken/unreachable store
yields no authorization and never falls back to process memory. A *dropped*
connection (a blip) is not a broken store — the next call reconnects, so a
transient interruption does not take the instance out of service. On start-up an
unreachable database refuses to start.

**Recover.**
1. Confirm the outage from the provider status page.
2. Do not "work around" it by switching to SQLite/in-memory — that silently drops
   shared replay protection. Fix the database instead.
3. When the database returns, confirm the app reconnects (a running instance
   reconnects on the next call; a failed-start instance must be restarted).

**Confirm consistency.** After recovery, run the cross-instance checks:
- a previously spent nonce is still refused (`REPLAYED`);
- a revocation issued before the outage is still enforced;
- the spending window total is unchanged (no double-spend from the gap);
- `GET /api/guard/metrics` reports `state.backend: "postgresql"`, `state.durable: true`.

**Resume.** Traffic resumes automatically once the store answers; no manual
state repair is needed, because every decision is atomic and fail-closed.

---

## B. Migration lock timeout

**Detect.** Start-up logs a fail-closed message about the PostgreSQL store not
opening; the first-deploy migration did not complete within its bounded wait.

**Expected behaviour.** Schema migration takes a session-scoped advisory lock
across the whole inspect-and-migrate sequence, with a **bounded** wait, then
fails closed. This prevents the first-deploy race where several instances migrate
concurrently and collide.

**Identify the cause.**
1. Is another instance mid-migration? Query the database:
   `SELECT pid, query, state FROM pg_stat_activity WHERE query ILIKE '%TRACESTM%' OR query ILIKE '%advisory%';`
   and `SELECT * FROM pg_locks WHERE locktype = 'advisory';`.
2. Is the DSN pointing at a **transaction-mode pooler**? That is the most common
   cause: a session lock cannot be held across transactions through such a pooler.
   Fix by using a direct/session connection (see `ARCHITECTURE.md` §3).
3. Is a previous instance still holding the lock after a crash? Session locks
   release when the backend ends, so terminate the stale backend if it is wedged:
   `SELECT pg_terminate_backend(<pid>);`.

**Recover without corrupting schema.** Do **not** hand-edit the schema-version
row. Let one instance complete the migration alone (scale to one instance), then
scale back up. Re-run start-up; the migration is idempotent and preserves data
(tested).

---

## C. Application restart

**Detect.** A platform restart or redeploy.

**Expected behaviour.** With a stable `TRACESETTLE_GUARD_AUTH_KEY` and PostgreSQL,
all security state survives: consumed nonces, revocations, idempotency keys, and
spending counters.

**Verify.**
1. **Signing key stability:** `GET /api/guard/metrics` shows `authorization.key_id`
   with a stable `k-<hash>` value (not `ephemeral-…`). An `ephemeral` key means
   `TRACESETTLE_GUARD_AUTH_KEY` is unset — fix it before serving.
2. **Revocation and idempotency survive:** re-issue a revocation for a test id,
   restart, and confirm it is still enforced; confirm a repeated idempotency key
   does not yield a second authorization.
3. **No replay vulnerability introduced:** sign once with a token, restart, and
   confirm the same token is refused as `REPLAYED`.

**Failure signature.** If a restart *re-enables* a spent nonce or a revoked
authorization, the deployment is not using durable shared state — check
`state.backend`/`state.durable` in metrics and the DSN.

---

## D. NEAR archival RPC outage

**Detect.** Historical investigations report the settlement stage as
`UNAVAILABLE`; archive endpoint returns HTTP 429 or times out.

**Expected behaviour.** A provider problem is `UNAVAILABLE`, **not** proof the
transaction is absent, and **not** a failed settlement. A miss on every endpoint
is `NOT_FOUND`. The rest of the investigation proceeds.

**Recover.**
1. Retry after the rate-limit window (`Retry-After` can be hundreds of seconds on
   the deprecated free archive).
2. Under the zero-budget constraint there is no alternative free archive: the
   only free archive is the deprecated, rate-limited
   `archival-rpc.mainnet.near.org` (see `NEAR_ARCHIVAL_RPC.md`). Retry after the
   rate-limit window. A reliable archive node is a **paid** option and is out of
   scope.

**Avoid false confirmations.** Never reclassify `UNAVAILABLE` as failed, and never
confirm a stage from a non-decisive event. Reconciliation is deterministic and
only a decisive on-chain event confirms a stage.

---

## E. Audit-chain divergence

**Detect.** The external monitor (see `AUDIT_ANCHORING.md` §5) finds that a new
anchor does not extend the previously verified chain, or `AuditLog.verify()`
reports a break.

**Expected behaviour.** In-place modification, reorder, or deletion is detectable
by recomputation. Divergence means the local history changed.

**Respond.**
1. **Preserve evidence first.** Copy the audit log file and the external proofs
   before doing anything else. Do not rewrite or prune the log.
2. Compare the local chain against the external checkpoint: recompute the digest
   for the anchored sequence and compare to the anchored value.
3. Investigate without rewriting: determine whether the cause is tampering, a
   restore-from-backup, or a bug (these are the three usual causes).
4. If tampering is plausible, treat the host as compromised: rotate credentials
   (see F), preserve the evidence, and follow your security process.

**Note.** Because anchoring is not yet automated, today this check is manual:
preserve the head digest out of band and compare it after each restart/deploy.

---

## F. Credential compromise

**Detect.** A secret is suspected leaked: `TRACESETTLE_API_KEY`,
`TRACESETTLE_GUARD_AUTH_KEY`, the PostgreSQL DSN, or service credentials.

**Respond.**
1. **API key:** rotate `TRACESETTLE_API_KEY` in the secret manager and redeploy.
   Verify the old key no longer works:
   `curl -s -o /dev/null -w '%{http_code}\n' -H "X-API-Key: <old>" https://<host>/api/guard/metrics`
   must return `401`.
2. **Guard signing key:** rotating `TRACESETTLE_GUARD_AUTH_KEY` **invalidates all
   outstanding authorization tokens** (they were signed with the old key). This
   is the safe direction but is disruptive; do it deliberately. Verify the new
   `key_id` in metrics differs and that previously issued tokens are refused.
3. **DSN:** rotate the database password, update the secret, redeploy, and
   confirm the app reconnects. Review database access logs for unexpected clients.
4. **Service credentials:** revoke the affected service identity in the
   credential registry and confirm it is refused.

**Preserve audit evidence.** The audit log records issuance, signing attempts,
and refusals. Do not delete it. Export the relevant window before any rotation
that changes the log's head.

**Verify old credentials no longer work** before closing the incident, and record
the rotation time.

---

## G. Previously exposed GitHub credential (open incident)

A GitHub credential was exposed in an earlier session; its revocation is
**unverified**. This is an owner-side action.

**Do (owner):**
1. Revoke/rotate the token at GitHub → Settings → Developer settings → Personal
   access tokens (or the App installation).
2. Confirm the old token is rejected (a call with it returns `401`).
3. Audit recent access for that credential.

**Do not (agent):** retrieve, print, use, or revoke the credential. Do not claim
the incident is resolved without evidence of revocation.
