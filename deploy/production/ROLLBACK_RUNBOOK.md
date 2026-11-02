# TRACESETTLE — rollback runbook

Rollback is safe because the deployment is **stateless apart from PostgreSQL and
the optional audit volume**, and the service is **read-only with no real-funds
execution**. Rolling back the application does not require undoing any on-chain
action, because none is taken.

## 1. When to roll back

- Health check failing after a deploy.
- Guard endpoints returning `500` for a configuration reason.
- A startup that now refuses (fail-closed) because a required variable changed.
- A regression in investigation output.

## 2. Roll back the application

The image is immutable and the previous digest is known, so rollback is a
re-deploy of the previous image digest:

```sh
# On the platform: set the service to the previous image digest and deploy.
# Or, with Docker directly:
docker stop tracesettle && docker rm tracesettle
docker run -d --name tracesettle <previous-image-digest> <same env as before>
```

Then verify:

```sh
curl -s https://<host>/api/health                 # expect 200
curl -s -H "X-API-Key: $TRACESETTLE_API_KEY" https://<host>/api/guard/metrics
```

## 3. Database schema compatibility

The PostgreSQL store applies **forward-only** migrations and records a schema
version. It **refuses to start** against a *newer* schema than it knows (this is
tested). Therefore:

- Rolling back to an application version **older** than the one that last
  migrated the schema may be refused. If so, either deploy a version that knows
  the current schema, or restore the database from a backup taken before the
  forward migration.
- Do **not** hand-edit the schema-version row to force a start. That can corrupt
  state.
- Migrations are additive for the current feature set; a same-series rollback
  (e.g. a bad config, not a schema change) needs no database action.

## 4. Data state after rollback

- Nonces already consumed stay consumed (correct: a nonce is single-use forever).
- Revocations and idempotency keys persist.
- Spending counters persist. This is the safe direction — rollback never *loosens*
  a guarantee.
- The audit log, if on a volume, is preserved; rollback does not touch it.

## 5. If the database is the problem

- If PostgreSQL is unreachable, the app fails closed (refuses to authorize) and
  the process exits at start-up. Roll the app back only after the database is
  healthy; otherwise the new instance will also refuse.
- Restore path: create a new database from the latest backup, point the DSN at
  it, then start. Confirm `state.backend: "postgresql"` in metrics.

## 6. Reverting a bad environment change

Most "deploy" failures are a wrong/missing environment variable, and the
fail-closed checks catch them at start-up rather than exposing the service:

- Missing credentials on a public bind → exit `2`.
- `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` with a non-PG backend → exit `2`.
- Bad DSN → exit `2`, DSN not printed.

Fix the variable in the secret manager and redeploy; no code rollback is needed.

## 7. After rollback

- Record what changed, the previous and new image digests, and the reason.
- Re-run the post-deploy verification from `DEPLOYMENT_RUNBOOK.md` §7.
- Keep the audit log; do not delete it as part of a rollback.
