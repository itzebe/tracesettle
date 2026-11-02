# Durable authorization state

Phase 1 inspection of TRACESETTLE's transaction guard, and the design of the
durable state layer that removes security-critical dependence on process-local
memory.

## 1. The state lifecycle

```
request ──► evaluate (controls) ──► decision ──► [ALLOW] issue authorization
                 │                                     │
                 │  reads velocity / volume / reject    │  records decision,
                 │  counters (process-local)            │  volume, incident
                 ▼                                     ▼
            GuardService._volume, monitor._events    authority.issue()
                 │                                     │
                 └──────────── audit log (hash chain) ─┘
                                                       │
signer.sign(token) ──► authority.validate(consume=True) ──► replay store
```

Two things in that picture decide whether a transaction may proceed:

1. **The replay store** decides whether an authorization nonce has been spent.
2. **The velocity / volume / rejection counters** decide whether a service is
   still inside its policy limits.

## 2. Security decisions that depend on process-local memory (before this work)

| Decision | Where | Storage before | Consequence of a restart |
| --- | --- | --- | --- |
| Single-use nonce | `InMemoryReplayStore` | in-memory `dict` | a spent nonce becomes valid again |
| Authorization revocation | `RevocationStore` | in-memory `dict` | a revoked authorization is accepted |
| Request velocity | `SecurityMonitor._events` | in-memory `deque(maxlen=500)` | counters reset to zero |
| Blocked-request rate | `SecurityMonitor._block_times` | in-memory `deque` | burst detection resets |
| Rejected authorizations | `SecurityMonitor._events` | in-memory `deque` | the "under attack" control resets |
| Window volume | `_WindowVolume._entries` | in-memory `deque(maxlen=4096)` | spending counters reset to zero |
| Idempotency | not implemented | — | no duplicate-accounting control existed |

Every one of these is a fail-open on restart: a process bounce silently restores
a spent nonce, clears a spending window, and forgets a burst of refusals. The
audit log is the only durable record, and it is a *record*, not a control.

## 3. What is already durable

* **Audit log** (`guard/audit.py`): when `TRACESETTLE_GUARD_AUDIT_LOG` is set,
  each record is appended as one JSON line and the chain resumes from the file on
  restart, so audit continuity already survives a restart.
* **Service credentials** (`serviceauth.py`): a JSON store on disk, hashed.
* **Policy** (`policy.py`): a JSON file.

## 4. Backend choice

**SQLite** (Python standard library `sqlite3`), because:

* it is available everywhere with no infrastructure and no new runtime
  dependency (the project is standard-library only);
* it gives real ACID transactions and a UNIQUE constraint, which is exactly the
  primitive an atomic nonce consumption needs;
* it survives a process restart from a file on a persistent volume.

**Honest limitation — this is not distributed state.** A SQLite database on a
local volume gives durable state for **one** application instance. It must not be
advertised as multi-instance shared state. Two processes sharing one database
file on a single host are safe (SQLite's file locking serialises writers); two
hosts cannot share it, and network filesystems are not supported by SQLite.

The interface (`GuardStateStore`) is deliberately narrow — atomic consume,
counter reads, event append — so a shared backend can implement the same methods.
**PostgreSQL is now that backend** (section 10), selected with
`TRACESETTLE_GUARD_STATE_BACKEND=postgresql`. It is an opt-in extra: the driver is
imported lazily, so the default install and the default image stay
standard-library only and need no database.

## 5. Schema (version 2)

```
schema_version(version INTEGER NOT NULL)             -- one row

consumed_nonces(
    nonce       TEXT PRIMARY KEY,                     -- UNIQUE = the atomicity
    expires_at  REAL NOT NULL,
    consumed_at REAL NOT NULL)
index consumed_nonces_expires_at(expires_at)

revoked_authorizations(
    authorization_id TEXT PRIMARY KEY,
    until            REAL NOT NULL)
index revoked_authorizations_until(until)

counter_events(
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    at         REAL NOT NULL,
    kind       TEXT NOT NULL,      -- DECISION | AUTHORIZATION_ISSUED | SIGNER
    service_id TEXT NOT NULL,
    outcome    TEXT,               -- decision value, or sign outcome
    asset      TEXT,
    amount     TEXT)               -- exact decimal, as a string
index counter_events_at(at)                       -- v2: serves the window read
index counter_events_service_at(service_id, at)
index counter_events_kind_at(kind, at)

idempotency(
    request_key TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    at          REAL NOT NULL)
index idempotency_at(at)                          -- v2: serves retention pruning
```

Money is stored as an exact decimal **string** (`Decimal` on read), never a
binary float, matching the rest of the project.

**Version 2 (retention).** The window read is `WHERE at >= ?`, which needs an
index whose *leading* column is `at`; the v1 composite indexes lead with
`service_id`/`kind` and so could not serve it. Without `counter_events_at` that
read is a full scan of a table that grows with every decision, so evaluation
cost grew without bound (measured ~1.6 ms/read at 50k rows and rising, versus
~0.03 ms once the index exists). `idempotency_at` serves the same role for the
idempotency table. A v1 database is upgraded in place on the next open, keeping
its data.

`counter_events` and `idempotency` are **bounded by retention**, not left to grow
forever. Events older than `TRACESETTLE_GUARD_STATE_RETENTION_SECONDS` (default
24h) cannot affect any velocity/volume window and are pruned; idempotency keys
older than the same horizon are pruned. The prune is driven from
`DurableReplayStore.consume` — the one call made on every signing attempt — so it
runs on the enforcement path and cannot be forgotten by a caller. This mirrors the
in-memory guard, which already bounds its equivalents (`deque(maxlen=...)`).


## 6. Pragmas and durability

* `journal_mode = WAL` — readers never block the writer and a crash recovers
  cleanly from the write-ahead log.
* `synchronous = FULL` — a commit is fsynced before it returns. This is a
  security boundary, so durability across power loss is worth the cost; the
  write rate is a handful per authorization.
* `busy_timeout` (default 5000 ms) — a second process waits for the write lock
  instead of failing immediately.
* `foreign_keys = ON`.

## 7. Atomicity and fail-closed guarantees

* **Nonce consumption** is a single `INSERT` against a `PRIMARY KEY`. Exactly one
  of any number of concurrent attempts (threads *or* processes) can succeed; the
  rest get an `IntegrityError` and are reported as `REPLAYED`.
* **The whole decision is one transaction.** `GuardService.evaluate` runs the
  read of the counters, the control evaluation, the idempotency claim, and the
  counter append inside one `decision_cycle` (`BEGIN IMMEDIATE`). Without this,
  two concurrent evaluations could both read an empty window and both authorize
  past the limit — a real breach the test suite reproduces by neutralising the
  cycle. The write lock is taken up front, so a second decision waits and then
  sees the first decision's events. A failure anywhere rolls the whole decision
  back; the process-local monitor and audit log are written only after the
  transaction commits, so a rolled-back decision is never recorded as if it had
  happened.
* **A store error fails closed.** `GuardService` catches a state-store error and
  turns the request into `HOLD` (never `ALLOW`) with a `STATE_STORE_UNAVAILABLE`
  finding; `AuthorizationAuthority.validate` catches a consume error and refuses
  the authorization. There is **no** fallback to in-memory state in production.
* **A failed write latches the store degraded.** If any durable write fails, the
  store sets a `degraded` flag and every later read and write raises. A counter
  write that failed cannot leave a limit silently unenforced for the rest of the
  process lifetime: the next evaluation fails closed instead.
* **Migrations** are numbered and applied in a transaction; a migration that
  raises leaves the database at its previous version rather than half-migrated,
  and a database written by a newer build is refused rather than misread.

## 8. Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRACESETTLE_GUARD_STATE_DB` | unset | path to the SQLite state database |
| `TRACESETTLE_GUARD_STATE_BACKEND` | `auto` | `auto` \| `sqlite` \| `postgresql` \| `memory` |
| `TRACESETTLE_GUARD_STATE_PG_DSN` | unset | PostgreSQL connection string (libpq form or URL) |
| `TRACESETTLE_GUARD_STATE_BUSY_TIMEOUT_MS` | `5000` | writer lock wait (SQLite) / decision lock wait (PostgreSQL) |
| `TRACESETTLE_GUARD_STATE_RETENTION_SECONDS` | `86400` | counter-event / idempotency retention |
| `TRACESETTLE_GUARD_REQUIRE_POSTGRES` | unset | if set, refuse to start unless the PostgreSQL backend is active |

`auto` (the default) keeps the historical behaviour: a configured
`TRACESETTLE_GUARD_STATE_DB` means SQLite, otherwise in-memory. `postgresql`
requires `TRACESETTLE_GUARD_STATE_PG_DSN` and the optional driver, and stops
start-up if either is missing rather than silently falling back. When unset, the
guard keeps its in-memory stores: the loopback development workflow is unchanged,
and the console reports the state backend honestly so an operator can see whether
the run is durable. A configured database that cannot be opened or fails its
integrity check stops the process at start-up rather than running with a silently
degraded control.

## 9. Deployment

The container runs as a non-root user and, with durable state unset, still writes
nothing to the filesystem. To enable durable state in a container, point
`TRACESETTLE_GUARD_STATE_DB` at a path on a **writable, persistent volume** that
the container user (uid 10001) can write, for example a mounted data directory.
An ephemeral container filesystem defeats the purpose: the database would be lost
on the next container replacement, exactly the restart the state exists to
survive.

Durable state here is **single-instance**. Do not run two replicas against the
same SQLite file on different hosts, and do not place the file on a network
filesystem. For a multi-replica deployment, use the PostgreSQL backend below; the
default single-instance SQLite store is correct for one instance and is honest
about it.

## 10. PostgreSQL backend (multi-instance)

`PostgresGuardStateStore` (`tracesettle/guard/state_pg.py`) implements the same
`GuardStateStore` contract against a shared PostgreSQL database, so several
TRACESETTLE instances enforce one set of nonces, revocations, counters, and
idempotency records. Enabling it:

```sh
# Optional dependency, only needed for this backend.
pip install "psycopg[binary]==3.3.6"

export TRACESETTLE_GUARD_STATE_BACKEND=postgresql
export TRACESETTLE_GUARD_STATE_PG_DSN="postgresql://user:pass@db-host:5432/tracesettle"
export TRACESETTLE_GUARD_REQUIRE_POSTGRES=1        # fail start-up if PG is not active
python3 -m tracesettle serve --host 0.0.0.0 --port 8000
```

The schema is created on first use (schema version 2, identical table and index
shape to the SQLite store, using `BIGINT GENERATED ALWAYS AS IDENTITY` for the
event sequence and `DOUBLE PRECISION` for the time columns). It is idempotent and
reopening an initialised database neither loses rows nor re-runs migrations.

**Atomicity without a retry loop.** SQLite takes a whole-database write lock with
`BEGIN IMMEDIATE`. PostgreSQL has no equivalent, so the store takes a
transaction-scoped advisory lock (`pg_advisory_xact_lock`) around each decision
transaction, with a bounded `lock_timeout`. This serialises the read-decide-write
critical section across *all* instances, so two concurrent requests on two hosts
cannot both pass a limit or both spend a nonce. The nonce primary key remains the
final backstop. A serialization or deadlock failure (SQLSTATE `40001`, `40P01`,
`55P03`) surfaces as a retryable conflict rather than an error.

**Fail-closed, and honest about failure.** The driver is imported lazily, so the
default build never needs it. A store that cannot be reached, a failed write, or
a schema mismatch raises `StateStoreError`, which the guard turns into `HOLD` with
no authorization — never `ALLOW`. The guard never falls back to in-memory state
when the shared database is unavailable: a broken shared store is not silently
downgraded to process memory, because that would reintroduce exactly the replay
the shared store exists to prevent. A *dropped connection* is different from a
broken store: the next call reconnects, so a transient network blip does not take
an instance out of service. A non-connection write failure still latches the
store degraded until the process is restarted.

**A connection lost mid-decision fails closed.** The one place a reconnect would
be unsafe is *inside* a decision transaction: reconnecting would run the rest of
the decision on a new transaction — and without the advisory lock — splitting one
atomic decision across two transactions and committing a partial result (for
example, losing the idempotency claim while the caller still sees `ALLOW`, so the
same key could be authorized again). So a connection that drops after the
decision has begun is not reconnected: the decision is abandoned and reported as a
state-store failure (`HOLD`), and an ordinary later call still reconnects. This is
covered by `test_connection_drop_mid_decision_fails_closed_without_partial_state`.

**Concurrency is the point.** The distributed guarantees are proven against a real
server in `tests/test_guard_postgres.py` (cross-instance replay refusal, a shared
spend window across two store instances, revocation visible across instances, and
fail-closed behaviour when the database goes away). CI runs them in a dedicated
job with a `postgres:16` service. The security invariants gain one entry,
`postgres_shared_state_refuses_cross_instance_replay`, which is exercised for real
when a DSN is configured and reports honestly that it was not exercised
otherwise.

## 11. Independent adversarial security review (pre-merge)

PR #6 was reviewed adversarially — not "the tests pass" but "find a way an
attacker or a compromised instance bypasses a control". The review attempted
nonce replay (single-instance, cross-instance, and concurrent on eight
connections), limit evasion (20-way thread race and eight separate OS processes
against one shared window), idempotency races, revocation visibility, cross-service
parameter substitution, migration races, and the behaviour of every failure path
(lock-timeout, statement-timeout, dropped connection, degraded latch, rollback).
Two real defects were found and fixed; both have mutation-checked regression tests.

1. **A connection lost mid-decision could split the decision across two
   transactions.** `_prepare` reconnected whenever the connection was closed —
   including inside a `decision_cycle`. A drop after the idempotency claim then
   re-ran the remaining writes on a new transaction *without* the advisory lock,
   and the decision still returned `ALLOW`: the claim was lost, so the same
   idempotency key was authorized a second time. Fix: a connection lost inside a
   decision is not reconnected; the decision fails closed (`HOLD`), while an
   ordinary later call still reconnects.
   Test: `test_connection_drop_mid_decision_fails_closed_without_partial_state`.

2. **A forged token could attribute its refusals to another service.** A signer
   refusal was counted against `token.service_id`, a field an attacker controls on
   a forged token. An authenticated attacker could set it to a victim service and,
   after `max_rejected_authorizations` refusals, drive the victim's own next
   transaction into `HOLD` — a cross-service denial of service. Fix: a refusal is
   attributed to the verified requester (`expected_service_id`), and the guard API
   binds `expected_service_id` to the authenticated caller rather than a body
   field. Tests: `test_refusal_is_attributed_to_the_requester_not_the_forged_token`,
   `test_a_forged_token_cannot_drive_another_service_into_a_hold`,
   `test_sign_refusal_is_attributed_to_the_authenticated_caller`.

Every other attempted bypass was refused. In particular, concurrent signing of one
token on eight separate connections executed exactly once; a 20-way and an
eight-process race against a shared spend window admitted no more than the window
allowed; a replayed nonce, a replayed token, a substituted parameter, a token for
another service, and an expired token were all refused; and a lock-timeout or a
statement-timeout failed closed without latching the store degraded. The 16
structural invariants all hold, and the offline demo is byte-identical across runs.
