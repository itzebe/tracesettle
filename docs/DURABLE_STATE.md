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
counter reads, event append — so a future shared backend (PostgreSQL) can
implement the same methods. The repository contains **no** PostgreSQL dependency
and no existing abstraction, so introducing one now would be unnecessary
infrastructure; the narrow interface is the correct preparation.

## 5. Schema (version 1)

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
index counter_events_service_at(service_id, at)
index counter_events_kind_at(kind, at)

idempotency(
    request_key TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    at          REAL NOT NULL)
```

Money is stored as an exact decimal **string** (`Decimal` on read), never a
binary float, matching the rest of the project.

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
| `TRACESETTLE_GUARD_STATE_BUSY_TIMEOUT_MS` | `5000` | writer lock wait |

When unset, the guard keeps its in-memory stores: the loopback development
workflow is unchanged, and the console reports the state backend honestly so an
operator can see whether the run is durable. A configured database that cannot be
opened or fails its integrity check stops the process at start-up rather than
running with a silently degraded control.

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
filesystem. For a multi-replica deployment, implement the narrow `GuardStateStore`
interface against a shared database (the interface exists for that reason); the
default single-instance SQLite store is correct for one instance and is honest
about it.
