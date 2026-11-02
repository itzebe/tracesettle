# TRACESETTLE — release status and verification record

This is a point-in-time record of the release-verification mission run on
**2026-11-02**. It states what was actually executed, what the observed results
were, and what remains outstanding. It does not replace the design documents; it
records the release state they describe.

**Verdict: RELEASE READY — NOT DEPLOYED.** The code, tests, container images and
configuration pass verification and PR #8 is merged to `master`. A Vercel
deployment is **not** performed, because a required component (a shared
PostgreSQL for durable guard state) cannot be provisioned under the owner's
**$0, no-credit-card** constraint without an owner-side account action. The
non-billable work is complete.

## 1. Repository state

| Item | Value |
| --- | --- |
| Repository | `https://github.com/itzebe/tracesettle` (private) |
| Default branch | `master` |
| Master before this mission | `7eea109fdf67de1f77c731fb9cb6493afe084bb1` |
| **Master after merge** | **`5c6f66df7e1bade23b07e4f4adc5e662f76fa77e`** |
| PR merged | **#8** `feat: Vercel Hobby deployment via the Container Runtime` |
| PR #8 head | `43b2375c43244bc2473870e7402ee51837a4e06d` |
| Merge method | normal merge commit (no squash, no rebase) |
| Merge tree | identical to the PR head tree (verified) |
| Working tree | clean |

`PR #8` was opened as a draft, verified, marked ready for review, and merged with
a merge commit. All of PRs #1–#8 are now merged.

## 2. What PR #8 added

| File | Role |
| --- | --- |
| `Dockerfile.vercel` | Vercel Container Runtime image (non-root uid 10001, port 80 default, `psycopg` baked in). |
| `vercel.json` | Pins the container to `Dockerfile.vercel` and routes all traffic to it. |
| `deploy/production/VERCEL_DEPLOYMENT.md` | Host guide for the Vercel deployment. |
| `.github/workflows/ci.yml` | New `vercel-container` CI job (builds and smoke-tests the Vercel image). |
| `.gitignore`, `.dockerignore` | Ignore `.vercel` local CLI state. |
| `README.md`, `deploy/production/README.md` | Documentation updates. |
| `tests/test_ui.py` | De-flake of a semaphore-release timing race (see §5). |

The production `Dockerfile` is unchanged.

## 3. Independent review findings

The complete PR #8 diff and the security-critical application paths were
reviewed. **No critical or high-severity findings.** The controls below were
confirmed intact:

- **Fail-closed startup** (`tracesettle/securityconfig.py`): a non-loopback bind
  refuses to start unless `TRACESETTLE_API_KEY` and `TRACESETTLE_GUARD_AUTH_KEY`
  are present. There is no override.
- **Authentication**: every guard route is gated by the API key; the guard's
  per-service identity plane is separate from the admin plane.
- **Transaction Guard**: `ALLOW`, `BLOCK` and `REQUIRE_APPROVAL` all preserve
  their behaviour (verified live, §4).
- **Signing**: `ReferenceSigner.sign` refuses before the executor is consulted
  when the authorization is not exactly `VALID`; the only executor is
  `SimulatedExecutor` (no keys, no broadcast).
- **PostgreSQL**: session-scoped advisory locks for migrations and
  transaction-scoped advisory locks for decisions; a missing or unreachable
  database **refuses to start** — there is no silent fallback to SQLite or
  memory.
- **Audit trail**: hash-chained and documented as **tamper-evident, not
  tamper-proof**; no external anchoring is claimed.

## 4. Verification executed (2026-11-02)

All commands were run in this environment. Nothing below is asserted without a
matching observation.

| Check | Result |
| --- | --- |
| Full test suite (no DSN) | **717 passed, 24 skipped** (the 24 skips are the PostgreSQL integration tests, which need a live server) |
| Full test suite (with `TRACESETTLE_TEST_PG_DSN`) | **741 passed** |
| PostgreSQL integration against a real server | **24 passed** |
| Safety/guard invariant tests | **74 passed** |
| `pyflakes tracesettle/ tests/ demo/` | clean |
| `compileall` | OK |
| Config validation (`deploy/production/validate_config.py`) | OK |
| Production `Dockerfile` build | OK (181 MB) |
| Production build with `--build-arg TRACESETTLE_WITH_POSTGRES=1` | OK (209 MB) |
| `Dockerfile.vercel` build | OK (209 MB, non-root uid 10001) |
| `vercel dev --local` (official container orchestration, real Docker) | builds and runs `Dockerfile.vercel`; `/` `200`, `/api/health` `200`, `/console` `200`, unauth guard `401`, auth guard `200` |
| Offline demo reproducibility | byte-identical across two runs (md5 `4864f13c…`) |
| Post-merge CI (`master` = `5c6f66d`) | **success**, all 4 jobs (Tests/static, PostgreSQL, Docker, Vercel container image) |

### Live behaviour observed through the Vercel container

| Request | Observed |
| --- | --- |
| `POST /api/guard/evaluate` denylisted destination | `decision=BLOCK`, `risk=CRITICAL`, `authorizes_signing=false` |
| `POST /api/guard/evaluate` approved destination, amount 10 | `decision=ALLOW`, `authorizes_signing=true` |
| `POST /api/guard/evaluate` approved destination, amount 6000 | `decision=REQUIRE_APPROVAL`, `risk=MEDIUM` |
| `POST /api/guard/sign` with no authorization | `outcome=REFUSED`, `state=MISSING` |
| `POST /api/guard/sign` with a valid authorization | `outcome=EXECUTED`, `simulated=true` |
| Repeat of the same authorization (nonce replay) | `outcome=REFUSED`, `state=REPLAYED` |
| `GET /api/guard/metrics` | `state.backend=postgresql`, `state.durable=true` |
| Server log after all requests | no API key, guard key or DSN present |

## 5. Defect fixed in this mission

`tests/test_ui.py::test_semaphore_slot_is_released_after_success_and_error` was
intermittently failing. Root cause: the concurrency slot is released in
`process_request_thread`'s `finally` **after** the response is written, so a
request issued immediately after a prior one can transiently observe the slot as
still taken and receive `503`. It is a **release-timing race, not a leak**. The
test now retries while it sees `503` within a bounded deadline; a separate
mutation check (suppressing the release) confirms a genuine leak is still caught.
No production code was changed.

## 6. Zero-cost infrastructure assessment

| Need | Finding |
| --- | --- |
| Vercel hosting | Hobby (personal, no payment method on the account). Container Runtime is available in beta on all plans. Hobby usage **pauses** at a cap and cannot auto-charge, so activating a Hobby deployment cannot create a bill. |
| Vercel Container Registry | `$0.10/GB-month`; the Hobby included-usage table lists no container-registry allowance. A ~209 MB image is cents, but it is **not a documented free allowance** and must be confirmed before reliance. |
| Shared PostgreSQL | **Not provisioned.** No free, card-free Postgres is available under the $0 constraint without an owner-side account action. |
| NEAR archival RPC | **Best-effort only.** Only the deprecated, rate-limited free archive (`archival-rpc.mainnet.near.org`) is free; it did not answer within a 20 s timeout during this mission. Every other free NEAR provider is non-archival. |

Because a required component (the shared PostgreSQL) cannot be provisioned under
the constraint, **the deployment step is not performed**. Deploying with
`TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` and no DSN would refuse to start (correct
fail-closed behaviour, but not a working deployment); deploying without the
requirement would silently fall back to per-instance memory, which the project's
invariants forbid.

## 7. Product truth

- Execution remains **simulated**. `SimulatedExecutor` holds no keys and
  broadcasts to no chain. `outcome=EXECUTED` means "the simulated executor
  recorded the transaction", and the receipt carries `simulated=true`.
- No real funds were moved, no transaction was signed, and no NEAR transaction
  was broadcast by TraceSettle at any point.
- The audit chain is tamper-evident, not tamper-proof, and is not externally
  anchored.

## 8. Outstanding owner actions

1. **Provision a free PostgreSQL** with a direct/session connection (for example
   Neon free, direct host) and set `TRACESETTLE_GUARD_STATE_PG_DSN`. Without
   this, a durable Vercel deployment cannot start.
2. **Confirm the Vercel Container Registry Hobby storage allowance** before
   relying on a Hobby deployment, or accept the cents-level usage.
3. **Revoke or rotate the previously exposed GitHub credential.** This remains an
   open, owner-side incident; see `INCIDENT_RESPONSE.md`.
4. Optionally set `TRACESETTLE_NEAR_RPC_FALLBACK_URL` to a paid archive node for
   reliable historical NEAR verification.

## 9. Recommended next action

Complete owner action 1 (a free direct-connection PostgreSQL), then deploy with
`vercel deploy --prod` using the §4 configuration in `VERCEL_DEPLOYMENT.md` and
re-run the live checks in §4 against the deployment URL. Until then the release
is **ready, verified, and not deployed**.
