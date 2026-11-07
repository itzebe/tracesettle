# Mission 25 — baseline verification

Recorded 2026-11-06 before any Mission 25 change. Every value was read from the
live repository or the live provider, not from memory.

## Repository state

| Item | Value | How verified |
| --- | --- | --- |
| Repository | `https://github.com/itzebe/tracesettle` | `git remote -v` |
| Default branch | `master` | GitHub API `repos/itzebe/tracesettle` |
| `origin/master` SHA at start | `67036c2c1ee5464e447cd7e52128a0137099c087` | `git rev-parse origin/master` |
| Matches the reported baseline | **yes** | compared to the mission brief |
| Clone depth | full history (`is-shallow-repository` → `false`) | `git rev-parse --is-shallow-repository` |
| Mission branch | `feat/mission25-live-tee-execution` | `git branch --show-current` |

## Commits after Mission 24

None. `67036c2` *is* the Mission 24 closure commit
(`docs(agents): record Mission 24 release closure`), and it is the tip of
`origin/master`.

```
67036c2 (origin/master, master) docs(agents): record Mission 24 release closure
3c9cf0e feat(near): TEE signing boundary via OutLayer Signing Keys (#24)
a802129 feat(near): enforce the provider policy on the main execution boundary (#23)
85eb261 feat(near): verify recovered transactions from durable signed bytes (#22)
804e9a6 docs(agents): record provider-policy gate release verification (#21)
```

## PR #24

| Item | Value |
| --- | --- |
| State | `closed`, `merged: true` |
| Merged at | `2026-11-07T20:24:46Z` |
| Merge commit | `3c9cf0eb1037d592f59310241873b135742ff3ef` |
| Base / head | `master` ← `feat/mission24-tee-signing-boundary` |
| Open PRs at start | none |

## CI status

All four workflow jobs **success** on `67036c2`:

- `Tests and static analysis` — success
- `PostgreSQL shared-state integration` — success
- `Docker build and runtime` — success
- `Vercel container image` — success

## Production deployment

| Item | Value |
| --- | --- |
| URL | `https://tracesettle-navy.vercel.app` |
| Deployed commit | `67036c2c1ee5` (deployment `tracesettle-ac1g0ag7i`) |
| State | `READY` |
| `/api/health` | `{"status": "ok", "tool": "TRACESETTLE", "version": "0.2.0", "read_only": true}` |

## Existing TEE signing implementation (Mission 24, already merged)

`tracesettle/near/tee_signing/` — 1463 lines including the guest module source:

| File | Lines | Role |
| --- | --- | --- |
| `__init__.py` | 75 | public surface |
| `request.py` | 190 | canonical signing request (structured, never raw bytes) |
| `provider.py` | 343 | OutLayer `/call` transport + deterministic stand-in |
| `attestation.py` | 194 | quote/measurement/build/commitment checks |
| `boundary.py` | 410 | fail-closed gate, evidence ladder, pipeline adapter |
| `guest_reference.py` | 104 | the guest's digest rule mirrored in Python |
| `guest/signing-module/src/lib.rs` | 147 | WASI P2 guest that composes and signs the NEAR digest |
| `guest/signing-module/{Cargo.toml,manifest.json}` | — | build config + manifest |

Related, already merged and reused by this mission:

- `tracesettle/near/pipeline.py` — durable submission ledger, finality polling,
  `TeeSigningTransactionSigner`.
- `tracesettle/near/ledger.py` — `SubmissionLedger`, `SubmissionState`.
- `tracesettle/near/verify.py` — independent on-chain verification.
- `tracesettle/near/tdx.py`, `collateral.py`, `attestation.py` — genuine Intel
  TDX quote verification with PCS collateral.
- `tracesettle/near/enclave.py` — the earlier (also access-blocked) enclave
  signing boundary.

## Existing research and free-access documentation

- `evidence/mission24/provider_research.md` — the three OutLayer surfaces are
  not interchangeable; only Signing Keys signs a caller-computed digest.
- `evidence/mission24/free_access_and_credentials.md` — the exact owner actions.
- `docs/TEE_RESEARCH.md`, `docs/NEAR_INTEGRATION.md` §10.

**Baseline conclusion:** the reported baseline is accurate. The TEE signing
boundary is implemented, tested and merged; it is **access-blocked**, not
unfinished. Mission 25's job is to find a genuinely free route to a real
signing operation, or to establish definitively that none exists and finish
everything else.
