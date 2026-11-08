# Mission 26 — verified baseline

Recorded 2026-11-08 before any change on this branch.

## Repository

| Field | Value |
| --- | --- |
| Repository | https://github.com/itzebe/tracesettle |
| Default branch | `master` |
| Verified `origin/master` SHA | `537a5a398b6775fa53fc3f76d309c22888195163` |
| Reported baseline SHA (mission brief) | `537a5a398b6775fa53fc3f76d309c22888195163` — **matches** |
| Mission branch | `feat/mission26-independent-tee-trust` (created from `master`) |
| Working tree at baseline | clean |

The repository had **not** advanced beyond the reported SHA. No reset, revert or
overwrite was performed.

## Pull requests

| PR | State | Merge commit |
| --- | --- | --- |
| #25 `feat(near): free on-chain TEE signing` | MERGED 2026-11-07T23:41:34Z | `537a5a398b6775fa53fc3f76d309c22888195163` |

No open PRs. `gh pr list --state open` returned `[]`.

## Production

| Field | Value |
| --- | --- |
| URL | https://tracesettle-navy.vercel.app |
| `/api/health` | `{"status":"ok","tool":"TRACESETTLE","version":"0.2.0","read_only":true}` |
| Deployment state | READY |
| Deployed commit | `537a5a398b6775fa53fc3f76d309c22888195163` |

## CI

Latest `master` run `42426395523` on `537a5a39`: **success**.

## TEE signing implementation at baseline

| Path | Role |
| --- | --- |
| `tracesettle/near/tee_signing/onchain.py` | Free on-chain route (`outlayer.<net>.request_execution`) |
| `tracesettle/near/tee_signing/request.py` | Canonical signing request + digest |
| `tracesettle/near/tee_signing/attestation.py` | Claim-by-claim attestation verdict |
| `tracesettle/near/tee_signing/boundary.py` | Signing boundary + authorization binding |
| `tracesettle/near/tee_signing/guest/` | Rust WASI-P2 guest crate + pinned WASM |
| `tracesettle/near/tdx.py` | Intel TDX quote verifier (re-used, not re-implemented) |
| `tracesettle/near/collateral.py` | Intel PCS collateral validation |

Guest artifact at baseline: `dist/tracesettle-signing-module-wasm.wasm`,
sha256 `eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0`.

## Test counts at baseline

`python3 -m pytest tests/ -q` → recorded at the end of Mission 25 as
`1821 passed, 34 skipped`. Re-measured on this branch before changes (see
`evidence/mission26/final_report.md`).

## What Mission 25 did *not* establish (the gaps this mission closes)

1. **No reproducible build.** The WASM was identified by a pinned sha256 only; no
   clean rebuild, no toolchain pin, no byte-for-byte comparison.
2. **No attestation retrieval.** The on-chain `execution_completed` event carries
   no quote; Mission 25 recorded `attestation_url: ""` and treated the run as
   provider-trusted.
3. **No evidence chain.** Authorization → digest → signature → broadcast →
   finality → settlement were checked in separate places, not as one record.
4. **No reviewer commands.** Nothing let an independent party reproduce the
   digest, verify the signature, or verify the attestation.
