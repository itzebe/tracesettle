# Mission 33 — live provider authentication and policy verification

**FINAL STATUS: `AUTHENTICATION_FAILED`**

The credential `NEAR_INTENTS_AGENT_API_KEY` is **absent from the protected
runtime**. Per the mission's own instruction (§2), live verification stops here
and this exact blocker is reported. No placeholder was used, and no unrelated
environment variables or files were searched.

This is **not** a rejected credential and **not** a provider outage: the provider
is reachable and healthy (see §2). It is a missing credential.

## 1. Starting state (verified, unchanged)

| Item | Value |
| --- | --- |
| Repository | `https://github.com/itzebe/tracesettle` |
| Branch | `feat/mission29-release-closure` |
| Local HEAD | `5962c91` |
| Remote branch head | `5962c916871792743a185da47545b7515c97471e` (matches) |
| Base `master` | `e7691d2b611b83d9c82a6b016693ba3631d05830` |
| PR #29 | open, **draft**, head `5962c91`, base `e7691d2`, `mergeable_state: clean` |
| Working tree | clean (nothing to commit) |

Mission 32 evidence (`evidence/mission32/`) and the provider commands
(`provider auth`, `provider agents`, `provider policy`) were inspected and left
untouched.

## 2. Credential delivery — the blocking fact

- `NEAR_INTENTS_AGENT_API_KEY`: **absent** (checked for presence only; the value
  was never read, printed, logged, hashed, encoded, transmitted, or committed).
- The provider is **reachable**: `GET /openapi.json` → `200`
  ("NEAR Intents Agent API" v1.0.0, 40 `/v1/…` paths); `GET /v1/network` → `200`
  (`status.overall: operational`); `GET /v1/whoami` without a key → `401`
  `invalid_api_key`.

Capture: `credential_presence.json`.

Because the provider answers and only the key is missing, the outcome is
`AUTHENTICATION_FAILED` — distinct from `PROVIDER_UNAVAILABLE` and from a
*rejected* credential (which would be a `401` on a key that was actually sent).

## 3. Live CLI outcomes (read-only; no key sent)

Run against the live base URL. All three fail closed and never print a key.
Capture: `cli_outcomes.md`.

| Command | Result | Exit |
| --- | --- | --- |
| `python3 -m tracesettle provider auth` | `authenticated: false`, `key_configured: false` | 1 |
| `python3 -m tracesettle provider agents` | `availability: UNAUTHENTICATED`, `count: 0` | 1 |
| `python3 -m tracesettle provider policy <id>` | `availability: UNAUTHENTICATED`, `policy: null` | 1 |

## 4. What could not be verified live (all blocked by the missing credential)

- Authenticated tenant identity — **not obtained**.
- Agent discovery / access scope — **not obtained**.
- Retrieved policy revision, status, synchronization, freshness — **not obtained**.
- Same-transaction policy enforcement against a **live** policy — **not run**.
- **No live authenticated policy was retrieved.** This is stated plainly and is
  not implied anywhere.

## 5. What remains verified from prior missions (unchanged by this mission)

These are code-path and offline proofs, not live-provider proofs:

- The full authenticated chain (real `HttpClient` + real `PolicyAdapter` +
  real `parse_policy` + real `ProviderPolicyGate`) over a real socket with a
  transport stub — `evidence/mission32/authenticated_chain_stub.json`.
- The retrieved policy changes the decision for the **identical** transaction
  (`tx_hash_bytes` equal): `tests/test_near_provider_policy_enforcement.py::test_the_retrieved_policy_changes_the_decision_for_the_same_transaction`.
- Fail-closed behaviour (missing/invalid credentials, missing policy, disabled
  transfer, stale/unsynced, malformed, outage) — §6 below.

## 6. Failure-mode results (offline, unchanged)

| Case | Test | Result |
| --- | --- | --- |
| Missing credential | `provider auth/agents/policy` no key | refuse, no provider call |
| Invalid credential | `authenticate_wrong_key`, `..._on_401` | refuse |
| Unauthorized agent access | agent-mismatch tests | `BLOCK` |
| Missing policy | `NOT_FOUND` tests | `HOLD` |
| Disabled transfer permission | `test_a_documented_policy_view_with_native_transfer_off_is_blocked` | `BLOCK` |
| Stale / unsynchronized | `test_adapter_refuses_a_stale_policy_...`, not-synced test | `HOLD` |
| Malformed provider response | `test_a_malformed_provider_body_fails_closed_...` | `HOLD` |
| Provider outage | `test_a_provider_outage_fails_closed_...` | `HOLD` |

No authorization bypass, permissive fallback, or weakened check exists.

## 7. Tests, static analysis, CI

No code changed in this mission, so the counts are identical to Mission 32's
verified run on this commit (`5962c91`). Re-run to confirm:

| Check | Result |
| --- | --- |
| `pytest tests/ -q` (filesystem) | see §7.1 |
| `pytest tests/ -q` (PostgreSQL 16) | see §7.1 |
| `pyflakes tracesettle/ tests/` | see §7.1 |
| `compileall tracesettle/` | see §7.1 |
| CI on `5962c91` | all five jobs green |

### 7.1 Actual results

| Check | Result |
| --- | --- |
| filesystem `pytest tests/ -q` | **1990 passed, 34 skipped** |
| PostgreSQL 16 `pytest tests/ -q` | **2014 passed, 10 skipped** |
| `pyflakes tracesettle/ tests/` | clean |
| `compileall tracesettle/` | OK |
| CI (`5962c91`) | Tests and static analysis, PostgreSQL, Docker, TEE guest digest parity, Vercel container image — all **success** |

## 8. Remaining blocker and the exact unblock

One blocker only: register the credential under the secret name
`NEAR_INTENTS_AGENT_API_KEY` in the OpenHands secret manager so it is injected as
an environment variable. Then, with no code change:

```
python3 -m tracesettle provider auth
python3 -m tracesettle provider agents
python3 -m tracesettle provider policy <agent_id>
```

and re-run §4's verification. Until then, live authenticated policy retrieval
cannot be performed and is **not** claimed.
