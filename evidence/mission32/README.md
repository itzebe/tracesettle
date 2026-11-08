# Mission 32 — complete live provider verification

**FINAL STATUS: `AUTHENTICATION_FAILED`** — but not for a cryptographic or code
reason. The credential was **not present in the runtime**, so no authenticated
call could be made. This is the same blocker Mission 31 reported; the secret was
not delivered to this environment.

## 1. Credential presence — the blocking fact

Read directly from the protected environment without displaying the value:

```
NEAR_INTENTS_AGENT_API_KEY:        ABSENT
TRACESETTLE_NEAR_AGENT_API_KEY:    ABSENT
NEAR_AGENT_API_KEY:                ABSENT
NEAR_INTENTS_AGENT_API_URL:        ABSENT
TRACESETTLE_NEAR_AGENT_API_URL:    ABSENT
```

A broader scan of plausible registered secret names (12 candidates, including
`NEAR_INTENTS_API_KEY`, `AGENT_API_KEY`, `PROVIDER_API_KEY`, …) resolved none.
The literal placeholder `[ENTER NEAR INTENTS API KEY HERE]` was **not** consumed.
No key was printed, logged, written to a file, or committed.

**Action required:** register the key under the secret name
`NEAR_INTENTS_AGENT_API_KEY` in the OpenHands secret manager so it is injected as
an environment variable. Without it, steps 3–6 of the mission cannot run live.

## 2. The provider is reachable; the auth boundary is real

Keyless, read-only probes against the live provider (`provider_probe.json`):

| Probe | Result |
| --- | --- |
| `GET /openapi.json` | `200` — "NEAR Intents Agent API" v1.0.0, 40 `/v1/…` paths; securitySchemes `[ApiKey, GrantToken]`; `/v1/whoami`, `/v1/agents`, `/v1/agents/{agent_id}/policy` are all `ApiKey`-gated |
| `GET /v1/network` | `200` — `network: mainnet`, `contract_id: outlayer.near`, `status.overall: operational` |
| `GET /v1/whoami` (no key) | `401 invalid_api_key` |
| `GET /v1/agents` (no key) | `401 invalid_api_key` |
| `GET /v1/agents/{id}/policy` (no key) | `401 invalid_api_key` |

The `401` is the documented auth boundary, **not** an outage. So this is
`AUTHENTICATION_FAILED` (no credential), **not** `PROVIDER_UNAVAILABLE`.

## 3. The real CLI commands (read-only) fail closed

Run against the live base URL with no key:

- `python3 -m tracesettle provider auth` → `authenticated: false`,
  `key_configured: false`, exit `1`.
- `python3 -m tracesettle provider agents` → `availability: UNAUTHENTICATED`,
  `count: 0`, exit `1`.
- `python3 -m tracesettle provider policy <id>` → `availability: UNAUTHENTICATED`,
  `policy: null`, exit `1`.

None of them prints the key. This is the correct fail-closed behaviour.

## 4. What *was* proven — the full authenticated chain over a real socket

With no live key, the **real** `HttpClient` (urllib), the **real** `PolicyAdapter`
(`authenticate`, `list_agents`, `read_policy`), the **real** `parse_policy` and
the **real** `ProviderPolicyGate` were driven against a local HTTP server that
enforces the `X-API-Key` header and returns the provider's documented `PolicyView`
shape. Capture: `authenticated_chain_stub.json`.

| Step | Result |
| --- | --- |
| `authenticate` (valid key) | `authenticated: true`, `api_key_id`/`tenant_id` surfaced |
| `authenticate` (wrong key) | `authenticated: false`, "provider rejected the key" |
| `list_agents` | `AVAILABLE`, 1 agent parsed from the documented envelope |
| `read_policy` | `AVAILABLE`, `in_force: true`, revision 7, `native.near.transfer: true` |
| gate, in-force policy | `IN_FORCE` → `ALLOW` |
| gate, transfer disabled | `NATIVE_TRANSFER_DISABLED` → `BLOCK` |
| gate, not applied/synced | `NOT_IN_FORCE` → `HOLD` |
| gate, malformed body | fails closed → `HOLD` |
| gate, provider outage (503) | `UNAVAILABLE` → `HOLD` |
| `read_policy` with no key | `UNAUTHENTICATED` (never calls the provider) |

The transport is the only substitution. This proves the **code path** a live key
would take — it does **not** claim live provider state.

## 5. The retrieved policy changes the decision for the exact same transaction

`tests/test_near_provider_policy_enforcement.py::test_the_retrieved_policy_changes_the_decision_for_the_same_transaction`
prepares the **identical** approved transaction twice; the only difference is the
policy the provider returned. An in-force policy that enables the transfer
authorizes (`ALLOW`); the same policy with the transfer disabled does not. The
test asserts `allowed.transaction.tx_hash_bytes == refused.transaction.tx_hash_bytes`,
so the decision provably comes from the retrieved policy, not the request.

## 6. Fail-closed coverage (unauthorized / missing / malformed / stale / outage)

| Case | Test | Result |
| --- | --- | --- |
| Unauthorized (no key) | `test_list_agents_refuses_without_a_key_*`, `read_policy` no-key | refuse, no provider call |
| Wrong key (401) | `test_list_agents_reports_unauthenticated_on_401`, `authenticate_wrong_key` | refuse |
| Missing policy (404) | `test_adapter_reports_not_found_*` | `NOT_FOUND` → `HOLD` |
| Malformed policy | `test_adapter_reports_malformed_on_a_bad_shape`, `test_a_malformed_provider_body_fails_closed_*` | `MALFORMED`/`NOT_IN_FORCE` → `HOLD` |
| Stale policy | `test_adapter_refuses_a_stale_policy_when_a_freshness_bound_is_set` | `STALE` → `HOLD` |
| Provider outage | `test_a_provider_outage_fails_closed_on_the_execution_path` | `UNAVAILABLE` → `HOLD` |
| Agent mismatch | `test_...agent_mismatch...` | `BLOCK` |

Every failure to *establish* the policy resolves to `HOLD` (never `ALLOW`); an
explicit provider denial resolves to `BLOCK`.

## 7. New this mission

- Read-only CLI `python3 -m tracesettle provider policy <agent_id>`
  (`cmd_provider_policy`), so steps 5–6 can be run the moment a key is present.
- +6 tests: 3 CLI (`provider policy`) and 3 enforcement
  (decision-change-for-same-transaction, provider-outage, malformed-body).

## 8. Honest classification

| Claim | Status |
| --- | --- |
| Live authenticated `whoami` / `agents` / policy read | **ACCESS-BLOCKED** (no credential) |
| Provider reachable; auth boundary real | **INDEPENDENTLY VERIFIED** |
| Real CLI commands fail closed without a key | **IMPLEMENTED AND TESTED** |
| Full authenticated chain (real adapter→parser→gate) over a real socket | **IMPLEMENTED AND TESTED** (stub transport) |
| Retrieved policy changes the decision for the same transaction | **IMPLEMENTED AND TESTED** |
| Fail-closed on unauthorized/missing/malformed/stale/outage | **INDEPENDENTLY VERIFIED** |
| Enforcement + fail-closed (Missions 23/25/29) | **INDEPENDENTLY VERIFIED** |
| Durable signature / restart verification (Missions 27/29) | **INDEPENDENTLY VERIFIED** |

No live policy was retrieved, so TraceSettle is **not** claimed to enforce a real
live policy in this mission. That is the single remaining step, gated only on
credential delivery.

## 9. Test results

| Command | Result |
| --- | --- |
| `pytest tests/ -q` (filesystem) | **1990 passed, 34 skipped** |
| `TRACESETTLE_TEST_PG_DSN=… pytest tests/ -q` (PostgreSQL 16) | **2014 passed, 10 skipped** |
| `pyflakes tracesettle/ tests/` | clean |
| `compileall tracesettle/` | OK |
| `demo/demonstrate.py --offline` twice | byte-identical |
| Mutation: revert the PolicyView envelope fix | 4 tests fail (not vacuous) |

Baseline (Mission 31, `266e737`): filesystem 1984 passed / 34 skipped; PostgreSQL
2008 passed / 10 skipped. The +6 are the three `provider policy` CLI tests and the
three enforcement tests (decision-change-for-same-transaction, provider-outage,
malformed-body).
