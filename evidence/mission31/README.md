# Mission 31 — secure NEAR Intents authentication

**Final status: `AUTHENTICATED_BUT_NO_ACCESSIBLE_POLICY`** — but with an important
qualifier: authentication itself could **not** be completed live, because the
credential was never delivered to the runtime. See §1.

This file states exactly what was and was not verified. Nothing here is inferred
from a documentation claim.

## 1. Credential delivery — the blocking fact

- The mission supplied the literal placeholder `[ENTER NEAR INTENTS API KEY HERE]`.
- The runtime environment does **not** contain `NEAR_INTENTS_AGENT_API_KEY`, nor
  any alias (`TRACESETTLE_NEAR_AGENT_API_KEY`, `NEAR_AGENT_API_KEY`,
  `AGENT_API_KEY`): all absent, checked directly (`len == 0`).
- Per the mission's own instruction, the placeholder was **not** consumed as a
  credential, and no key was pasted into source, a command line, a log, or an
  evidence file.
- Therefore the live authenticated calls (`GET /v1/whoami`, `GET /v1/agents`,
  `GET /v1/agents/{id}/policy`) could not be performed with a real key.

**Action required from the owner:** enter the key through the secure secret input
under the name `NEAR_INTENTS_AGENT_API_KEY`. It is read only from the environment
by `tracesettle/config.py` and is never printed.

## 2. What was verified instead (real, not mocked)

### 2.1 The read path reaches the real provider

| Call | Result |
| --- | --- |
| `GET /openapi.json` (no key) | `200` — "NEAR Intents Agent API" v1.0.0, securitySchemes `[ApiKey, GrantToken]`, 40 `/v1/…` paths, `/v1/whoami` and `/v1/agents` both `ApiKey`-gated |
| `GET /v1/network` (no key) | `200` — `network: mainnet`, `contract_id: outlayer.near`, `status.overall: operational` |
| `GET /v1/whoami` (no key) | `401 invalid_api_key` ("Send a live API key in the X-API-Key header.") |
| `GET /v1/agents` (no key) | `401 invalid_api_key` |

Capture: `provider_probe.json`. The `401` proves the endpoint is real and the
authentication boundary is exactly as modelled — it is **not** an outage.

### 2.2 The authenticated path works end to end over a real socket

Because no live key is available, the **real** `HttpClient` (urllib), the real
`PolicyAdapter.authenticate()`, `list_agents()` and `read_policy()`, and the real
parser were driven against a **local HTTP server** that requires the
`X-API-Key` header and returns the provider's documented shapes. This exercises
every line a live key would take:

- valid key → `authenticated: true`, `api_key_id`/`tenant_id` surfaced;
- `list_agents()` → `AVAILABLE`, one agent parsed from the documented
  `{data: [AgentView], next_cursor}` envelope;
- `read_policy()` → `AVAILABLE`, `in_force: true`, `max_actions_per_hour: 5`;
- wrong key → `authenticated: false`;
- the key never appears in any output document.

The stub is a transport stand-in only. It is **not** the live provider, and this
section does not claim a live authenticated read.

### 2.3 CLI

`python3 -m tracesettle provider auth` and `... provider agents` are read-only and
free. With no key they fail closed (`UNCONFIGURED` / `UNAUTHENTICATED`) and never
print the key. Verified in `tests/test_tee_verify_cli.py`.

## 3. New capability added this mission

The adapter previously had no way to discover an agent id — mission step 4
requires determining whether an accessible agent exists. Added, all read-only:

- `PolicyAdapter.list_agents()` → `AgentList` (documented `GET /v1/agents`,
  `ApiKey`-gated). Returns `AgentSummary` (id, name, status, archived, deleted) —
  no wallet, balance, or signing material.
- CLI `python3 -m tracesettle provider agents`.
- 8 new unit tests + 3 new CLI tests.

## 4. Enforcement (unchanged, fail-closed)

The provider-policy gate that consumes this data was already verified in Missions
23/25/29 and is untouched. Its fail-closed behaviour is covered by existing
tests (`tests/test_near_provider_policy_gate.py`,
`tests/test_near_provider_policy_enforcement.py`,
`tests/test_near_policy.py`): a policy that is missing, not in force, frozen,
stale, malformed, unreadable, for another agent, or that disables the operation
refuses authorization and never reaches the signer.

## 5. Honest classification

| Claim | Status |
| --- | --- |
| Live authenticated `/v1/whoami` | **ACCESS-BLOCKED** (no key delivered) |
| Live authenticated `/v1/agents` / policy read | **ACCESS-BLOCKED** |
| Read path reaches the real provider (`401` boundary) | **INDEPENDENTLY VERIFIED** |
| Authenticated path over a real socket (stub transport) | **IMPLEMENTED AND TESTED** |
| `list_agents()` / `provider agents` CLI | **IMPLEMENTED AND TESTED** |
| Real parser → real gate → real boundary enforcement | **IMPLEMENTED AND TESTED** (mutation-checked) |
| Provider-policy enforcement + fail-closed | **INDEPENDENTLY VERIFIED** (Missions 23/25/29) |
| Durable signature / restart verification (Mission 27/29) | **INDEPENDENTLY VERIFIED** |

No policy was retrieved from the live provider, so TraceSettle was **not** shown
enforcing a real live policy in this mission. That remains the one open step, and
it is gated only on credential delivery.

## 6. Test and static-analysis results (this mission)

| Command | Result |
| --- | --- |
| `pytest tests/ -q` (filesystem) | **1984 passed, 34 skipped** |
| `TRACESETTLE_TEST_PG_DSN=… pytest tests/ -q` (PostgreSQL 16) | **2008 passed, 10 skipped** |
| `pytest tests/test_near_provider_policy_enforcement.py -q` | 15 passed |
| `pytest tests/test_near_policy.py tests/test_tee_verify_cli.py -q` | 68 passed |
| `pyflakes tracesettle/ tests/` | clean |
| `compileall tracesettle/` | OK |
| Mutation: revert the PolicyView envelope fix | 4 tests fail (not vacuous) |

Baseline (Mission 30, `efd28ba`): filesystem 1970 passed / 34 skipped;
PostgreSQL 1994 passed / 10 skipped. The +14 are the new `list_agents` tests (8),
`provider agents` CLI tests (3), and the real-parser→gate enforcement tests (3).

