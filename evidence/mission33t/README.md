# Mission 33T — authenticate with the new Partner API Key

**Date:** 2026-11-09 · **Branch:** `feat/mission29-release-closure` @ `7553cba`
**Base:** `master` @ `e7691d2` · **PR:** #29 (open, draft, unmerged)

## Outcome

**`AUTHENTICATION_FAILED` — the replacement credential is present, freshly
issued, and rejected by the Agent API (it is an *explorer*-scoped key, not a
partner-scoped Agent API key).**

This mission set out to use a newly issued **NEAR Intents Partner API Key** to
complete genuine, read-only Agent API authentication and read an existing
agent's actual policy. The credential `NEAR_INTENTS_AGENT_API_KEY` **is**
injected into this runtime and **is** a replaced value (its non-secret `iat`
moved from `2026-11-08T14:45:51Z` to `2026-11-09T10:09:33Z`, minutes before this
session). But its non-secret JWT claim `key_type` is **`explorer`**, and the
Agent API rejects it with HTTP 401 `invalid_api_key`.

The provider's own documentation is explicit about what a Partner API Key is:
an **opaque string created in the partner portal**, sent as `X-API-Key`. The
injected value is instead a 530-character **JWT** whose own claim says it is an
**explorer** key — the same key family as Mission 33S. So the runtime received a
replaced credential, but it is **still explorer-scoped**, and the Agent API
never authenticates.

Because authentication fails, **no policy can be read**. So
`AUTHENTICATED_AND_POLICY_VERIFIED` and `AUTHENTICATED_BUT_NO_ACCESSIBLE_POLICY`
are both unreachable: authentication itself failed.

## 1. Environment — credential present and replaced

Checked by name and by **non-secret** structural claims only. The value was
never displayed, printed, logged, hashed, encoded, persisted, transmitted or
committed. Capture: `credential_presence.json`.

| Check | Result |
| --- | --- |
| `NEAR_INTENTS_AGENT_API_KEY` present | **yes** |
| nonempty | **yes** |
| length | 530 |
| whitespace-free | yes |
| is a JWT | yes (3 segments, `RS256`, `typ=JWT`) |
| non-secret claims | `exp`, `iat`, `key_type`, `partner_id`, `v` |
| `key_type` | **`explorer`** |
| issued | `2026-11-09T10:09:33Z` (this session started ~10:13Z) |
| expires | `2027-11-09T10:09:33Z` (365-day lifetime) |
| expired | **no** |

### 1.1 Owner-side confirmation the runtime received a *replaced* value

Comparing the non-secret claims against the Mission 33S capture (never the
value) shows the injected value genuinely changed — capture:
`runtime_credential_change.json`.

| Fact | Mission 33S | Mission 33T |
| --- | --- | --- |
| issued_at | `2026-11-08T14:45:51Z` | `2026-11-09T10:09:33Z` |
| expires_at | `2027-11-08T14:45:51Z` | `2027-11-09T10:09:33Z` |
| `key_type` | `explorer` | **`explorer`** (unchanged) |
| value_replaced | — | **true** |

So: **the runtime did receive the newly issued credential** (issuance timestamp
advanced by ~19 hours), and **its scope did not change** — it is still
`explorer`.

## 2. Repository state (verified)

| Item | Value |
| --- | --- |
| repository | `itzebe/tracesettle` |
| branch | `feat/mission29-release-closure` |
| commit | `7553cba` (matches the expected head) |
| base | `master` @ `e7691d2` |
| PR | #29 — open, **draft**, unmerged |
| working tree | clean before this mission; only additive evidence added |

The expected SHA was checked, not assumed: `7553cba` is the tip of
`feat/mission29-release-closure` and the head of PR #29.

## 3. Live Agent API authentication (real provider, real key)

Command run exactly as the mission names (read-only, free):

```
python3 -m tracesettle provider auth --base-url https://api.agentsonintents.com --json
```

The documented header is `X-API-Key` (the provider's OpenAPI declares
`securitySchemes.ApiKey` = `{in: header, name: X-API-Key}`). Real response:

```json
{
  "api_key_id": null,
  "authenticated": false,
  "base_url_configured": true,
  "detail": "the provider rejected the key (invalid or retired credentials)",
  "endpoint": "https://api.agentsonintents.com/v1/whoami",
  "http_status": 401,
  "key_configured": true,
  "tenant_id": null
}
```

**Exact provider error:** HTTP `401`, code **`invalid_api_key`**,
`{"detail":"Send a live API key in the X-API-Key header."}`. `api_key_id` and
`tenant_id` are `null` — no tenant identity could be established. Redacted
capture: `cli_outcomes.md` / `cli_outcomes.json`, `live_adapter_read.json`.

## 4. Existing agents — none accessible

```
python3 -m tracesettle provider agents --base-url https://api.agentsonintents.com --json
```

Returns HTTP 401, `availability: UNAUTHENTICATED`, `count: 0`. No agent id could
be discovered, so **none was invented**. The policy command used a documented
all-zero placeholder and never reached policy parsing:

```
python3 -m tracesettle provider policy 0000000000000000000000000000000000000000000000000000000000000000 --base-url https://api.agentsonintents.com --json
```

→ HTTP 401, `availability: UNAUTHENTICATED`, `policy: null`.

Because no existing agent is accessible, **policy revision, status,
`provider_policy_synced`, freshness and permissions could not be verified** —
not because they were checked and found wrong, but because the read never
authenticated. No agent was created (mission restriction).

## 5. The credential's actual scope — explorer, not partner

The key is **live**, but on a different surface with a different header. The
Agent API rejects it; the **Explorer API** accepts it. Capture: `key_scope.json`.

| Surface | Header | Result with this key |
| --- | --- | --- |
| Agent API `api.agentsonintents.com/v1/whoami` | `X-API-Key` | **401 `invalid_api_key`** |
| Explorer API `explorer.near-intents.org/api/v0/transactions` | `Authorization: Bearer` | **200** |

The provider's docs (`docs.agentsonintents.com/integration/agent-api/authentication`)
state the Partner API Key is "an opaque string, created in the partner portal,
shown once" and is sent as `X-API-Key`. A genuine partner key is therefore **not
a JWT**, and the injected credential — a JWT that self-describes as
`key_type: explorer` — is not one. The provider directs key creation to
`partners.near-intents.org`, which requires the owner's sign-in (an owner-only
action, out of scope here).

## 6. Not a provider outage

The provider is fully reachable and serving; it rejects *this key*. The
unauthenticated and wrong-key responses are byte-identical, so no "missing key"
hint is available — the key is simply not accepted. Capture:
`provider_reachability.json`.

| Probe | Result |
| --- | --- |
| `GET /openapi.json` | 200 (`NEAR Intents Agent API` v1.0.0, 40 `/v1` paths) |
| `GET /v1/network` | 200 |
| `GET /v1/tokens` | 200 |
| `GET /v1/agents` (no auth) | 401 `invalid_api_key` |
| `GET /v1/whoami` (with key) | **401 `invalid_api_key`** |

## 7. Enforcement stays fail-closed (same transaction)

Even though the provider refuses the read, the enforcement behaviour is real and
was demonstrated live. The same transaction, with an **identical bytes binding**
(`binding` includes the `transaction_digest`), is driven through the real NEAR
execution boundary; only the provider-policy layer changes. Capture:
`enforcement_demo.json` (`enforcement_demo.py`).

| Configuration | Decision | Authorized |
| --- | --- | --- |
| operator policy alone | `ALLOW` | yes (`auth_812a92cf…`) |
| + live provider-policy layer (`require=True`) | **`HOLD`** | **no** (authorization discarded) |

The provider verdict is `outcome: UNAUTHENTICATED`, `source: live`, endpoint
`https://api.agentsonintents.com/v1/agents/treasury-agent/policy`, and the guard
finding `PROVIDER_POLICY_UNAUTHENTICATED` is attached. The layer can only ever
*tighten* a decision; a read it cannot establish fails closed to `HOLD`, never to
an authorization. The flip is caused by the provider policy, not by any change
to the transaction.

## 8. Failure-mode matrix (real guard, real boundary)

Every failure mode the mission lists was exercised against the real
`ProviderPolicyGate` and `combine_provider_policy` with the same transaction.
Capture: `failure_modes.json` (`failure_modes.py`). The `UNAUTHENTICATED` row
uses the **live** Agent API with the injected key.

| Scenario | Provider outcome | Guard decision | Authorized |
| --- | --- | --- | --- |
| IN_FORCE (control) | `IN_FORCE` | `ALLOW` | **yes** |
| NOT_IN_FORCE | `NOT_IN_FORCE` | `HOLD` | no |
| FROZEN | `FROZEN` | `BLOCK` | no |
| NATIVE_TRANSFER_DISABLED | `NATIVE_TRANSFER_DISABLED` | `BLOCK` | no |
| AGENT_MISMATCH | `AGENT_MISMATCH` | `BLOCK` | no |
| UNAUTHENTICATED (live) | `UNAUTHENTICATED` | `HOLD` | no |
| NOT_FOUND | `NOT_FOUND` | `HOLD` | no |
| MALFORMED | `MALFORMED` | `HOLD` | no |
| UNAVAILABLE | `UNAVAILABLE` | `HOLD` | no |
| UNCONFIGURED | `UNCONFIGURED` | `HOLD` | no |
| STALE | `STALE` | `HOLD` | no |
| REQUIRED_NO_ADAPTER | `EXECUTION_ERROR` | — | no |

The control authorizes, so the matrix is not a blanket refusal; every failure
mode refuses, so the layer is fail-closed. (An adapter that is configured with an
`expected_agent_id` catches a wrong-agent body one step earlier, as
`MALFORMED` — also `HOLD`, never an authorization.)

## 9. What could and could not be verified

| Requirement | Status |
| --- | --- |
| credential present and replaced | **established** (non-secret claims) |
| tenant identity (`api_key_id`, `tenant_id`) | **not established** — `whoami` rejected |
| agent access (accessible agents) | **not established** — `agents` rejected |
| policy revision / status / `provider_policy_synced` | **not established** — no policy read |
| freshness (`as_of`) | **not established** |
| synchronization | **not established** |
| transaction binding | **established** — identical binding across both runs |
| decision impact of the retrieved policy | **demonstrated as a fail-closed refusal** (no policy retrievable) |

## 10. Restrictions honoured

Zero spending · no paid calls/purchases/subscriptions · no agent creation · no
grant creation or issuance · no owner signatures · no wallet funding · no mainnet
transactions · no transfers/swaps/deposits/withdrawals · no provider-side state
changes · no security bypasses or weakened authorization · no merge, deployment
or publication · no unrelated feature development. Only documented read-only API
calls were made. PR #29 remains open and unmerged.

## 11. Files

| File | Contents |
| --- | --- |
| `credential_presence.json` | presence, length, non-secret JWT claims |
| `runtime_credential_change.json` | replaced-value confirmation vs Mission 33S |
| `provider_reachability.json` | public/authenticated endpoint status |
| `cli_outcomes.md` / `.json` | the three live CLI commands and their output |
| `key_scope.json` | Agent API vs Explorer API acceptance of this key |
| `live_adapter_read.json` | the product adapter's own live read result |
| `enforcement_demo.py` / `.json` | the decision-flip demonstration |
| `failure_modes.py` / `.json` | the fail-closed failure-mode matrix |
| `collect_evidence.py` | regenerates the JSON evidence (read-only) |

## 12. Required to close this

A **genuine Agent API Partner API Key** — created in the partner portal at
`partners.near-intents.org` (owner sign-in required) and stored as
`NEAR_INTENTS_AGENT_API_KEY`. That is an owner-only credential action, out of
scope here. Once a partner-scoped key is injected, re-run §3–§4: authentication
should answer 200 with `api_key_id`/`tenant_id`, agents should list, and an
existing agent's policy can be read and verified. No code change is needed — the
client already sends the documented `X-API-Key` header and already fails closed.

## 13. Conclusion

The runtime credential injection **works** and the runtime received a
**replaced** value (issuance advanced ~19 h). The replacement is **still an
explorer-scoped key** (non-secret claim `key_type: explorer`, and it is a JWT
where a partner key is an opaque string), so the **Agent API rejects it** with
HTTP 401 `invalid_api_key` while the **Explorer API accepts it**. No agent is
accessible, so no policy could be read. Enforcement is verified to remain
fail-closed. Final outcome: **`AUTHENTICATION_FAILED`** — explicitly distinct
from a missing credential and from a provider outage.

_This evidence was produced by an AI agent (OpenHands) on behalf of the
repository owner. No secret value appears in any file here._
