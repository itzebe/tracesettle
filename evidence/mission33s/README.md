# Mission 33S — fresh runtime credential injection & live provider verification

**Date:** 2026-11-09 · **Branch:** `feat/mission29-release-closure` @ `506ac95`
**Base:** `master` @ `e7691d2` · **PR:** #29 (open, draft, unmerged)

## Outcome

**`AUTHENTICATION_FAILED` — credential rejected (not missing, not a provider outage).**

The credential `NEAR_INTENTS_AGENT_API_KEY` **is** injected into this runtime and is
well-formed, but the **NEAR Intents Agent API rejects it** with HTTP 401
`invalid_api_key`. The key is a valid, unexpired JWT of `key_type: explorer`, and it
**is accepted by the NEAR Intents Explorer API** (`explorer.near-intents.org`,
`Authorization: Bearer`) — so the secret is a live credential, just not one the
**Agent API** accepts. The Agent API requires a partner/agent-scoped key issued at
`partners.near-intents.org`; this runtime holds an explorer-scoped key.

Because the Agent API never authenticates, **no policy can be read**, so
`AUTHENTICATED_AND_POLICY_VERIFIED` and `AUTHENTICATED_BUT_NO_ACCESSIBLE_POLICY` are
both unreachable: authentication itself failed.

## 1. Environment — credential present

| Check | Result |
| --- | --- |
| `NEAR_INTENTS_AGENT_API_KEY` present | **yes** |
| nonempty | **yes** |
| length | 530 |
| whitespace-free | yes |
| JWT segments | 3 (`RS256`, `typ=JWT`) |
| non-secret claims | `exp`, `iat`, `key_type`, `partner_id`, `v` |
| `key_type` | **`explorer`** |
| issued / expires | 2026-11-08 / 2027-11-08 (365-day lifetime) |
| expired | **no** |

The value is never displayed, logged, hashed, encoded, persisted or committed. Only
presence, length and non-secret structural claims are recorded
(`credential_presence.json`).

## 2. Repository state

| Item | Value |
| --- | --- |
| repository | `itzebe/tracesettle` |
| branch | `feat/mission29-release-closure` |
| commit | `506ac95` |
| base | `master` @ `e7691d2` |
| PR | #29 — open, **draft**, unmerged |
| working tree | clean before this mission; only additive evidence added |

## 3. Live provider verification (real provider, real key)

Commands run (read-only, free):

```
python3 -m tracesettle provider auth   --base-url https://api.agentsonintents.com --json
python3 -m tracesettle provider agents --base-url https://api.agentsonintents.com --json
python3 -m tracesettle provider policy <agent_id> --base-url https://api.agentsonintents.com --json
```

All three return **HTTP 401 `invalid_api_key`**, `availability: UNAUTHENTICATED`,
exit 1 (`cli_outcomes.md`). No agent id could be discovered, so the `policy` command
used a documented placeholder (64 hex zeros) — it never reached policy parsing.

Independent confirmation (raw `curl`, key only in a header, never printed):

* `X-API-Key: <key>` → `401 {"code":"invalid_api_key", "detail":"Send a live API key in the X-API-Key header."}`
* `Authorization: Bearer <key>` → same `401`
* `Authorization: ApiKey <key>` → same `401`

The provider's own OpenAPI (`GET /openapi.json`, HTTP 200) documents the scheme as
`ApiKey`, `in: header`, `name: X-API-Key` — exactly what was sent. The client is
therefore not at fault.

## 4. Not a provider outage

| Probe | Result |
| --- | --- |
| `GET /openapi.json` | 200 |
| `GET /v1/network` (public) | 200 |
| `GET /v1/tokens` (public) | 200 |
| `GET /v1/agents` (no auth) | 401 |
| `GET /v1/whoami` (with key) | **401 `invalid_api_key`** |

The provider is fully reachable and serving; it is rejecting *this key*
(`provider_reachability.json`).

## 5. Missing vs rejected — the key is live, but on the wrong surface

| Surface | Header | Result with this key |
| --- | --- | --- |
| Agent API `api.agentsonintents.com/v1/whoami` | `X-API-Key` | **401 `invalid_api_key`** |
| Explorer API `explorer.near-intents.org/api/v0/transactions` | `Authorization: Bearer` | **200** |

The Explorer API genuinely validates the JWT: a forged-signature token of the same
shape is refused `400 INVALID_TOKEN`, a missing header is `400 MISSING_TOKEN`, and the
real key returns `200` with transaction data. So the credential is real and live — it
is an **explorer** key, and the **Agent API** does not accept explorer keys.

**Required to close this:** an Agent API key issued for a partner at
`partners.near-intents.org` (the provider's own error directs users there). That is an
owner-only credential action, out of scope here (no agent/grant creation, no paid
calls).

## 6. Policy enforcement — the live layer still changes the decision

Even though the provider refuses the read, the *enforcement* behaviour is real and
was demonstrated live (`enforcement_demo.py` → `enforcement_demo.json`). The same
transaction, with an **identical bytes binding** (`binding` includes the
`transaction_digest`), is driven through the real NEAR execution boundary:

| Configuration | Decision | Authorized |
| --- | --- | --- |
| operator policy alone | `ALLOW` | yes |
| + live provider-policy layer (`require=True`) | **`HOLD`** | **no** (authorization discarded) |

The provider-policy verdict is `outcome: UNAUTHENTICATED`, `source: live`, endpoint
`https://api.agentsonintents.com/v1/agents/treasury-agent/policy`, and the guard
finding `PROVIDER_POLICY_UNAUTHENTICATED` is attached. The layer can only ever
*tighten* a decision, and a read it cannot establish fails closed to `HOLD` — never to
an authorization. The flip is caused by the provider policy, not by any change to the
transaction.

This is the honest, expected behaviour: **with no readable policy, nothing is
authorized.** It is not a substitute for `AUTHENTICATED_AND_POLICY_VERIFIED` — that
outcome requires a policy that is actually read, in force, and enabling the action.

## 7. What could and could not be verified

| Requirement | Status |
| --- | --- |
| tenant identity (`tenant_id`, `api_key_id`) | **not established** — `whoami` rejected |
| agent access (accessible agents) | **not established** — `agents` rejected |
| policy revision / status / `provider_policy_synced` | **not established** — no policy read |
| freshness (`as_of`) | **not established** |
| synchronization | **not established** |
| transaction binding | **established** — the enforcement demo shows an identical binding across both runs, and the provider layer is what changed the decision |
| decision impact of the retrieved policy | **demonstrated as a fail-closed refusal** (no policy retrievable) |

## 8. Restrictions honoured

Zero spending · no paid API calls · no mainnet transactions · no agent or grant
creation · no transfers/swaps/deposits/withdrawals · no provider-side state changes ·
no security bypasses · no merge or deployment · no unrelated feature development.

## 9. Files

| File | Contents |
| --- | --- |
| `credential_presence.json` | presence, length, non-secret JWT claims |
| `provider_reachability.json` | public/authenticated endpoint status |
| `cli_outcomes.md` / `.json` | the three live CLI commands and their output |
| `key_scope.json` | Agent API vs Explorer API acceptance of this key |
| `live_adapter_read.json` | the product adapter's own live read result |
| `enforcement_demo.py` / `.json` | the decision-flip demonstration |
| `collect_evidence.py` | regenerates the JSON evidence (read-only) |

## 10. Conclusion

The runtime credential injection **works** — `NEAR_INTENTS_AGENT_API_KEY` is present
and nonempty. The credential itself is **rejected by the NEAR Intents Agent API**
(HTTP 401 `invalid_api_key`) while being **accepted by the Explorer API**, i.e. it is a
live **explorer** key rather than an **Agent API** partner key. This is a
**rejected-credential** outcome, explicitly distinct from a missing credential and from
a provider outage. Final outcome: **`AUTHENTICATION_FAILED`**.

_This evidence was produced by an AI agent (OpenHands) on behalf of the repository
owner. No secret value appears in any file here._
