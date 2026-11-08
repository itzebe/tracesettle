# Mission 29 — provider authorization

## The provider and endpoint

- Provider: **NEAR Intents Agent API** (`api.agentsonintents.com`).
- Endpoint: `GET /v1/agents/{agent_id}/policy` — the documented policy read
  (`docs.agentsonintents.com/integration/agent-api/policies-and-limits`).
- Auth: `X-API-Key` header (the provider's published `ApiKey` security scheme).

## Credential availability — without exposing the credential

- **No Agent API credential is present in this environment.** No
  `TRACESETTLE_NEAR_AGENT_API_URL` / `TRACESETTLE_NEAR_AGENT_API_KEY` (or the
  `TRACESETTLE_TEST_AGENT_API_*` test pair) is set, and no `.env` on disk carries
  one (the only tracked env file is `deploy/production/.env.production.example`,
  placeholders only).

## Live retrieval evidence (unauthenticated probe — free, no cost)

```
$ curl -s -o /dev/null -w '%{http_code}' https://api.agentsonintents.com/v1/agents/NEAR_AGENT_ID/policy
401
{"errors":[{"status":"401","code":"invalid_api_key","layer":"auth",
 "title":"Invalid api key","detail":"Send a live API key in the X-API-Key header."}]}
```

This confirms the endpoint is **real and documented** and that the adapter's
auth boundary (`UNAUTHENTICATED` on 401/403) matches the provider exactly. It is
not a fabricated or invented endpoint.

## Enforcement evidence (offline, real code paths)

The adapter and the gate are fully implemented and exercised without a network
call. `PolicyAdapter.read_policy` verifies four things before reporting
`AVAILABLE`: the provider **host** (pinned), the **agent association** (against
the body, not just the request), the policy `as_of` **freshness** (bounded), and
that the body **parsed**. Any failure is a non-available read.

`ProviderPolicyGate` (in `near/provider_policy_gate.py`) then runs **after** the
guard and can only *tighten* the decision:

- `IN_FORCE` → `ALLOW`; an explicit denial (`FROZEN`, `NATIVE_TRANSFER_DISABLED`)
  → `BLOCK`; every failure to *establish* policy (`UNCONFIGURED`, `UNAVAILABLE`,
  `MALFORMED`, `UNAUTHENTICATED`, `NOT_FOUND`, `STALE`, `AGENT_MISMATCH`,
  `NOT_IN_FORCE`) → `HOLD`, which never authorizes signing.
- A **required** layer with no adapter is a hard refusal (`ExecutionError`),
  never a silent fall-through to the operator policy alone.

Both layers are enforced on the two execution paths (the NEAR execution boundary
and the OutLayer custody boundary) and asserted by invariants
`near_execution_enforces_the_provider_policy` and
`custody_provider_policy_only_tightens` (mutation-tested).

## Exact remaining blocker

A **successful authenticated live read** requires a live `X-API-Key` that only
the user or the provider can supply. Without it the adapter correctly reports
`UNCONFIGURED` (no base URL) or `UNAUTHENTICATED` (URL but no key) and the guard's
own operator policy governs. This is the single unresolved dependency for
criterion 2; it is not a code gap.

Verify when a credential is supplied (never run without one):

```
TRACESETTLE_TEST_AGENT_API_URL=https://api.agentsonintents.com \
TRACESETTLE_TEST_AGENT_API_KEY=<key> \
TRACESETTLE_TEST_AGENT_ID=<agent_id> \
python3 -m pytest tests/test_near_live_provider.py -q
```
