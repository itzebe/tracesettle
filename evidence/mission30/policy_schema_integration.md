# Policy schema integration — a real defect, found and fixed

## What the provider actually returns

`GET /v1/agents/{agent_id}/policy` returns a **`PolicyView`** (per the provider's
live OpenAPI, `https://api.agentsonintents.com/openapi.json`, fetched
2026-11-08). Its lifecycle fields sit at the **top level** and the rules are
nested under a `policy` object:

```json
{
  "wallet_id": "...",
  "revision": 7,
  "policy_hash": "…64 hex…",
  "status": "APPLIED",
  "applied_at": "…",
  "transaction_hash": "…",
  "provider_policy_synced": true,
  "cooldowns": { "policy_change_available_at": null, "unfreeze_available_at": null },
  "policy": {
    "frozen": false,
    "actions": ["swap", "transfer", "withdraw"],
    "assets": "any",
    "limits": { "per_transaction": {"nep141:usdc.near": "100000000"}, … },
    "max_actions_per_hour": 20,
    "destinations": { "mode": "only", "list": [ … ] },
    "budget": { "daily_usd": "500.00", "weekly_usd": null, "monthly_usd": null },
    "timelock_ms": 0,
    "native": { "near": { "sign_message": [], "transfer": false, "call": [] }, … }
  },
  "usage": { "budget": { "daily": {"limit_usd": "…", "spent_usd": "…"} }, "timelock": {…} }
}
```

The provider's own documentation
(`docs.agentsonintents.com/integration/agent-api/policies-and-limits`) confirms:
*in force once `status` is `APPLIED` **and** `provider_policy_synced` is true*,
`max_actions_per_hour` sits **beside** `limits`, the dollar ceiling is
`budget.daily_usd` / `weekly_usd` / `monthly_usd`, and the documented read uses
`-H "X-API-Key: $NEAR_INTENTS_AGENT_API_KEY"`.

## The defect

`parse_policy` treated `raw["policy"]` (when present) as the *whole* document and
ignored the top-level envelope. Against the real `PolicyView` it therefore:

1. **Rejected the document outright** — `budget` is an *object*
   (`{"daily_usd": …}`), but the parser fed it to `Decimal()`, raising
   `PolicyParseError: policy.budget_usd is not a valid decimal number`. A genuine,
   in-force policy was reported `MALFORMED`.
2. Would otherwise have read **`status`/`provider_policy_synced` as absent**
   (they live in the envelope, not under `policy`) → `in_force == False`. A real
   applied policy would have been treated as not-in-force.
3. Read `max_actions_per_hour` from inside `limits`, but the documented `Policy`
   places it beside `limits` → the hourly action cap was silently lost.
4. Read `native.*` switches with `bool(...)`, but the documented switches
   `sign_message` / `call` / `sign_transaction` are **arrays** (a non-empty array
   means on). `bool([])` is `False`, so a *non-empty* array would have read as
   **off** (a false negative) and a *non-empty* one as on — the wrong rule.

None of these were fail-open; each made the gate **stricter or wrong**, but a
genuine in-force policy reading as "malformed / not in force" makes the whole
provider-policy layer useless in production.

## The fix (`tracesettle/near/policy.py`)

* `parse_policy` now recognises the `PolicyView` envelope: the nested `policy`
  provides the **rules**, the top level provides the **lifecycle**
  (`status`, `provider_policy_synced`, `revision`, `policy_hash`, `applied_at`).
  A flat document (local fixtures, offline demo) still parses unchanged.
* `max_actions_per_hour` is read from beside `limits` (and still from inside
  `limits` for the flat shape).
* `budget` is read from `budget.daily_usd|weekly_usd|monthly_usd` (tightest set
  window), with a new `budget_spent_usd` read **only** from `usage.budget`, never
  conflated with the budget object.
* Native switches accept the documented array form: empty ⇒ off, non-empty ⇒ on;
  a boolean is also accepted; anything else ⇒ off.
* `as_of` falls back to the documented `applied_at` so freshness works.

## Regression tests (`tests/test_near_policy.py`)

Seven new tests pin the documented shape:
`test_policy_view_envelope_is_parsed_and_in_force`,
`test_policy_view_rules_are_read_from_the_nested_policy`,
`test_policy_view_native_methods_use_the_documented_array_form`,
`test_policy_view_not_applied_reads_not_in_force`,
`test_policy_view_flat_document_still_parses`,
`test_adapter_reads_a_policy_view_from_the_provider`,
`test_adapter_enforces_freshness_using_applied_at`.

The new synthetic fixture `tracesettle/near/fixtures/policy_view_applied.json`
carries `"_provenance": "synthetic"` and a note naming the live OpenAPI it
reproduces. It is not live provider state.
