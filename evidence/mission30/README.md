# Mission 30 — Authenticate NEAR Intents Provider

Read-only, zero-cost. No key is stored in the repository, no paid endpoint is
called, no mainnet transaction is made, nothing is deployed or merged.

## Objective

Authenticate TraceSettle against the NEAR Intents Agent API and make the
provider read path work against the provider's **actual** documented response
shapes — without weakening the fail-closed guarantees.

## Outcome in one line

The authenticated read path is implemented, tested and proven to reach the real
provider and classify its responses correctly; a **successful** authenticated
read is `ACCESS-BLOCKED` because the API key is not delivered to this runtime.

## Status of each claim

| Claim | Status |
| --- | --- |
| Provider base URL and endpoints are real (from the live OpenAPI) | INDEPENDENTLY VERIFIED |
| `GET /v1/network` reachable, unauthenticated, operational | INDEPENDENTLY VERIFIED |
| `GET /v1/whoami` reachable and requires `X-API-Key` | INDEPENDENTLY VERIFIED |
| Adapter's policy parser matches the documented `PolicyView` | IMPLEMENTED AND TESTED |
| `PolicyAdapter.authenticate()` (whoami) implemented | IMPLEMENTED AND TESTED |
| `python3 -m tracesettle provider auth` CLI command | IMPLEMENTED AND TESTED |
| Provider env names (`NEAR_INTENTS_AGENT_*`) honoured | IMPLEMENTED AND TESTED |
| **Successful** authenticated read against a live key | ACCESS-BLOCKED |

## Why the live read is blocked

`NEAR_INTENTS_AGENT_API_KEY` is **not present** in this runtime's environment
(`len == 0`; the name is absent from the injected-secret set). The key was to be
supplied through the secure secret input, but it is not registered, so no value
is injected. A key must never be pasted into source, a command line, or a log,
so the live read is deferred rather than faked.

The request path itself is proven to be genuine: with an obviously invalid key
the CLI reaches the provider and the provider answers
`401 invalid_api_key` — the exact documented auth boundary (see
`provider_probe.json`).

## Files

- `provider_probe.json` / `provider_probe.py` — a real, read-only probe of the
  provider's OpenAPI, `/v1/network` and `/v1/whoami` (no key sent).
- `policy_schema_integration.md` — the integration defect found against the
  documented schema and its fix, with the official references.
- `limitations.md` — the honest limitations list.
