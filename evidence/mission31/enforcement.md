# Mission 31 — enforcement: does TraceSettle enforce the retrieved policy?

TraceSettle enforces **two independent** policies before an agent's payment can
reach a signer:

1. its own operator policy (the seven deterministic guard controls), and
2. the **provider** policy the NEAR Intents Agent API holds for the agent.

The second layer is `tracesettle/near/provider_policy_gate.py`. It runs *after*
the guard, can only **tighten** the outcome, and discards any authorization the
guard issued when the provider policy is not in force — so no token can reach a
signer.

## Vocabulary mapping (cannot-establish vs explicitly-denied)

| Provider outcome | Guard decision | Meaning |
| --- | --- | --- |
| `IN_FORCE` | `ALLOW` | applied, synced, not frozen, enables the action |
| `NOT_IN_FORCE` | `HOLD` | a requested/signed update is not active |
| `FROZEN`, `NATIVE_TRANSFER_DISABLED` | `BLOCK` | the provider says *no* |
| `UNCONFIGURED`, `UNAVAILABLE`, `UNAUTHENTICATED`, `NOT_FOUND`, `MALFORMED`, `STALE`, `AGENT_MISMATCH` | `HOLD` | we cannot establish the policy |

`HOLD` is the guard's "insufficient evidence" state and never authorizes signing.

## The corrected parser is connected to enforcement

The Mission 30 fix made `parse_policy` accept the provider's documented
`PolicyView` envelope (lifecycle at the top level, rules nested under `policy`).
This mission proves the *real* parser feeds the *real* gate:

- `tests/test_near_provider_policy_enforcement.py::test_the_real_parser_connects_a_documented_policy_view_to_enforcement`
  — a documented PolicyView drives the real `PolicyAdapter`, real `parse_policy`
  and real `ProviderPolicyGate` to `IN_FORCE` / `ALLOW`.
- `...::test_a_documented_policy_view_that_is_not_synced_is_refused_by_the_gate`
  — the envelope's top-level `provider_policy_synced: false` refuses.
- `...::test_a_documented_policy_view_with_native_transfer_off_is_blocked`.

The only substitution is the HTTP transport (a canned response). The adapter's
URL building, header handling, status classification, the parser and the gate all
run for real.

## Mutation test

Neutralising the envelope handling (`body = raw` instead of the nested `policy`)
makes **4** tests fail — including the enforcement integration test:

```
FAILED tests/test_near_provider_policy_enforcement.py::test_the_real_parser_connects_a_documented_policy_view_to_enforcement
FAILED tests/test_near_policy.py::test_policy_view_rules_are_read_from_the_nested_policy
FAILED tests/test_near_policy.py::test_policy_view_native_methods_use_the_documented_array_form
FAILED tests/test_near_policy.py::test_adapter_reads_a_policy_view_from_the_provider
```

So the tests are not vacuous.

## Transaction-to-policy binding and fail-closed cases (existing, unchanged)

The following are covered by existing tests that still pass (Missions 23/25/29):

- **Missing / unauthorized / unreadable policy** → `HOLD` / refusal
  (`test_an_unreadable_policy_blocks_when_required`,
  `test_a_required_layer_with_no_adapter_refuses_authorization`).
- **Not in force / frozen / native transfer disabled** → `HOLD` / `BLOCK`.
- **Stale / malformed / agent mismatch** → `HOLD` / `BLOCK`
  (`tests/test_near_policy.py` freshness, `MALFORMED`, `AGENT_MISMATCH` tests).
- **Transaction binding** — the authorization binds the exact unsigned bytes
  (`transaction_digest`), so a changed receiver, amount, asset, action or network
  is `WRONG_PARAMETERS`
  (`tests/test_near_signer_enforcement.py`: `test_changed_receiver_invalidates_authorization`,
  `test_changed_amount_invalidates_authorization`,
  `test_the_transaction_boundary_refuses_a_bytes_only_substitution`).
- **Provider authorization is kept separate from TEE provenance and signature
  verification** — the provider-policy decision is its own field on the prepared
  operation; it never sets a TEE or signature status.
