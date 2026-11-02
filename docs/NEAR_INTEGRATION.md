# NEAR integration

TRACESETTLE protects a transaction *before* it executes and verifies the
settlement *after* it executes. This document covers the NEAR side of both.

It has two halves:

* **Before execution** — an agent-side authorization wrapper that an AI agent or
  payment service must pass before it may sign. It reads the NEAR Intents agent
  policy, the access-key scope, and the guard's own deterministic decision.
* **After settlement** — an honest assurance view over the existing settlement
  engine, phrased for the NEAR path, so a provider's "success" is never taken as
  proof.

The settlement engine and its correlation rules are **untouched**. This
integration adds a boundary in front of a signer and a view over the engine; it
does not change how a settlement is decided.

## 1. What is simulated, and what is real

| Piece | Status |
| --- | --- |
| Guard controls (identity, destination, amount, velocity, integrity) | **Real** code, real evaluation |
| Authorization authority, parameter binding, single-use nonce | **Real** |
| Reference signer + executor | **Simulated executor**, clearly labelled |
| NEAR Intents policy parser and scope analysis | **Real**, against the documented shape |
| NEAR access-key permission analysis | **Real**, against the documented shape |
| Provider policy read | **Real when configured**; unconfigured by default (no invented endpoint) |
| Settlement engine | **Real**, unchanged |
| Attack scenarios | **Simulated**, every result labelled |

No transaction is signed, broadcast, or moved. No private key is requested or
stored. No policy is written, no account is frozen. No real unauthorized testing
was performed against any live system.

## 2. The agent-side authorization wrapper

`tracesettle.near.agent_wrapper.AgentAuthorizationWrapper` is the boundary. An
agent calls it with the **actual transaction parameters** — not a description of
them — and receives one of five outcomes:

| Outcome | Meaning for the agent |
| --- | --- |
| `ALLOW` | Proceed. An exact, transaction-bound authorization is valid. |
| `REQUIRE_APPROVAL` | An authenticated human must approve before signing. |
| `BLOCK` | Refuse to sign or submit. |
| `HOLD` | Do not execute while the required condition is unresolved. |
| `UNKNOWN` | Fail safely: the evidence needed to authorize was not obtained. |

Three independent checks feed the outcome, and the **strictest wins** (compared
by an explicit severity rank, never by the string value — `"MEDIUM"` sorts after
`"HIGH"` alphabetically):

1. the guard's deterministic decision on the transaction parameters;
2. the NEAR Intents policy scope;
3. the access-key scope.

The wrapper never reads the agent's prose. It reads `service_id`, `operation`,
`chain`, `asset`, `amount`, `destination`, `scope`, `receiver_id`, `method_name`
and `transfers_near`.

### The five outcomes in the required order

The mission lists `ALLOW`, `WARN / REQUIRE_APPROVAL`, `BLOCK`, `HOLD`,
`UNKNOWN`. `AGENT_DECISION_OUTCOMES` is exactly that set, and `REQUIRE_APPROVAL`
is the mission's "WARN".

## 3. NEAR Intents policy integration

Source: `docs.agentsonintents.com/integration/agent-api/policies-and-limits`
(plus `/concepts` and `/native-accounts`). The field names and the enforcement
split in `tracesettle/near/policy.py` follow that page.

### A policy is in force only when the provider says so

An agent has **one** policy. Each `policy_update` replaces the whole policy and
names the `expected_revision` it edits. A policy is treated as active **only**
when both of these hold:

* `status == "APPLIED"`
* `provider_policy_synced == true`

A requested or signed update is **not** in force. `IntentsPolicy.in_force`
encodes this, and the wrapper returns `REQUIRE_APPROVAL` (Intents path) or
`HOLD` (native path) when it does not hold. This is asserted by the invariant
`near_policy_must_be_in_force`.

### The two enforcement layers, and the scope gap

The policy has two enforcement layers. This is the distinction the mission asks
to make explicit:

| Control | Enforced by | Applies to |
| --- | --- | --- |
| `destinations`, `budget`, `timelock_ms`, `schedule` | Agent API | **Intents only** |
| `actions`, `assets`, `limits`, `max_actions_per_hour` | agent wallet | Intents |
| `owner_approval`, `frozen` | agent wallet | Intents |
| `native.near` / `native.evm` / `native.solana` method switches | agent wallet | native |

**A native NEAR/EVM/Solana request is not protected by the Intents money rules.**
Its destination list, USD budget, timelock, schedule and owner approval do not
apply. The only fence is the `native` method switch. A NEAR transfer can go to
any account whatever `destinations` says.

`controls_applicable_to(scope)` and `controls_not_applicable_to(scope)` return
the real sets. The wrapper reports the gap in `non_applicable_controls` and in
its `limitations`, and requires an independent TraceSettle decision. This is
asserted by the invariant `near_native_scope_gap_is_always_stated`.

### Reading a policy

`PolicyAdapter` reads `GET {base_url}/v1/agents/{agent_id}/policy` when
`TRACESETTLE_NEAR_AGENT_API_URL` is set. With no base URL it reports
`UNCONFIGURED` — no endpoint is invented. A local fixture
(`PolicyAdapter.from_fixture`) is always available for offline reproduction and
is marked `local_fixture=True`.

The adapter never writes a policy, never requests an owner signature, and never
freezes or unfreezes an account. Reading is the whole capability.

## 4. NEAR access-key security

Source: `docs.near.org/protocol/accounts-contracts/access-keys` and `.../gas-keys`.
`tracesettle/near/access_keys.py` analyses a *declared* key. It never requests,
derives or stores a private key.

| Permission | Can transfer NEAR | Can add keys | Risk |
| --- | --- | --- | --- |
| `FullAccess` | yes | yes | CRITICAL |
| `FunctionCall` with `method_names` + `allowance` | no | no | LOW |
| `FunctionCall` with `method_names`, no allowance | no | no | MEDIUM |
| `FunctionCall` with no `method_names` | no | no | HIGH |
| unrecognised | treated as unrestricted | — | CRITICAL |

The documented limitations the code states, because they are the ones people get
wrong:

* A **Function-Call key cannot transfer NEAR** and **cannot attach NEAR tokens**
  to a contract call. `key_supports_operation(..., transfers_near=True)` refuses.
* An omitted `method_names` means **every method** on the receiver contract. An
  empty list is reported as "all methods", never as "safe".
* An omitted `allowance` means **unlimited gas** until the account balance runs
  out; the code warns.
* A gas key (NEP-611) cannot set an allowance; its prepaid balance is the budget.
* An unrecognised permission is treated as **unrestricted**, never as safe.

The wrapper applies the key check only to a **native** request, because that is
what the key signs directly. On the Intents path the wallet provider signs, so
the key is not the fence. A full-access key is always reported, on either path,
because an agent holding one forces a review.

## 5. Attack demonstration

Nine deterministic scenarios in `tracesettle/near/attacks.py`, each run against
the real controls. Run them with:

```bash
python demo/near_demo.py            # all nine
python demo/near_demo.py --scenario B
python demo/near_demo.py --json     # machine-readable
python demo/near_demo.py --access-keys
python demo/near_demo.py --policy-scope
```

| id | Attack | Expected |
| --- | --- | --- |
| A | Legitimate payment | `ALLOW` + executed |
| B | Prompt-injected agent, unauthorised destination | `BLOCK` |
| C | Agent changes the destination after approval | `REFUSED (WRONG_PARAMETERS)` |
| D | Agent exceeds its spending policy | `REQUIRE_APPROVAL` / `BLOCK` |
| E | Agent uses an unauthorised service identity | `BLOCK` |
| F | Agent replays an authorization | `REFUSED (REPLAYED)` |
| G | Operation outside the permitted key scope | `BLOCK` / refused |
| H | Native tx wrongly assumed protected by an Intents-only policy | policy-scope rejection |
| I | Provider reports success without independent evidence | `UNKNOWN` / `UNAVAILABLE` |

Every scenario asserts that the executor was **never called** unless the outcome
was `ALLOW` (scenarios A and F), so "refused" is provable rather than asserted.

Scenario C is the subtle one: both destinations are on the guard's approved
list, so the wrapper's own destination control passes and the **signer's
parameter binding** is what refuses. A genuine token minted for one destination
is refused for another.

## 6. Settlement assurance after execution

`tracesettle/near/settlement.py` wraps the existing engine's result. It does not
re-decide anything. It maps the engine's stages onto the NEAR settlement stages
(deposit address, source-chain transaction, deposit confirmation, intent
execution, destination transaction, destination receipt, refund) and reports an
assurance level:

| Level | Meaning |
| --- | --- |
| `VERIFIED` | Decisive stages independently confirmed from authoritative evidence |
| `REPORTED_ONLY` | The provider claims success; at least one decisive stage is only reported |
| `CONTRADICTORY` | Independent evidence conflicts materially |
| `UNAVAILABLE` | The sources needed could not be queried |
| `UNKNOWN` | Evidence insufficient to decide |

**A provider success status never raises the level.** It is recorded as
`provider_claimed_success` and phrased in the summary, but the level is computed
from the engine's evidence. This is asserted by the invariant
`near_provider_success_is_never_verified_without_evidence`.

`GET /api/guard/near/settlement-demo` runs a synthetic case where the provider
reports success with no decisive evidence and reports the honest level.

## 7. HTTP surface

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/guard/near/scenarios` | run the nine attack scenarios |
| GET | `/api/guard/near/access-keys` | access-key permission analysis |
| GET | `/api/guard/near/policy-scope` | which controls protect which path |
| GET | `/api/guard/near/settlement-demo` | a provider claim that is not verified |
| POST | `/api/guard/near/agent-evaluate` | evaluate one agent transaction |

`agent-evaluate` is scoped to the authenticated service identity, like the other
service-facing routes. It never returns the authorization unless
`return_authorization` is true, and it never signs.

## 8. Environment

| Variable | Purpose |
| --- | --- |
| `TRACESETTLE_NEAR_AGENT_API_URL` | Agent API base URL. Unset = no live policy reads. |
| `TRACESETTLE_NEAR_AGENT_API_KEY` | Agent API key. Never logged or returned. |
| `TRACESETTLE_NEAR_POLICY_FIXTURE` | Path to a local policy fixture. |
| `TRACESETTLE_NEAR_AGENT_ID` | Default agent id to read a policy for. |

The runtime stays standard-library only. The NEAR package adds no dependency.

## 9. Known limitations

* **No live provider policy read is verified end to end.** The adapter is built
  to the documented shape and exercised against fixtures; a live read requires an
  Agent API base URL and key, which are not configured here (zero-budget, no
  account). The `UNCONFIGURED` path is what runs by default.
* **The policy scope analysis is a reading of the documentation.** It encodes the
  documented enforcement split. If the provider changes which layer enforces
  which control, this reading must be updated.
* **The attack scenarios are simulations.** They prove the boundary refuses; they
  do not prove anything about a live agent or a real account.
* **No testnet or mainnet transaction was executed.** Nothing here was verified
  against a chain.
* **TEE is researched, not integrated.** See `docs/TEE_RESEARCH.md`.
