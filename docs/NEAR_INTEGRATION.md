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

### The signer validates before it spends

At the signing gate (`NearExecutionBoundary.accept_signature`) the signature is
decoded and verified against the transaction hash and the signer's public key
*before* the destructive checks run. The TEE gate and the single-use
authorization consume happen only after the signature verifies. This ordering is
deliberate: a malformed or wrong-transaction signature is refused without
spending the authorization, so a rejected attempt cannot be turned into a denial
of the legitimate signer's one valid submission. A binding mismatch is likewise
refused before the nonce is consumed, so a tampered transaction cannot burn the
authorization either. The property is asserted by the invariant
`near_signature_is_verified_before_state_is_consumed`, with a mutation test that
fails if the order is reversed.

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
| unrecognised | denied by `key_supports_operation` | — | CRITICAL |

The documented limitations the code states, because they are the ones people get
wrong:

* A **Function-Call key cannot transfer NEAR** and **cannot attach NEAR tokens**
  to a contract call. `key_supports_operation(..., transfers_near=True)` refuses.
* An omitted `method_names` means **every method** on the receiver contract. An
  empty list is reported as "all methods", never as "safe".
* An omitted `allowance` means **unlimited gas** until the account balance runs
  out; the code warns.
* A gas key (NEP-611) cannot set an allowance; its prepaid balance is the budget.
* An unrecognised permission is **denied** by `key_supports_operation` — the
  helper fails closed on its own, not only because its callers pre-reject it.

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
| `SETTLEMENT_VERIFIED` | Both the origin deposit and the destination delivery independently confirmed from authoritative evidence |
| `DESTINATION_DELIVERY_VERIFIED` | The destination delivery is confirmed but the origin deposit is not |
| `ORIGIN_DEPOSIT_VERIFIED` | The origin deposit is confirmed but the destination delivery is not |
| `REPORTED_ONLY` | The provider claims success; at least one decisive stage is only reported |
| `CONTRADICTORY` | Independent evidence conflicts materially |
| `UNAVAILABLE` | The sources needed could not be queried |
| `UNKNOWN` | Evidence insufficient to decide |

The verified levels are graded by *which leg* was established on-chain, so a
confirmed deposit is never presented as a completed delivery. This is asserted by
the invariant `near_destination_delivery_requires_the_destination_chain`.

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
| `TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION` | Off by default. When off, `policy_fixture` and `agent_id` in a request body are **ignored** and the operator's configuration governs. Loopback-only: a public binding refuses to start with it set. |

### The evaluated policy is not client-selectable

The policy a request is judged against is part of the enforcement decision, so
the caller must not choose it. With `TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION`
unset (the default), `POST /api/guard/near/agent-evaluate` resolves the policy
from the server only:

1. `TRACESETTLE_NEAR_POLICY_FIXTURE` — the operator's pinned fixture.
2. The configured Agent API (`TRACESETTLE_NEAR_AGENT_API_URL`).
3. Nothing, so the guard's own policy governs.

A request body may name `policy_fixture` or `agent_id` only when the flag is
explicitly on. This is asserted by the invariant
`near_policy_selection_is_not_client_controlled` and mutation-tested.

The runtime stays standard-library only. The NEAR package adds no dependency.

## 9. Known limitations

* **No live provider policy read is verified end to end.** The adapter is built
  to the documented shape and exercised against fixtures. The live endpoint
  `GET https://api.agentsonintents.com/v1/agents/{agent_id}/policy` is real and
  documented (verified: it answers `401 invalid_api_key` without a live key — see
  §10), and the adapter's host-pinning, agent-association, freshness, `401`,
  `404` and transport-failure branches are covered by tests. A *successful*
  authenticated read requires a provider account and live API key, which are not
  configured here (zero-budget). The `UNCONFIGURED` path is what runs by default.
  An opt-in test (`tests/test_near_live_provider.py`) exercises the real endpoint
  when `TRACESETTLE_TEST_AGENT_API_URL`/`_KEY` are supplied.
* **The policy scope analysis is a reading of the documentation.** It encodes the
  documented enforcement split. If the provider changes which layer enforces
  which control, this reading must be updated.
* **The attack scenarios are simulations.** They prove the boundary refuses; they
  do not prove anything about a live agent or a real account.
* **Enclave-resident signing of an arbitrary payload is not enabled.** No free,
  publicly reachable TDX enclave endpoint signs a caller-supplied NEAR
  transaction. The attested NEAR AI Cloud gateway exposes real TDX quotes and a
  *completion*-signing endpoint only. The boundary therefore stays fail-closed by
  default and never claims hardware protection without a configured, verified
  endpoint. See §10.
* **TEE quote verification is integrated; TEE *confidentiality* of execution is
  not.** The guard fetches and verifies a genuine TDX quote (and its Intel PCS
  collateral) and can enforce it at the signing boundary, but the reference
  executor still simulates execution and broadcasts nothing.

## 10. Real-world execution evidence and the hardware blocker

This section records what was actually executed, and what remains blocked by
unavailable infrastructure. Nothing here is simulated unless it says so.

### Testnet execution — executed

A real, end-to-end NEAR **testnet** execution ran through the production pipeline
(`tracesettle/near/pipeline.py`):

| Fact | Value |
| --- | --- |
| Transaction | `3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd` |
| Signer → receiver | `ts-m6-probe-13285.testnet` → `ts-m6-recv-13153.testnet` |
| Action | `Transfer` 0.01 NEAR (`10000000000000000000000` yoctoNEAR) |
| Submission state | `SETTLED` |
| Settlement state | `VERIFIED` (all seven checks ok) |
| Finality | `FINAL`, `SuccessValue` |
| Independent re-read | two public testnet RPCs (`rpc.testnet.near.org`, `rpc.testnet.fastnear.com`) |

A second, independent run of the demo boundary produced
`HYkzY2A1dcW7K2kAGDsEjaxntPpUrF7XjurzQ3P2EEb` (same amount, same shape). Both were
re-read from the chain directly; the receiver balance rose by exactly the
transferred amount. The testnet accounts were created with the free NEAR testnet
faucet (`helper.testnet.near.org`); no money was spent.

The opt-in reproduction test is `tests/test_near_live_testnet.py`, skipped unless
`TRACESETTLE_TEST_TESTNET_KEY`/`_ACCOUNT`/`_RECEIVER` are supplied. It is
testnet-only and refuses mainnet.

**Correction.** Earlier prose (README and `AGENTS.md`) cited
`Gjs4YNbEPBQKWB3M6MpV2zAwhvJySk7U6Q8NZnKVWCKH` as the execution-boundary
transfer. On-chain re-read shows that transaction is a **0.02 NEAR** transfer
signed by `ts-demo-8f3a1c.testnet` → `ts-recv-8f3a1c.testnet` — the
browser-wallet demo, not the execution boundary. The execution-boundary claim is
corrected above to the verified 0.01 NEAR transaction.

### Provider policy — endpoint verified, live read needs a key

The Agent API is real: `GET https://api.agentsonintents.com/v1/agents/{agent_id}/policy`
is in the provider's published OpenAPI (`https://api.agentsonintents.com/openapi.json`,
`securitySchemes: {ApiKey: X-API-Key}`). A live probe without a key returns
`401 {"code":"invalid_api_key"}` — the exact authentication boundary the adapter
models. A *successful* read needs a live key, which is out of the zero-budget
scope; the read is reported `UNCONFIGURED` and the guard's own policy governs.

### Hardware (TDX) — quote verified, enclave signing blocked

The live harness (`tracesettle/near/enclave_harness.py`,
`TRACESETTLE_ENCLAVE_HARNESS=1`) fetched a **genuine** Intel TDX quote from the
NEAR AI Cloud gateway and verified it locally — all 16 checks pass, including
Intel PCS collateral (TCB `UpToDate`, PCK not revoked, QE identity match) — and
rejected a wrong measurement pin and a wrong nonce. Result: `genuine: true`,
`signing_available: false`.

The blocker is precise: the gateway exposes a TDX-attested enclave with a
`signed_address` and a **completion**-signing endpoint (`GET /v1/signature/{chat_id}`),
but **no endpoint that signs an arbitrary caller-supplied payload**. A NEAR
transaction is an arbitrary payload, so no free, publicly reachable enclave can
sign one here. The integration is complete and fail-closed: supply a genuine
endpoint via `TRACESETTLE_ENCLAVE_SIGN_URL` and a pinned measurement via
`TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT` and the same boundary provisions a key
against a verified, measurement-pinned, transaction-bound attestation and signs.
Until then it refuses — it never substitutes software signing for TEE signing.

### OutLayer custody — signing reachable, per-operation attestation unavailable

`tracesettle/near/outlayer.py` and `outlayer_execution.py` add an opt-in custody
boundary (`TRACESETTLE_OUTLAYER_ENABLED=1`) that sends an authorized operation to
an OutLayer TEE-held signing wallet and then verifies settlement independently
against the NEAR RPC. The boundary is deliberately evidence-honest: it reports the
state it actually established on a strict ladder, and a provider `success` is
never promoted past `SETTLEMENT_VERIFIED`.

The limit was found by reading the provider's own published OpenAPI, not by
assuming. The OutLayer Agent Custody OpenAPI (testnet, version `0.1.0-alpha.4`,
96 paths) contains **no per-operation attestation schema** — no measurement,
collateral, MRTD, RTMR or PCR fields — and `POST /wallet/v1/transfer` returns only
`request_id`, `status`, `tx_hash` and `result`. Attestation-shaped paths exist only
in the separate compute/inbox ("Agent Connect") surface, which does not sign a
custody transfer. A per-operation TEE claim therefore cannot be cryptographically
established here, so the boundary reports
`PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE`, never `TEE_SIGNING_VERIFIED`.

`tracesettle/near/custody_attestation.py` is the evidence layer that makes the
claim honest *and* forward-compatible. If a provider ever returns an `attestation`
object, it is verified for real: the quote's signature chain is checked against the
pinned Intel SGX Root CA (reusing `tracesettle/near/tdx.py`), and its `report_data`
must commit to `sha256(wallet_public_key) || operation_commitment` — a digest over
the exact custody digest, wallet key, account and network of *this* operation. A
quote for any other key or operation, an unapproved measurement, or an unverifiable
quote resolves to `DISPUTED`, never to an accepted state. The guarantee is
structural (`custody_tee_signing_requires_bound_attestation_and_settlement`) and
mutation-tested against both a trusting evidence ladder and an accepting verifier.
No new provider endpoint is invented and no key is configured, so the routes report
themselves disabled and refuse by default.
