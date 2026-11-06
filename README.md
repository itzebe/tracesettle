# TRACESETTLE

**Blockchain Transaction Security & Settlement Assurance.**

> Prevent unauthorized transactions. Detect suspicious activity. Verify every settlement.

TRACESETTLE has two halves that share one idea: do not trust a claim you have not
checked.

1. **Transaction security (new).** A pre-execution **Transaction Guard** evaluates a
   transaction request against a policy, a **Risk Engine** explains what is wrong,
   and an **Authorization Firewall** issues a short-lived, transaction-bound
   authorization that a **reference signer** independently validates before it will
   execute anything. If the authorization is missing, expired, replayed, or bound to
   different parameters, the signer refuses and nothing is executed.

2. **Settlement verification (existing).** A read-only cross-chain settlement
   investigator for NEAR Intents. It takes one identifier, gathers what public
   sources actually say about a 1Click swap, separates what is **independently
   verified** from what is **merely reported**, flags contradictions and gaps, and
   prints an evidence-backed report.

3. **NEAR agent protection (new).** An agent-side authorization wrapper an AI agent
   or payment service must pass before it may sign. It inspects the real transaction
   parameters, the NEAR Intents agent policy, and the NEAR access-key scope, and
   returns `ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`, `HOLD` or `UNKNOWN`. A provider's
   settlement claim is still verified after the fact, never trusted. See
   [`docs/NEAR_INTEGRATION.md`](docs/NEAR_INTEGRATION.md).

TRACESETTLE never signs a real transaction, never submits one, never holds funds,
and never asks for a private key or seed phrase. The reference signer simulates
execution; it is the *enforcement boundary*, not a wallet.

**Hackathon track: `security` (AI Security & Defense)** — the track that names
policy engines and spending limits for agents, i.e. "give AI money without giving
it the keys to everything". See [Submission](#hackathon-submission).

## The problem

Two failures, one root cause.

**Unauthorized transactions.** Protecting a private key is not enough. An attacker
who can make an otherwise legitimate system *authorize* an illegitimate transfer
causes the damage without ever touching the key. The defenses that matter are the
ones at the authorization boundary: who is asking, for how much, to where, how
often, and whether the approval that arrived is actually bound to this transaction.

**Unverified settlement.** When a cross-chain swap goes wrong, the evidence is
scattered: a 1Click status record, an origin-chain receipt, a NEAR transaction, a
destination-chain receipt. Each source speaks a different vocabulary (`SUCCESS`,
`SETTLED`, `FINAL`, `0x1`). The common failure mode is treating an upstream
service's word as ground truth. A status of `FAILED` is not proof funds were lost.
A `refundedAmount` of `0` is not proof no refund can occur. A transaction hash is
not proof the event it describes happened.

## What it does

### Transaction security

For every transaction request, seven deterministic controls run — all of them,
never short-circuiting — and produce one explained decision.

| Decision | Meaning | Authorization issued |
| --- | --- | --- |
| `ALLOW` | every control passed | yes |
| `REQUIRE_APPROVAL` | a human decision is needed | no |
| `HOLD` | rate or volume anomaly; retry later | no |
| `BLOCK` | a blocking finding | no |

Controls: service identity and its allowed operations/chains/assets; destination
denylist and allowlist; per-transaction amount limits and an approval threshold;
request rate, blocked-request rate and rolling per-asset volume; repeated rejected
authorization attempts; caller-supplied approval flags; and request integrity.

Every decision carries a decision id, timestamp, request reference, the policy and
version, every control result with the policy that produced it, the findings, a
human-readable explanation, and an audit record.

An `ALLOW` decision mints an **authorization**: an HMAC-SHA256-signed statement
bound to the exact `service_id`, `operation`, `chain`, `asset`, `amount`,
`destination` and — where the caller holds the transaction bytes — a digest of
those exact bytes (`transaction_digest`), with an expiry (90s default) and a
single-use nonce. The signer re-derives the binding from the transaction it was
asked to sign. A genuine, unexpired, unused authorization minted for a *different*
transaction is refused as `WRONG_PARAMETERS` — which is the whole point of binding
it to the transaction rather than merely authenticating the caller. Because the
NEAR path includes the byte digest, a transaction whose *bytes* differ from the
evaluated parameters (a swapped action, a substituted token contract, forged call
arguments) is refused even when every human-readable field is unchanged.

Amounts are exact `Decimal`s: a limit of `0.3` admits `0.3` and refuses
`0.30000000000000004`. Severity is compared by an explicit rank, never by the
severity's string value (`"MEDIUM"` sorts after `"HIGH"` alphabetically).

Forty-five structural guarantees are checked by *running the real code*, on demand, at
`GET /api/guard/invariants` — including `refusal_never_reaches_the_executor` and
`authorization_is_single_use`. Each checker is also mutation-tested: the guarded
behaviour is deliberately broken and the checker must notice. A checker that
cannot fail proves nothing.

### Settlement verification

For each transaction stage TRACESETTLE records evidence, then classifies it:

| Classification | Meaning |
| --- | --- |
| `CONFIRMED` | Independently verified from an authoritative source (chain RPC, event logs). |
| `REPORTED` | A service says so, but it was not independently checked. |
| `MISSING` | Not found. Explicitly **not** proof the stage failed. |
| `UNAVAILABLE` | The source needed to check could not be reached. |
| `INCOMPLETE` | The source answered, but a required search could not be completed. Insufficient evidence, not proof of absence. |
| `CONTRADICTORY` | Two pieces of evidence materially disagree. |
| `SIMULATED` | Clearly-labelled test evidence, never a live finding. |

Each evidence item also carries a `verification_method` field stating how its
classification was reached (for example a locally recomputed transaction id, a
script-level recipient match, or a plain upstream report).

**How strong is a claim?** Separate from the per-stage classification above, every
capability in this repository is stated with an evidence level. No claim is made at
a level it was not established at.

| Evidence level | Meaning |
| --- | --- |
| Locally verified | Actually executed on this machine against the real code paths; reproducible with the commands in [Tests](#tests). |
| Simulated | A controlled demonstration with synthetic parameters. The reference executor simulates execution and broadcasts nothing. |
| Testnet verified | Actually exercised against a public test network. |
| Mainnet verified | Independently confirmed against a public main network (a public RPC, event log, or explorer). |

Where each capability stands:

- **Transaction security, NEAR policy scope, access-key analysis, the nine attack
  scenarios:** Locally verified (real code, real assertions) and, for the attack
  scenarios themselves, Simulated — they are controlled simulations of attacks, not
  live attacks.
- **Settlement verification:** Mainnet verified — the reference swap, the refund
  case, and the origin/bridge/settlement/destination stages are confirmed against
  public mainnet RPCs and event logs, with raw captures under `evidence/raw/`.
- **NEAR Intents provider reads (tokens, quote, status):** Mainnet verified
  read-only against the public provider endpoints. Live provider-*policy*
  integration is **not** claimed: it is unverified unless an operator configures
  `TRACESETTLE_NEAR_AGENT_API_URL` and the read succeeds.
- **TEE:** no TEE *confidentiality* protection is claimed for execution, and the
  default path does not require one (see
  [`docs/TEE_RESEARCH.md`](docs/TEE_RESEARCH.md)). Two honest capabilities are
  provided, both **Locally verified**:
  1. `GET /api/guard/near/tee/attest` fetches the NEAR AI Cloud gateway's **real**
     Intel TDX quote and verifies it locally against the pinned Intel SGX Root CA
     — the quote signature, the PCK certificate chain, the attestation key bound
     to the Quoting Enclave report, the nonce and signing-address binding, and the
     event log replayed to the RTMRs. It additionally fetches and verifies
     **Intel PCS collateral** (`tracesettle/near/collateral.py`): the signed TCB
     Info for the platform's FMSPC (with TCB-level matching and freshness), the
     signed PCK CRL (revocation), and the signed QE Identity (MRSIGNER/ISVPRODID
     and ISVSVN), each checked against the pinned Intel root. This is verification
     of a genuine hardware quote *and* its current Intel-published trust state.
     Live-verified: TCB `UpToDate`, PCK not revoked, QE identity match.
  2. The verified quote can be **enforced** at the signing boundary. With
     `TRACESETTLE_NEAR_TEE_REQUIRED=1` the boundary refuses to accept a signature
     unless a verified attestation is bound to the exact transaction: the digest
     commits to the exact bytes to be signed, the lifecycle reaches signing only
     from `TEE_VERIFIED`, and a substituted transaction is refused. This gates the
     *signing boundary*; the reference executor still simulates execution and
     broadcasts nothing, so it is not a claim that a real transaction was
     broadcast under attestation. Off by default; enabling it without the
     attestation provider and the execution boundary is a fail-closed start-up
     error on any binding.
  The attestation *reporting* routes are separately off by default
  (`TRACESETTLE_TEE_ATTESTATION=1`).
  3. A prepared NEAR transaction can be signed **inside a measured enclave**
     (`tracesettle/near/enclave.py`, **Locally verified**). `EnclaveSigningBoundary`
     provisions a signing key only against a verified Intel TDX attestation whose
     measurement is an operator-approved identity (`mr_config_id` and any further
     pinned fields must match exactly) and whose nonce is bound to the exact
     transaction, then verifies the returned signature over those exact bytes with
     the provisioned key. With no signing endpoint configured
     (`TRACESETTLE_ENCLAVE_SIGN_URL`) the boundary reports itself unavailable and
     refuses — it never falls back to a software key. The boundary is
     **testnet-only**: it refuses to sign for mainnet. The only substitution in the
     tests and the demo is the enclave transport (a deterministic stand-in with a
     real ed25519 keypair); the genuineness of real quote verification is covered
     separately by the live hardware harness (`tracesettle/near/enclave_harness.py`)
     and the `tee_attestation_verification_is_genuine` invariant. Enabling enclave
     signing without a sign endpoint, or TEE-required without an attestation
     provider, is a fail-closed start-up error on any binding. **No free, publicly
     reachable TDX enclave that signs an arbitrary caller-supplied payload is
     available**, so enclave signing stays fail-closed by default: the attested
     NEAR AI Cloud gateway exposes real TDX quotes and a completion-signing
     endpoint, but no endpoint that signs an arbitrary NEAR transaction. The
     blocker and the integration path are documented in
     [`docs/NEAR_INTEGRATION.md`](docs/NEAR_INTEGRATION.md) §10.
- **Live NEAR execution boundary:** Testnet verified — the opt-in boundary
  (`TRACESETTLE_NEAR_EXECUTION=1`) built, signed, broadcast and independently
  verified a real NEAR testnet transfer of 0.01 NEAR (tx
  `3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd`, signer
  `ts-m6-probe-13285.testnet` → `ts-m6-recv-13153.testnet`, `FINAL`,
  `SuccessValue`). The default **simulated executor** never signs or broadcasts
  anything — that is by design, and no Testnet or Mainnet evidence is claimed
  for it.
- **Wallet-mediated flow:** Testnet verified — the authorize → prepare → verify
  path was exercised against real NEAR testnet: a funded `*.testnet` account
  signed the exact wallet request the server returned, the harness broadcast it,
  and `/verify` read the chain back to `VERIFIED`. Replay of a consumed
  `prepare_id` is refused (`404`); a tampered submission resolves to `DISPUTED`.
  The server held no key at any point — the testnet account's own key signed
  *outside* the server.
- **Browser-wallet journey:** Testnet verified — the console's real wallet panel
  was driven in a real Chromium browser by a wallet that holds the key and signs
  (`demo/browser_wallet/`). Four scenarios were exercised end to end against real
  testnet transactions: an approved transfer reaches `VERIFIED`; a non-approved
  recipient is `BLOCK`ed before the wallet is ever asked to sign; a wallet that
  signs a *different* amount than was authorized is `DISPUTED` (the transfer
  succeeds on-chain, but the record contradicts the intent); and a rejected
  signature broadcasts nothing. The page never sees a private key — the wallet
  emulator speaks the bundled connector's injected-wallet protocol and returns
  only a signed-and-broadcast hash, exactly as a real extension does. The
  emulator's transaction layout is pinned byte-for-byte to the repository's own
  serializer (`tests/test_browser_wallet_borsh.py`). See
  [`demo/browser_wallet/README.md`](demo/browser_wallet/README.md).

Stages: `SOURCE_CHAIN_DEPOSIT`, `BRIDGE_DEPOSIT_CREDIT`, `NEAR_SETTLEMENT`,
`DESTINATION_CHAIN_DELIVERY`, and `REFUND`.

A stage is confirmed **only** by its decisive evidence, never by a neighbouring
signal:

- source deposit: the origin-chain transaction executed **and did not revert** —
  a transaction confirmed to have reverted is `CONTRADICTORY`, never `CONFIRMED`,
  because inclusion in a block proves only that it was mined, not that it
  succeeded (safety invariant `reverted_execution_never_confirms`);
- bridge deposit credit: an on-chain bridge transfer to `intents.near` carries a
  `BRIDGED_FROM` memo naming **this** deposit's origin transaction hash (for a
  Bitcoin origin, a bridge `utxo_added` event names the origin Bitcoin txid);
- settlement: the investigated intent hash appears in on-chain intent-execution
  event logs (a NEAR transaction merely being included or final is not enough);
- destination delivery: the expected asset transfer to the expected recipient
  appears in the destination receipt logs;
- refund: a **confirmed** on-chain transaction pays the address recorded on-chain
  for this intent's withdrawal. A reported refund alone never confirms it.

Correlation uses explicit identifiers only (intent hash, deposit address,
recipient address, transaction hash). Amount and timestamp similarity are never
used to link stages.

### Settlement assurance in the report

Every investigation report carries a `settlement_assurance` view over the same
deterministic result, so the question "did the money arrive, and is that
independently proven?" has a first-class answer rather than being left to the
reader to infer from stage states. It maps the engine's stages onto the NEAR
settlement path (deposit address, source-chain transaction, deposit confirmation,
intent execution, destination transaction, destination receipt, refund) and
reports one of `SETTLEMENT_VERIFIED`, `DESTINATION_DELIVERY_VERIFIED`,
`ORIGIN_DEPOSIT_VERIFIED`, `REFUNDED`, `FAILED`, `PARTIAL`, `PENDING`,
`REPORTED_ONLY`, `CONTRADICTORY`, `UNAVAILABLE`, or `UNKNOWN`.

**A provider's success status is a `REPORTED` claim and never raises the level.**
If the provider says `SUCCESS` but no decisive on-chain evidence confirms it, the
assurance level is not verified — the report says so explicitly, and the
Markdown document, the main page and the operations console all render the view.
The verified levels are graded by *which leg* was established on-chain, so the
two are never conflated: `SETTLEMENT_VERIFIED` means the origin deposit **and**
the destination delivery were each independently confirmed; when only the
destination leg is confirmed (the origin source was unavailable) the level is
`DESTINATION_DELIVERY_VERIFIED`; when only the origin deposit is confirmed and
the destination is not, the level is `ORIGIN_DEPOSIT_VERIFIED` — a confirmed
deposit says nothing about whether the money arrived. The three terminal states
are distinguished by their evidence: a refund confirmed
on-chain is `REFUNDED` (never presented as a successful settlement), a failure
established by decisive evidence is `FAILED` (a merely *reported* failure stays
unverified), and a confirmed deposit whose swap is still progressing is `PENDING`
(not `UNKNOWN`). When the destination delivery *is* independently confirmed but the
received amount is below the quote's expected output, the level is `PARTIAL` (never
a verified level), and both the expected and observed amounts plus the shortfall are
disclosed. A shortfall against an *unconfirmed* delivery is not classified as
partial; the difference is disclosed as a limitation instead. Amounts never create
a confirmation.
The same capability is exercised end to end in `tests/test_near_acceptance.py`,
which drives the real server and the real report builder, so it cannot regress
into an unused library.

### The learning loop (durable safeguards)

The mission lifecycle is *identify → authorize → protect → execute → verify →
investigate → **learn***. The learning loop is that last step, and it is what makes
the guard adapt rather than repeat a mistake.

When a decision surfaces a security failure — a client trying to assert its own
approval, a transfer to an unapproved or denied destination, a rolling-window
volume breach — the lesson is recorded as a **durable safeguard** and applied to
later decisions. A safeguard is a restriction, scoped to a service identity and
(optionally) an asset:

- `require_approval_above` — above the amount that tripped the lesson, a human must
  approve;
- `require_verification` — the operation needs independent verification before it
  may sign.

**Learning can only ever tighten.** A safeguard is applied *on top of* the
operator's configured policy and the strictest of the two wins; nothing in the loop
can grant a permission, relax a limit, or edit the policy. A lesson is drawn only
from a recognised risk finding, never invented from an arbitrary code. A decision
that already did the right thing (an `ALLOW`) teaches nothing. The safeguards are
durable: they survive a restart, and the console and
`GET /api/guard/safeguards` report them honestly. With no safeguard store
configured (`TRACESETTLE_GUARD_SAFEGUARD_DB` unset) the loop is inert and the guard
behaves exactly as before.

```sh
python3 demo/near_demo.py --learning-loop
```
→ a failure is refused and teaches a lesson, a later larger request that the policy
alone would allow is tightened to `REQUIRE_APPROVAL`, and a request below the
learned floor is unaffected. Two structural invariants
(`learning_loop_only_tightens`, `learning_never_relaxes_policy`) hold this property
and are mutation-tested.

### Independent origin-chain deposit verification

The deposit hash the operator's wallet reports is a **claim** until it is checked
against the chain. `POST /api/guard/near/lifecycle/{intent_id}/verify-origin` (and
the console's **Verify deposit on origin chain** button) reads the origin chain
directly and compares explicit identifiers — the recipient, the token contract and
the amount — never a provider's word and never amount/timestamp similarity. The
verdict is one of `VERIFIED`, `UNCONFIRMED`, `CONTRADICTORY`, `NOT_FOUND`,
`UNAVAILABLE` or `UNSUPPORTED`:

- `VERIFIED` — the transaction is included, **succeeded**, and pays the deposit
  address the expected token and amount.
- `CONTRADICTORY` — the transaction is confirmed to have **reverted**, or it pays a
  different recipient, so it cannot be the claimed deposit.
- `UNCONFIRMED` — the transaction was found but a required check did not hold (an
  unmined transaction, or a value that differs from the quote). This is
  insufficient evidence, not proof of failure.
- `NOT_FOUND` / `UNAVAILABLE` / `UNSUPPORTED` — a missing record, a source outage,
  or no configured source for the chain. None is a verdict that the deposit failed.

The check is read-only and never blocks the provider-status read that calls it; a
verdict is recorded on the intent and carried forward on later reads without a
second network call. `tests/test_near_origin_verify.py` (19 tests) covers each
verdict, and `tests/test_near_lifecycle.py` covers the wiring and persistence.

### Independent destination-chain delivery verification

A confirmed origin deposit proves only that the money **left** the source; it says
nothing about whether the intended asset reached the intended recipient on the
destination chain. `POST /api/guard/near/lifecycle/{intent_id}/verify-destination`
(and the console's **Verify delivery on destination chain** button) closes that gap
the same way the origin check works: it reads the destination chain directly and
matches explicit identifiers — the recipient address and the ERC-20 token
contract — never a provider's word and never amount/timestamp similarity. The
verdict is one of `VERIFIED`, `UNCONFIRMED`, `CONTRADICTORY`, `NOT_FOUND`,
`UNAVAILABLE` or `UNSUPPORTED`:

- `VERIFIED` — the destination transaction is included, **succeeded**, and carries
  a `Transfer` of the expected token to the intended recipient for the expected
  amount. For a native asset the top-level recipient is matched and the amount is
  disclosed as not checked (a receipt does not carry the transferred value).
- `CONTRADICTORY` — the transaction is confirmed to have **reverted**, or pays a
  different recipient, or transfers a different token, so it cannot be the claimed
  delivery.
- `UNCONFIRMED` — the transaction was found but a required check did not hold (too
  few confirmations, a differing amount, or an unknown intended recipient). This is
  insufficient evidence, not proof of failure.
- `NOT_FOUND` / `UNAVAILABLE` / `UNSUPPORTED` — a missing record, a source outage,
  or no configured source for the chain. None is a verdict that the transfer failed.

Amount is never used to *find* or *correlate* a transaction; it is only ever
compared once the transaction is already identified by its hash. The check is
read-only and carried forward on later reads without a second network call.
`tests/test_near_destination_verify.py` (16 tests) covers each verdict, and
`tests/test_near_lifecycle.py` covers the wiring and persistence. The structural
guarantee is asserted by the `near_destination_delivery_requires_the_destination_chain`
invariant.

### NEAR Intents lifecycle

The shipped application wires the NEAR capabilities into a real, end-to-end
lifecycle rather than leaving them as library code. When enabled by the operator
(`TRACESETTLE_NEAR_LIFECYCLE=1`; off by default, because a live quote yields a
fundable deposit address), the server exposes a create → authorize → quote →
settle → assurance flow:

1. **Create + authorize.** `POST /api/guard/near/lifecycle` takes a proposed
   transaction, runs the guard and the NEAR policy/access-key controls on the
   **actual** parameters, and only proceeds to a quote when the outcome is
   `ALLOW`. The operator's policy is resolved server-side; a client cannot choose
   the policy it is judged against. A top-level `idempotency_key` makes a retried
   or double-submitted create resolve to one intent.
2. **Quote.** On `ALLOW` the lifecycle requests a live 1Click quote
   (`POST /v0/quote`, `dry: false`) to obtain a deposit address, and records the
   intent with its deposit address, expected output amount, and the quote's
   expiry. `quote_expiry()` enforces a **stated** deadline (`deadline` or
   `timeWhenInactive`); when the provider states none it does not invent one — it
   marks the quote usable but flags `expiry_known: false` and says so.
3. **Approve.** `POST /api/guard/near/lifecycle/{intent_id}/approve` records the
   user's explicit decision on the live quote. Approval requires a still-usable
   quote and a stored decision that permits signing, and it does not move funds —
   it marks that the user accepts *this exact* quote. A fresh quote clears any
   prior approval, so approval is always bound to the quote the user reviewed.
4. **Deposit handoff.** The console shows the deposit address, any memo, the
   quoted fees, and the quote expiry, so the operator can fund the address from
   their **own** wallet. `POST /api/guard/near/lifecycle/{intent_id}/deposit`
   records the deposit transaction hash the operator supplies and asks the
   provider to pre-verify it. A deposit is refused until the quote is approved and
   while the quote is unexpired. This step moves nothing: the tool never signs,
   sends, or holds funds.
5. **Get / list.** `POST /api/guard/near/lifecycle/{intent_id}/get`,
   `/lifecycle/list`, and `/lifecycle/tokens` read the durable intent record
   (SQLite via `TRACESETTLE_INTENTS_DB`) and the provider asset list. Intent
   records are owner-scoped: a request can only read an intent it owns.
6. **Settle + assurance.** When the swap settles, the same evidence pipeline that
   powers investigations produces the settlement-assurance view (above), so a
   provider `SUCCESS` is never confused with verified receipt.
7. **Resume.** The console lists the owner's durable intents with a per-intent
   **Resume** control, so a record survives a page reload and an in-flight
   transaction can be continued (approve, deposit, status, assurance) without
   creating a new intent. Resuming re-selects the stored record through the same
   `/get` action; it creates nothing.

The lifecycle never signs, submits, or moves funds: it obtains a deposit address,
hands it to the operator, and observes the outcome. `tests/test_near_lifecycle.py`
(33 tests) drives the real lifecycle object and the real durable store, and
`tests/test_near_acceptance.py` drives the **whole journey over a real HTTP
socket** — create → authorize → live quote → approve → status → assurance — so a
route wired to the wrong path, gated by the wrong flag, or answered without a body
fails there rather than in the product. The console walks the same six steps in
the **Intents Lifecycle** tab, gating the deposit form behind the approve/reject
controls, and lists the durable intents with a **Resume** control so a reload does
not abandon an in-flight transaction.

### Live NEAR execution boundary (opt-in, off by default)

Beyond the simulated executor, TRACESETTLE ships a **real** NEAR execution
boundary (`tracesettle/near/execution.py`) that builds a genuine transaction,
binds the guard's authorization to the exact bytes, accepts a signature produced
elsewhere, broadcasts it, and then *independently* verifies the result by reading
the chain back. It is deliberately narrow and gated:

- **Off by default.** The routes are only mounted when
  `TRACESETTLE_NEAR_EXECUTION=1`; a prepared operation is server-side, bounded,
  TTL'd and owner-scoped, and no route signs with a stored key.
- **The guard authorizes; it never holds a key.** `POST .../near/execution/prepare`
  runs the seven controls against the *actual* parameters and, on `ALLOW`, returns
  a transaction plus an authorization. The caller signs with their **own** wallet
  and submits the signature; the boundary re-derives the binding from the bytes it
  would broadcast, so changing the amount after authorization is refused
  (`WRONG_PARAMETERS`).
- **Independent verification, not a provider's word.** After broadcast the
  boundary reads the transaction back and confirms the outcome, the signer, the
  receiver and the transferred amount before it reports `VERIFIED`. A provider
  `SUCCESS` alone never yields `VERIFIED`.
- **The signer's access-key permission is enforced.** Before building anything,
  the boundary reads the signer account's on-chain access key and refuses unless
  the key's permission covers the transaction: a function-call key can never move
  native NEAR, a receiver/method outside the key's scope is refused, an omitted
  `method_names` means *all methods*, an omitted allowance means *unlimited gas*,
  and an unrecognised permission shape is never treated as safe.
- **Standard library only.** Serialization (Borsh), ed25519, the RPC client and
  the verifier are all stdlib — no runtime dependency is added.

**The real testnet executor (`tracesettle/near/pipeline.py` + `ledger.py`).**
`NearExecutionPipeline` is the production path that replaces the simulated
executor for a NEAR operation. It composes the pieces above rather than
duplicating them, and adds two properties the raw boundary does not have:

- **Durability.** Every signed submission is recorded in a SQLite ledger
  (`TRACESETTLE_NEAR_LEDGER_DB`) *before* it is sent and updated after. A send
  that times out — the outcome is genuinely unknown — is recorded `UNKNOWN`
  (never `FAILED`) and resolved by asking the chain what happened; it is never
  blindly resubmitted. Because a NEAR transaction hash covers its nonce, the
  *identical* signed bytes can be applied at most once, so a re-send of the same
  bytes is idempotent while different bytes are never sent.
- **Finality.** A broadcast commonly returns an *optimistic* (non-final) status.
  The pipeline polls the chain, bounded, until the execution is `FINAL` before it
  verifies — it never inflates a pending state to `VERIFIED`.

Two further structural invariants guard it:
`near_execution_requires_access_key_permission` and
`near_submission_is_durable_and_recovery_never_resubmits`.

**Locally verified + Testnet verified:** the full pipeline was exercised live on
NEAR testnet — a funded `*.testnet` account (`ts-m6-probe-13285.testnet`) built,
TEE-attestation-gated, signed, broadcast and independently verified a real 0.01
NEAR transfer (tx `3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd`) to
`ts-m6-recv-13153.testnet`, reaching submission state `SETTLED` and settlement
state `VERIFIED` with all seven verification checks ok. The live run moved real
testnet value (the receiver's balance rose by exactly the transferred amount).
The transaction hash, signer, receiver, amount and `FINAL` status were
re-read from two independent public testnet RPCs
(`rpc.testnet.near.org`, `rpc.testnet.fastnear.com`). The tests substitute only
the RPC transport (a network boundary), so every line of `execution.py` and
`pipeline.py` runs.

### End-to-end agent lifecycle (interception → block/authorize → settle → verify)

`demo/near_agent_demo.py` runs the whole story through the **production**
boundary in one command. A deterministic **local agent harness**
(`tracesettle/near/agent_harness.py`) turns a payment instruction into a
concrete transaction *proposal* - no model, no network - and drives it through
the real `NearExecutionBoundary`, the real signer, the real broadcast, and the
real independent settlement verification:

```
agent instruction -> proposal -> TraceSettle evaluation -> decision ->
signer enforcement -> NEAR broadcast -> independent verification
```

Two scenarios run side by side:

| Scenario | What the agent does | What TraceSettle does |
| --- | --- | --- |
| **malicious** | injected context redirects a legitimate invoice to an attacker receiver; the (compromised) planner proposes the attacker | the real guard `BLOCK`s it (`UNAPPROVED_DESTINATION`), the **signer is never invoked** (count `0`), nothing is broadcast |
| **legitimate** | the operator-approved receiver is paid | the real guard `ALLOW`s it, the signer signs exactly the authorized bytes, the transaction is broadcast, and settlement is independently `VERIFIED` |

The guard reads the proposal's **parameters**, never the agent's text: a
convincing instruction cannot change the decision. "The signer was never
reached" is proved as "the counting signer was called zero times" and "the
transport recorded zero broadcasts", never as prose.

Each scenario's output carries the **authorization binding** — the canonical
parameter set the authorization covers (`destination`, `amount`, `asset`,
`chain`, `operation`, `service_id`) and the `transaction_digest` it is bound to —
together with `signed_bytes_digest`, recomputed from the final transaction. The
two are equal only because the authorization covers the *exact bytes* that are
signed. The digest is `sha256(unsigned_bytes)`, which is the preimage NEAR hashes
to the transaction hash, so base58-encoding it yields the on-chain `tx_hash`: the
authorization is cryptographically tied to the transaction the chain records, not
to a summary of it.

```sh
python3 demo/near_agent_demo.py            # offline, deterministic, no key
python3 demo/near_agent_demo.py --json
```
→ the malicious payment is `BLOCK`ed before signing and the legitimate payment
reaches `SETTLED` / `VERIFIED`. The offline transport is the only substitution
(a network boundary); the boundary, guard, signer, pipeline and verifier are the
real code. Labelled **SIMULATED**.

**Live testnet run (`--live`).** With a funded `*.testnet` key the same harness
signs and broadcasts a **real** testnet transaction and reads the on-chain
record back to verify it. It refuses to point at mainnet and never writes the
key anywhere.

```sh
TRACESETTLE_DEMO_TESTNET_KEY=<64-hex-seed> \
TRACESETTLE_DEMO_ACCOUNT=<you.testnet> \
TRACESETTLE_DEMO_RECEIVER=<recipient.testnet> \
python3 demo/near_agent_demo.py --live
```
→ **Testnet verified:** the malicious scenario still `BLOCK`s (signer calls
`0`); the legitimate scenario settles and verifies against the live chain. Real
runs moved 0.1 NEAR from `tsdemo916196f7.testnet` to `tsrecv2f0f12b8.testnet`
(tx `HRKsn8s1L6h97aGHBWdkBmg7S8USzMN5aQePgxMc5o3n`, and a later run
`9CuS2F6PMLXfkbbsWLAv6Fii3VQukWJiQhb4pMsh11mN`), each `FINAL` with status
`SuccessValue`, re-read from two independent public testnet RPCs
(`rpc.testnet.near.org`, `rpc.testnet.fastnear.com`). The live run is not
reproduced in CI (it needs a funded key); the offline run is, and is
byte-identical across runs.

### TEE-bound signing (optional, off by default)

The same boundary can additionally require a verified Intel TDX attestation
before it will accept a signature. With `TRACESETTLE_NEAR_TEE_REQUIRED=1`:

1. `prepare` creates an `ExecutionRecord` carrying the transaction digest, the
   authorization nonce, the service identity and the policy version.
2. `POST /api/guard/near/execution/attest` fetches the gateway's real TDX quote,
   verifies it locally, and binds it to that record — the binding commits to the
   **exact bytes to be signed** (`unsigned_bytes()`), so it covers the amount.
3. The lifecycle state machine (`RECEIVED → … → TEE_VERIFIED → SIGNING_PENDING →
   SIGNED`) reaches signing **only** from `TEE_VERIFIED`; `accept_signature`
   refuses unless a verified attestation is bound to the same digest.

A transaction whose signed bytes are substituted after attestation is refused
(`does not match the authorized execution`). Enabling the gate without the
attestation provider and the execution boundary is a fail-closed start-up error
on any binding. This gates the *signing boundary*; the default executor still
simulates execution and broadcasts nothing.

### Wallet-mediated flow (the wallet signs and sends)

The server-side boundary above is for an operator who wants TRACESETTLE to build
and broadcast. The **wallet-mediated flow** is the other half of the mission: the
user connects their own NEAR wallet, TRACESETTLE authorizes the *intent*, and the
wallet — not the server — signs and sends. The server holds no key at any point.

- **Routes** (mounted only when `TRACESETTLE_NEAR_EXECUTION=1`):
  `GET /api/guard/near/wallet` describes the flow;
  `POST /api/guard/near/wallet/prepare` runs the seven controls against the
  actual parameters and, on `ALLOW`, returns the exact wallet request the user
  must approve plus a transaction-bound authorization;
  `POST /api/guard/near/wallet/verify` reconciles the submitted transaction hash
  against the intent.
- **The authorization is bound to the intent, not to bytes.** Because the wallet
  chooses its own nonce and block hash, `prepare` binds the authorization to the
  canonical parameter set (signer, receiver, operation, amount, recipient).
  `verify` re-derives that binding, consumes the single-use nonce, and reads the
  chain back with `verify_intent` — checking the signer, receiver, operation,
  amount and recipient against the on-chain record.
- **A provider or wallet `SUCCESS` never verifies on its own.** Verification is
  the same deterministic discipline as everywhere else: a contradiction is
  `DISPUTED`, an unfinalized transaction is `PENDING`, and only a fully matched,
  final, successful record reaches `VERIFIED`. An operation the verifier does not
  recognise is `DISPUTED`, never `VERIFIED`; a degraded RPC source (timeout,
  rate limit, server error, unauthorized) is `INSUFFICIENT_EVIDENCE`, never
  `VERIFIED`.
- **The verification is recorded as durable evidence.** Each `verify` outcome is
  appended to the hash-chained audit log (`SETTLEMENT_VERIFICATION`, with the
  on-chain tx hash, destination, amount and every check), so the independent
  finding survives the request and a restart. A configured `TRACESETTLE_GUARD_AUDIT_LOG`
  is honoured — a fresh, empty path-backed log is kept, not silently replaced
  (invariant `configured_audit_log_is_persistent`).
- **The connector is vendored and served same-origin.** The console loads
  `@hot-labs/near-connect` (MIT) from `/assets/near-connect.js`, so no
  third-party script origin is added to the page. The console's
  `Content-Security-Policy` names only the two connector RPC origins it needs;
  every other response keeps the strict default CSP.
- **The console offers the full transfer flow.** The wallet panel lists the
  assets the server advertises for the configured network (so a testnet asset is
  never offered on mainnet), previews the exact asset, recipient, amount and
  network before anything is signed, asks for a blocking confirmation of those
  parameters after the server authorizes and before the wallet signs, and
  offers a disconnect control. The approved account is re-read from the wallet
  on every change, so an authorization is never bound to a stale identity. The
  server's decision remains the only thing that permits a sign; the confirmation
  is a human check on top of it, never a replacement.

**Locally verified + Testnet verified:** the flow was exercised against real NEAR
testnet — the server's `prepare` returned the exact wallet request, the testnet
account signed it, the harness broadcast the signed transaction, and `verify`
read the chain back to `VERIFIED`. Replaying a consumed `prepare_id` is refused
(`404`), and a tampered submission resolves to `DISPUTED`. Packaging tests prove
the wallet route and the vendored asset are present in a package-only copy, so
the shipped image serves them. The server never held a key: the signing account's
key lived only in the harness, outside the server process.

**Testnet verified (browser):** the console's wallet panel was additionally driven
in a real Chromium browser by a wallet emulator that holds the key and signs
(`demo/browser_wallet/run_demo.py`). It runs four scenarios — approved
(`VERIFIED`), non-approved recipient (`BLOCK`, the wallet is never asked),
tampered amount (`DISPUTED`), and user rejection (nothing broadcast) — against
real testnet transactions. The page never receives the key.

### Durable investigation history

A settlement investigation is a conclusion drawn from live sources, and those
sources drift. When the operator sets `TRACESETTLE_INVESTIGATIONS_DB`, every
completed investigation is persisted (SQLite) so a report produced before a
restart can be retrieved afterwards with its evidence intact.

- `GET /api/guard/investigations` lists the stored investigations for the local
  owner; `GET /api/guard/investigations/{id}` returns one report in full.
- The stored record is the conclusion **as recorded at the time**, reconstructed
  from its recorded evidence — it is not re-reconciled against live sources, and
  the console says so on screen.
- History is gated by the same API key as the other guard routes when one is
  configured, and is reported as `enabled: false` when no database is set.
- A configured database that cannot be opened is a hard failure at start-up: a
  recorded conclusion must not silently fail to persist.

### NEAR agent protection

An AI agent or a payment service acting for one must ask TRACESETTLE before it
signs. `AgentAuthorizationWrapper.evaluate(transaction)` reads the **actual**
parameters — never the agent's explanation — and runs four independent checks,
where the strictest outcome wins:

1. the Transaction Guard's deterministic decision;
2. the NEAR Intents policy scope;
3. the NEAR access-key scope;
4. **counterparty risk intelligence** (opt-in, `TRACESETTLE_NEAR_COUNTERPARTY=1`):
   a deterministic read of the destination account from public, keyless NEAR RPC
   reads — account existence (`view_account`), a contract-vs-account check, and
   account age in blocks. A non-existent account is `BLOCK`, a contract or a
   brand-new account forces a review, and a signal that cannot be read fails safe.
   A counterparty read only ever **adds** restriction; it never overrides a
   mandatory control downward.

**A human approval is bound to the exact payload.** When a decision is
`REQUIRE_APPROVAL` and approval is enabled
(`TRACESETTLE_NEAR_APPROVAL=1`), an authenticated approver signs a payload bound
to the request's own authorization fingerprint (including the transaction byte
digest when the caller holds the bytes), single-use and expiring (default 300 s).
A valid approval can raise `REQUIRE_APPROVAL` to `ALLOW` and nothing else: it can
never override a `BLOCK` or a `HOLD`, and a tampered, expired, replayed or
payload-mismatched approval leaves the decision at `REQUIRE_APPROVAL`. Off by
default, so an unconfigured deployment can never turn a needed approval into an
allow.

| Outcome | Meaning |
| --- | --- |
| `ALLOW` | An exact, transaction-bound authorization is valid; proceed. |
| `REQUIRE_APPROVAL` | The mission's "WARN": an authenticated human must approve. |
| `BLOCK` | Refuse to sign or submit. |
| `HOLD` | Do not execute while the required condition is unresolved. |
| `UNKNOWN` | Fail safely: the evidence needed to authorize was not obtained. |

**A NEAR Intents policy is in force only when the provider reports `status:
APPLIED` and `provider_policy_synced: true`.** A requested or signed update is not
active, and its rules are never treated as if they were.

**The policy scope gap is stated, not hidden.** An Intents policy's destinations,
USD budget, timelock, schedule and owner approval protect the **Intents** path. A
**native** NEAR/EVM/Solana request is not protected by them — only the policy's
native method switch, plus an independent TraceSettle decision. The wrapper
reports the gap explicitly.

**A NEAR function-call key cannot transfer NEAR** and cannot attach NEAR tokens to
a call. The wrapper checks the declared key scope before a native request reaches a
signer, and treats an unrecognised permission as unrestricted, never as safe.

**The signer validates before it spends.** At the signing gate the transaction's
signature and its authorization binding are checked *before* the single-use
authorization nonce is consumed. A malformed or wrong-transaction signature is
refused without burning the authorization, so a rejected attempt cannot be turned
into a denial of the legitimate signer's one valid submission. This ordering is
itself a structural invariant (`near_signature_is_verified_before_state_is_consumed`)
with a mutation test that fails if the order is reversed.

Nine deterministic attack scenarios run against the real controls, and every
refusal is provable: the executor is never called unless the outcome was `ALLOW`.

| id | Attack | Expected |
| --- | --- | --- |
| A | Legitimate payment | `ALLOW` + executed |
| B | Prompt-injected agent, unauthorised destination | `BLOCK` |
| C | Destination changed after approval | `REFUSED (WRONG_PARAMETERS)` |
| D | Agent exceeds its spending policy | `REQUIRE_APPROVAL` / `BLOCK` |
| E | Unauthorised service identity | `BLOCK` |
| F | Replayed authorization | `REFUSED (REPLAYED)` |
| G | Operation outside the permitted key scope | `BLOCK` |
| H | Native tx wrongly assumed protected by an Intents-only policy | policy-scope rejection |
| I | Provider reports success without independent evidence | `UNKNOWN` / `UNAVAILABLE` |

Fifteen NEAR-specific structural guarantees join the invariant set, each
mutation-tested: `near_policy_must_be_in_force`,
`near_policy_selection_is_not_client_controlled`,
`near_native_scope_gap_is_always_stated`,
`near_function_call_key_cannot_transfer_near`,
`near_unrecognised_access_key_never_allows`,
`near_provider_success_is_never_verified_without_evidence`,
`near_partial_settlement_is_never_verified`,
`near_terminal_states_are_evidence_distinguished`,
`near_destination_delivery_requires_the_destination_chain`,
`near_chain_is_derived_from_the_origin_asset`,
`near_execution_never_signs_without_authorization`,
`near_execution_binding_covers_the_bytes`,
`near_signature_is_verified_before_state_is_consumed`,
`near_execution_requires_access_key_permission`, and
`near_submission_is_durable_and_recovery_never_resubmits` (fifteen NEAR-specific
in total). Two further guarantees cover the newer controls and are mutation-tested
too: `counterparty_intelligence_only_adds_restriction` (a counterparty read can
never weaken a decision) and `human_approval_cannot_override_a_block` (an approval
can never lift a `BLOCK` or a `HOLD`).

## Try it: do X → see Y

No API keys, no paid services, no database. Python 3.11+ standard library only —
TRACESETTLE has **zero runtime dependencies**. The development tools are separate
and pinned in `requirements-dev.txt`.

**0. Set up a clean environment (development tools only).**

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` pins `pytest` and `pyflakes` (and pytest's transitive
dependencies). You only need it to run the checks below; the tool itself runs on
a bare interpreter.

**1. Run the tests.**

```sh
python -m pytest tests/ --collect-only -q   # 1471 tests collected
python -m pytest tests/ -q                  # 1444 passed, 27 skipped
```
→ `1444 passed, 27 skipped`. The skips are the PostgreSQL integration
tests; set `TRACESETTLE_TEST_PG_DSN` to a real server to run them
(**1468 passed, 3 skipped** — the remaining 3 are opt-in *live-infrastructure*
tests that need real provider credentials, a testnet key, or a TDX enclave
harness, none of which a zero-budget local run has).

**2. Prove the enforcement boundary: a permitted request executes, a suspicious
one cannot.**

```sh
python3 -m tracesettle serve --port 8080 &
```

Then open `http://127.0.0.1:8080/console`, go to **Transaction Guard**, and run
the three scenarios. Or drive it with `curl`:

```sh
# a) Legitimate: evaluated, authorized, then executed by the reference signer.
AUTH=$(curl -sS -X POST http://127.0.0.1:8080/api/guard/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"1250.50",
       "destination":"0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"},
       "return_authorization":true}')
echo "$AUTH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("decision:",d["decision"])'
```
→ `decision: ALLOW`.

```sh
# b) Suspicious: 480,000 to an unapproved address.
curl -sS -X POST http://127.0.0.1:8080/api/guard/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"480000",
       "destination":"0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"}}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["decision"],[f["code"] for f in d["findings"]], "authorization:", d.get("authorization"))'
```
→ `BLOCK ['UNAPPROVED_DESTINATION', 'AMOUNT_EXCEEDS_LIMIT'] authorization: None`.

```sh
# c) The bypass attempt: no authorization at all.
curl -sS -X POST http://127.0.0.1:8080/api/guard/sign \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"480000",
       "destination":"0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"},
       "authorization":null}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["outcome"],d["state"])'
```
→ `REFUSED MISSING`. The executor was never called.

**3. See the structural guarantees hold on the running build.**

```sh
curl -sS http://127.0.0.1:8080/api/guard/invariants \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("all hold:",d["all_hold"]);[print(" ",i["name"]) for i in d["invariants"]]'
```
→ `all hold: True` and the forty-six invariant names, including the fifteen NEAR
ones (`near_policy_must_be_in_force`, `near_native_scope_gap_is_always_stated`,
`near_function_call_key_cannot_transfer_near`,
`near_unrecognised_access_key_never_allows`,
`near_provider_success_is_never_verified_without_evidence`,
`near_partial_settlement_is_never_verified`,
`near_policy_selection_is_not_client_controlled`).

**4. Investigate a real, known-good swap from the command line.**

```sh
python3 -m tracesettle investigate 0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B
```
→ a Markdown report whose outcome is `SETTLED_VERIFIED`, with the source
deposit, bridge deposit credit, NEAR settlement, and destination delivery each
marked `CONFIRMED` and each linking to its real explorer page.

**5. See conservative handling of an unknown address.**

```sh
python3 -m tracesettle investigate 0x000000000000000000000000000000000000dEaD
```
→ outcome `NOT_FOUND`, and the report says plainly that not found is not proof
the swap failed.

**6. See that a reported-only settlement is not called verified.**

```sh
python3 -m tracesettle investigate 7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG --json
```
→ outcome `SETTLED_REPORTED_ONLY`: the intent hash path can read a service
statement but cannot reach the whole path, and the report says so.

**7. See how a real reported Bitcoin refund is handled.**

```sh
python3 -m tracesettle investigate bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm
```
→ the tool reads the intent's on-chain withdrawal recipient and looks for a
**confirmed** Bitcoin transaction paying that address, using the provider's
transaction list first and the address's own confirmed history as a fallback. A
payout is confirmed only when it is tied to the intent by an explicit identifier
and the tool validates it itself (raw bytes fetched, txid recomputed, recipient
script matched). Whether that is possible depends on what the provider exposes,
which changes over time:

- When the provider names the refund transaction (as its record did on
  2026-10-19), the tool validates it and the refund reads `CONFIRMED`; the outcome
  is `REFUND_VERIFIED` and the evidence records `discovery: "explicit"`.
- When the provider names no transaction and the address has several confirmed
  payouts, no payout can be tied to the intent by an explicit identifier: the
  refund stays a reported claim and the stage reads `UNAVAILABLE` with reason
  `AMBIGUOUS_REFUND_PAYOUT`. Confirming one of the payouts would be a guess, so the
  tool does not.

Either way the tool never picks a payout by amount or timestamp, and a reported
refund alone never confirms the stage. When a Bitcoin source is unreachable the
refund likewise stays `UNAVAILABLE` (a source problem, not a failed refund). The
demo states the outcome it actually observed in that run rather than a fixed
verdict.

**8. Run the web interface.**

```sh
python3 -m tracesettle serve --host 127.0.0.1 --port 8000
```
→ open `http://127.0.0.1:8000`, enter a deposit address, press **Investigate**,
and read the evidence in chronological order with links to every source record.
Copy or download the report as JSON or Markdown.

To expose the interface beyond loopback, set an API key first so
`POST /api/investigate` requires it:

```sh
TRACESETTLE_API_KEY=… TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
  python3 -m tracesettle serve --host 0.0.0.0 --port 8000
```
→ requests without a matching `X-API-Key` header receive `401`; `GET /` and
`GET /api/health` stay open. Binding a public interface without both credentials
now **refuses to start** (see **Fail-closed startup** below). See **Interface
hardening** below for the concurrency, rate-limit, and cache settings.

**9. Or run all three settlement cases at once.**

```sh
python3 demo/demonstrate.py
```
→ prints the verified swap, the intent-hash-only lookup, and a real refunded
swap side by side, with the decisive evidence for each confirmed stage. The third
case shows how a refund is handled: the tool reports the level the evidence
actually supports and never upgrades a reported refund to a confirmed one without
a transaction it validated itself. It uses live public endpoints; if one is
unreachable it says so and does not fabricate a result. The upstream record can
change between runs, so the third case states what it observed in that run rather
than a fixed verdict.

**10. If a public endpoint is down, replay the captured evidence.**

```sh
python3 demo/demonstrate.py --offline
```
→ runs the same analysis over the **real captures** in `evidence/raw/`, with no
network access. It substitutes only the network transport, so the adapter,
engine, and report code is the real code. The run is labelled `OFFLINE REPLAY`
and states the capture date; it does not show that an endpoint is answering now.

**11. Run the NEAR agent attack demonstration.**

```sh
python3 demo/near_demo.py
```
→ runs the nine scenarios against the real controls. Expected: A `ALLOW` +
executed, B `BLOCK`, C `REFUSED (WRONG_PARAMETERS)`, D `REQUIRE_APPROVAL` /
`BLOCK`, E `BLOCK`, F `REFUSED (REPLAYED)`, G `BLOCK`, H policy-scope rejection,
I `UNKNOWN`. Every scenario prints whether the simulated executor was reached;
for B–E and G–I it is `0`.

**12. Attempt an attack and see why it is blocked.**

```sh
python3 demo/near_demo.py --scenario B
```
→ a prompt injection tells the agent to pay `0xdeadbeef…`. The wrapper reads the
real destination, not the agent's explanation, and returns `BLOCK` with the
findings `GUARD_DECISION`, `GUARD_UNAPPROVED_DESTINATION` and
`POLICY_DESTINATION_DENIED`. The executor is never called (`executor executions
-> 0`).

```sh
python3 demo/near_demo.py --scenario H
```
→ a native NEAR transfer is rejected (`POLICY_SCOPE_REJECTED`) because the
Intents policy does not enable `native.near.transfer`, and the run states that
the Intents money controls do not apply to a native request.

**13. Verify the policy scope gap and the access-key facts.**

```sh
python3 demo/near_demo.py --policy-scope
python3 demo/near_demo.py --access-keys
```
→ the first prints which controls protect the `INTENTS` path versus a
`NATIVE_NEAR` request; the second prints that a function-call key cannot transfer
NEAR, that an omitted `method_names` means every method, and that an omitted
`allowance` means unlimited gas.

**13b. Run the full agent lifecycle end to end: intercept → block → authorize →
settle → verify.**

```sh
python3 demo/near_agent_demo.py
```
→ a deterministic local agent proposes two payments through the **real**
execution boundary. The malicious one (a legitimate invoice redirected to an
attacker receiver) is `BLOCK`ed with the signer invoked **zero** times and
nothing broadcast; the legitimate one is `ALLOW`ed, signed, broadcast, and
independently verified (`SETTLED` / `VERIFIED`). Add `--live` with a funded
`*.testnet` key to run the identical path against **NEAR testnet** (see
[End-to-end agent lifecycle](#end-to-end-agent-lifecycle-interception--blockauthorize--settle--verify)).

**14. Inspect the NEAR surface over HTTP (server from step 8 running).**

```sh
curl -sS http://127.0.0.1:8000/api/guard/near/scenarios \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("all passed:",d["all_passed"])'
curl -sS http://127.0.0.1:8000/api/guard/near/policy-scope \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["scope"]["NATIVE_NEAR"]["non_applicable_controls"])'
```
→ `all passed: True`, and the native scope names the controls that do **not**
apply (`destinations`, `budget_usd`, `timelock_ms`, `schedule`,
`owner_approval`).

**14b. See the agent-authorization behaviours and the prompt-injection demo.**

```sh
curl -sS http://127.0.0.1:8000/api/guard/near/behaviours \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("all held:",d["all_held"]);[print(" ",b["name"],b["observed"]) for b in d["behaviours"]]'
curl -sS http://127.0.0.1:8000/api/guard/near/prompt-injection \
  | python3 -c 'import sys,json;a=json.load(sys.stdin)["audit"];print(a["authorization_result"], "signed:", a["signed"], "broadcast:", a["broadcast_occurred"])'
```
→ `all held: True` for the six behaviours (ALLOW, WARN, BLOCK, TAMPER, REPLAY,
FAILURE), and `BLOCK signed: False broadcast: False` for the injection demo: a
manipulated agent that is told to pay an attacker's receiver is refused because
the guard evaluates the **actual transaction parameters**, not the instruction,
and nothing is signed or broadcast. Both panels are also in the console's
**NEAR agent security** tab.

**15. Evaluate one agent transaction over HTTP — allowed, then blocked.**

The default policy approves `0x4e6d3a556e485188e9c9a528bc72c88bd92bd735` and
`0xb741c00f6d63b6ded0ccada1a82bcbadc38a572b`, so the first call passes.

```sh
curl -sS -X POST http://127.0.0.1:8000/api/guard/near/agent-evaluate \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"100",
       "destination":"0x4e6d3a556e485188e9c9a528bc72c88bd92bd735",
       "scope":"INTENTS","policy_action":"withdraw"}}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["outcome"],d["permits_signing"])'
```
→ `ALLOW True`.

```sh
curl -sS -X POST http://127.0.0.1:8000/api/guard/near/agent-evaluate \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"WITHDRAWAL",
       "chain":"eth","asset":"USDC","amount":"100",
       "destination":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
       "scope":"INTENTS","policy_action":"withdraw"}}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["outcome"],d["permits_signing"])'
```
→ `BLOCK False`. The destination is unapproved, so the wrapper refuses to permit
signing. Nothing is signed or broadcast in either call.

**16. Walk the NEAR Intents lifecycle: create → quote → approve → deposit.**

This needs the lifecycle enabled and a durable store. It issues a live (fundable)
quote, so it is an explicit operator decision:

```sh
TRACESETTLE_NEAR_LIFECYCLE=1 TRACESETTLE_INTENTS_DB=/tmp/intents.db \
TRACESETTLE_INVESTIGATIONS_DB=/tmp/investigations.db \
  python3 -m tracesettle serve --host 127.0.0.1 --port 8000
```

Create and authorize an intent (the guard runs on the real parameters):

```sh
curl -sS -X POST http://127.0.0.1:8000/api/guard/near/lifecycle \
  -H 'Content-Type: application/json' \
  -d '{"transaction":{"service_id":"treasury-agent","operation":"SETTLEMENT",
       "chain":"eth","asset":"USDC","amount":"1000000","scope":"INTENTS"},
       "idempotency_key":"demo-1"}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["intent_id"],d["decision"]["outcome"])'
```
→ an intent id and `ALLOW`. A `SETTLEMENT` over the policy limit would return
`REQUIRE_APPROVAL` or `BLOCK` instead, and no quote would be issued.

Request a live quote, then try to record a deposit **before** approving it:

```sh
ID=<the intent id>
curl -sS -X POST http://127.0.0.1:8000/api/guard/near/lifecycle/$ID/quote \
  -H 'Content-Type: application/json' -d '{"dry":false}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("address:",d["deposit_address"]);print("expiry:",d["expiry"]["reason"])'
curl -sS -X POST http://127.0.0.1:8000/api/guard/near/lifecycle/$ID/deposit \
  -H 'Content-Type: application/json' -d '{"deposit_tx_hash":"0xabc"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["error"])'
```
→ the quote prints a deposit address and `expiry: VALID`; the deposit is refused
with `the quote has not been approved; approve the live quote before recording a
deposit`.

Approve the quote, and only then record the deposit:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/guard/near/lifecycle/$ID/approve \
  -H 'Content-Type: application/json' -d '{"approve":true}' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["state"],d["approved"])'
```
→ `QUOTE_APPROVED True`, and the deposit form is now accepted. A fresh quote
clears the approval, so approval is always bound to the quote you reviewed.

**17. Retrieve a stored investigation after a restart.**

With `TRACESETTLE_INVESTIGATIONS_DB` set (step 16), every completed investigation
is persisted. After running step 4, list and open the stored report:

```sh
curl -sS http://127.0.0.1:8000/api/guard/investigations \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("enabled:",d["enabled"]);print("count:",len(d["investigations"]))'
curl -sS http://127.0.0.1:8000/api/guard/investigations/<investigation_id> \
  | python3 -c 'import sys,json;d=json.load(sys.stdin)["investigation"];print(d["outcome"],len(d["evidence"]),"evidence items")'
```
→ the stored outcome and its full evidence, reconstructed from what was recorded
at the time. The record is **not** re-reconciled against live sources, and the
console says so. Restart the server and the report is still there.

**18. Watch the learning loop tighten a later decision.**

```sh
python3 demo/near_demo.py --learning-loop
```
→ a request to an unapproved destination is `BLOCK`ed and teaches a durable
safeguard; a later, larger request that the operator's policy alone would `ALLOW`
is tightened to `REQUIRE_APPROVAL`; a request at or below the learned floor is
unaffected. The lesson is durable and only ever tightens — it never overrides the
operator's policy. With `TRACESETTLE_GUARD_SAFEGUARD_DB` set (see
[The learning loop store](#the-learning-loop-store)), `GET /api/guard/safeguards`
lists the safeguards in force and the console's NEAR tab renders them.

**19. See the enclave signing boundary hold its guarantees.**

```sh
python3 demo/near_enclave_demo.py
```
→ five checks against the real boundary logic, using a deterministic stand-in
enclave transport (a real ed25519 keypair, no network): A a key provisioned against
a verified, measurement-pinned, transaction-bound attestation signs the exact
bytes and the signature verifies; B a non-approved measurement is refused; C
mainnet signing is refused (testnet-only); D a signature that does not verify is
refused; E a key cannot be used with a different provisioning request. Expected:
`5/5 checks produced the expected outcome.` and `No transaction was signed for a
chain.` The demo is byte-identical across runs.

## Supported input and honest limits

| Identifier | What it can do |
| --- | --- |
| 1Click deposit address (EVM, NEAR, TRON, Bitcoin) | Full path: source, settlement, destination, refund. |
| Intent hash | Settlement status only (solver relay). No reverse lookup exists. |
| Origin-chain transaction hash | Not supported. The 1Click status endpoint is keyed on the deposit address; there is no documented reverse lookup. |

Deposit addresses are recognised by their exact encoding, not by length or a
leading character: EVM `0x`+40 hex, NEAR account ids, TRON mainnet Base58Check
(version byte `0x41`), and Bitcoin legacy Base58Check (P2PKH/P2SH) plus segwit
(bech32/bech32m). A Solana public key is a 32-byte base58 value, which is the
same encoding a NEAR transaction hash and an intent hash use; every 32-byte
base58 value is 43-44 characters, so the three are indistinguishable from the
string alone. Such a value is therefore never routed as a deposit address: it is
reported as `UNKNOWN` with a note naming all three possibilities, and is offered
the intent-hash path. `is_solana_address` recognises the encoding for a caller
that already knows the chain, but no automatic routing is performed.

Other limits, stated in every report:

- 1Click status is a service statement, reported and not independently verified.
- Only chains with a configured public RPC can be independently verified.
- **Free public RPCs prune history.** The default endpoints keep roughly a
  two-day window, so an older transaction returns a null receipt (EVM) or
  `UNKNOWN_TRANSACTION` (NEAR) even though it exists. Each chain therefore
  carries archive-capable fallbacks (`eth.drpc.org`, `…drpc.org` per chain, and
  `eth-mainnet.public.blastapi.io`; NEAR uses `archival-rpc.mainnet.near.org`).
  A fallback answer is validated by exactly the same checks as the primary, so a
  fallback never weakens verification. When every endpoint misses, the stage stays
  `NOT_FOUND`; when an endpoint is unreachable, it stays `UNAVAILABLE` — never
  `FAILED`. Set `TRACESETTLE_NEAR_RPC_FALLBACK_URL` to a paid archive node for a
  reliable historical NEAR lookup; the free archive is deprecated and rate-limits
  hard (HTTP 429), in which case the stage is `UNAVAILABLE`, not confirmed.
- A missing record or a 404 is not evidence that a transaction failed.
- A reported failure is not proof funds were lost.
- A reported refund of zero is not proof no refund can occur.
- Simulated test evidence is always labelled.
- **Bitcoin refunds are only confirmed when the payout is unambiguous.** For a real
  refunded BTC→TRON swap (`bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm`), the tool
  confirms the refund only when exactly one confirmed payout matches the on-chain
  withdrawal recipient, or when the provider itself names the transaction and it
  validates. When the provider names no transaction and the recipient has several
  confirmed payouts, the payout cannot be tied to this intent by an explicit
  identifier: the refund stays a reported claim and the stage reads `UNAVAILABLE`
  (`AMBIGUOUS_REFUND_PAYOUT`). The tool never picks a payout by amount or timestamp,
  and a reported refund alone never confirms the stage.
- The reported refund amount and the observed on-chain payout may differ. Both
  figures are stated and the difference is disclosed, not reconciled; a lower
  payout is expected because network and bridge fees are deducted.
- The bridge credit is confirmed from an on-chain `BRIDGED_FROM` memo that names
  the origin transaction hash. That memo is emitted by the bridge service, so it is
  strong identifier-based, on-chain corroboration — **not** cryptographic proof of
  the whole settlement. The report states this in the evidence item's limitations.

## Architecture

Two layers. The security layer gates what may be executed; the settlement layer
verifies what was. They share one principle: never trust a claim you have not
checked.

```
                        ┌───────────── security layer ─────────────┐
transaction request ──▶ │ guard/rules.py      7 controls, all run  │
                        │ guard/policy.py     policy + version     │
                        │ guard/model.py      explained Decision   │
                        │ guard/authorization.py  transaction-bound │
                        │                     HMAC authorization    │
                        │ guard/signer.py     reference signer:     │
                        │                     validate, then execute │
                        │ guard/audit.py      hash-chained records  │
                        │ guard/monitor.py    counters + incidents  │
                        │ guard/invariants.py 45 checked guarantees │
                        └────────────────────┬─────────────────────┘
                                             │ ALLOW + authorization
                                             ▼
                                     execution or refusal
                                     (SimulatedExecutor: no chain)

identifier
   │
   ▼
identifiers.py ── classify + validate
   │
   ▼
investigation.py ── orchestrates adapters, correlates via explicit ids
   │
   ├── adapters/oneclick.py      1Click status      (reported)
   ├── adapters/solver_relay.py  intent status      (reported)
   ├── adapters/near_rpc.py      NEAR tx + logs     (authoritative)
   ├── adapters/evm_rpc.py       EVM receipts       (authoritative)
   └── adapters/btc_rpc.py       Bitcoin tx + addr  (authoritative)
   │
   ▼
model.py ── normalized EvidenceItem stream
   │
   ▼
reconcile.py ── deterministic engine, 12 safety invariants
   │
   ▼
report.py ── JSON + Markdown investigation report
   │
   ▼
ui.py / __main__.py ── web interface + CLI
```

The engine is deterministic: identical evidence produces an identical result.
No LLM decides whether a transaction is confirmed. The security controls are
equally deterministic: identical requests against an identical policy produce
identical decisions.

## Files

| Path | Role |
| --- | --- |
| `tracesettle/identifiers.py` | Identifier classification and validation. |
| `tracesettle/base58.py` | Shared Base58/Base58Check decoding (used by classification and Bitcoin script decoding). |
| `tracesettle/model.py` | Evidence model: stages, states, outcomes, safety invariants. |
| `tracesettle/assets.py` | `nep141:` asset id parsing to chain/contract. |
| `tracesettle/config.py` | Public chain RPC map (with archive fallbacks), explorer URL builders, guard settings. |
| `tracesettle/httpclient.py` | Timeouts, bounded retries, error classification. |
| `tracesettle/adapters/` | One adapter per data source (1Click, solver relay, NEAR, EVM, Bitcoin). |
| `tracesettle/reconcile.py` | Deterministic reconciliation engine. |
| `tracesettle/investigation.py` | Orchestrator. |
| `tracesettle/investigation_store.py` | Durable settlement-investigation store (SQLite), so a report survives a restart. |
| `tracesettle/intents_store.py` | Durable NEAR Intents lifecycle store (SQLite). |
| `tracesettle/report.py` | Report generation. |
| `tracesettle/ui.py` | Standard-library web interface, guard routes, console. |
| `tracesettle/ratelimit.py` | Token buckets for per-IP and per-host limits. |
| `tracesettle/cache.py` | Bounded TTL cache with single-flight. |
| `tracesettle/serviceauth.py` | Per-service credential registry (hashed secrets, constant-time). |
| `tracesettle/securityconfig.py` | Fail-closed startup validation for the network interface. |
| `tracesettle/__main__.py` | CLI (`investigate`, `serve`, `credentials`). |
| `tracesettle/guard/model.py` | Transaction request, policy, decision, finding, authorization models. |
| `tracesettle/guard/policy.py` | Default policy and JSON override loading. |
| `tracesettle/guard/rules.py` | The seven deterministic controls. |
| `tracesettle/guard/authorization.py` | Issuing, validating, expiring, single-use nonces. |
| `tracesettle/guard/signer.py` | Reference signer + simulated executor (the enforcement boundary). |
| `tracesettle/guard/audit.py` | Hash-chained, verifiable audit log. |
| `tracesettle/guard/monitor.py` | Security counters and incident records. |
| `tracesettle/guard/service.py` | Orchestration: controls → authorization → monitor → audit. |
| `tracesettle/guard/state.py` | Durable state: `GuardStateStore` (SQLite), backend-aware `open_state_store`. |
| `tracesettle/guard/safeguards.py` | Durable security safeguards: the learning loop's store (SQLite). |
| `tracesettle/guard/learning.py` | The learning loop: derive a lesson, apply safeguards (only ever tightening). |
| `tracesettle/guard/state_pg.py` | Optional PostgreSQL backend: shared nonces, counters, revocations, idempotency. |
| `tracesettle/guard/invariants.py` | The forty-six structural guarantees, checked by execution. |
| `tracesettle/guard/api.py` | Guard HTTP routing and JSON serialization. |
| `tracesettle/guard/console.py` | The security operations console page. |
| `docs/TRANSACTION_SECURITY.md` | The security layer in full, including what it does not do. |
| `Dockerfile` / `.dockerignore` | Minimal non-root container image (healthcheck probes `/api/health`). |
| `Dockerfile.vercel` / `vercel.json` | Vercel Hobby deployment via the Container Runtime (see `deploy/production/VERCEL_DEPLOYMENT.md`). |
| `.github/workflows/ci.yml` | CI: tests, static analysis, Docker build + runtime, demo determinism. |
| `demo/demonstrate.py` | Read-only walkthrough (live, or `--offline` replay of captures). |
| `demo/near_agent_demo.py` | End-to-end agent lifecycle (intercept → block/authorize → settle → verify), offline or `--live` on testnet. |
| `demo/replay_opener.py` | Offline transport that replays `evidence/raw/` through the real code. |
| `tracesettle/static/near-connect.js` | Vendored `@hot-labs/near-connect` (MIT) wallet connector, served same-origin at `/assets/near-connect.js`. |
| `tests/` | 1471 tests (27 PostgreSQL tests skip without `TRACESETTLE_TEST_PG_DSN`; 3 further tests are opt-in live tests that skip without a live testnet key, live Agent API credentials, or `TRACESETTLE_ENCLAVE_HARNESS=1`). `evidence/raw/` fixtures are real captures; `tests/fixtures/synthetic/` are clearly labelled synthetic. |
| `PHASE1_FEASIBILITY.md` | Phase 1 feasibility and API verification. |
| `submission/` | Hackathon artifacts: API payload shape, technical summary, demo post draft, publication checklist. |
| `docs/official/` | NEAR documentation captured during Phase 1. |
| `requirements-dev.txt` | Development-only tool pins (`pytest`, `pyflakes`). Not needed at runtime. |

tracesettle/near/          NEAR agent protection: policy scope, access-key
                          analysis, the agent authorization wrapper, the attack
                          scenarios, the local agent harness (agent_harness.py),
                          the settlement assurance view, the Intents lifecycle
                          (create → authorize → quote → approve → deposit →
                          settle), TEE research, and the enclave signing boundary

## Runtime dependencies

**None.** TRACESETTLE imports only the Python standard library at runtime
(`json`, `urllib`, `http.server`, `hashlib`, and similar). `requirements-dev.txt`
exists solely for the test and lint tooling and must not be installed to run the
tool. Supported interpreter: CPython 3.11+; verified on 3.13.15.

## Security and reliability

- No private keys, seed phrases, signing, or transaction submission anywhere.
- All external input is validated (type, length, control characters).
- Every upstream request has a timeout and a bounded retry budget; 4xx errors
  are not retried.
- Rate limits and upstream errors are classified, not hidden.
- No secrets are read, written, logged, or sent to the client.
- Errors returned to the client never contain internal details.
- The app stays usable when a source is down, marking evidence `UNAVAILABLE`.
- A blockchain hash commitment is never treated as proof the underlying event is
  true.

### Interface hardening

The web interface is hardened against resource exhaustion and abuse, with every
limit configurable by environment variable:

- **Client socket timeouts.** Each connection has a read timeout
  (`TRACESETTLE_CLIENT_TIMEOUT`, default 10s), so a slow or idle client cannot
  hold a worker thread open (slowloris).
- **Hard concurrency cap.** At most `TRACESETTLE_MAX_CONCURRENCY` (default 16)
  connections are served at once. Excess connections get an immediate
  `503 Service Unavailable` with `Retry-After` instead of being queued. The
  concurrency slot is released on every path, including errors.
- **Bounded request bodies.** `Content-Length` is checked against an 8 KiB cap
  *before* the body is read; an oversized or missing body is `413`, never
  buffered.
- **API-key authentication.** Set `TRACESETTLE_API_KEY` to require an `X-API-Key`
  header on `POST /api/investigate` (constant-time comparison; the key is never
  logged or echoed). Unset, the endpoint is open — the default for loopback use.
- **Per-IP rate limiting.** `TRACESETTLE_RATE_LIMIT_PER_MINUTE` /
  `_BURST` bound each client IP (keyed on the socket peer, so a spoofed
  `X-Forwarded-For` cannot bypass it); over-budget requests get `429` with
  `Retry-After`.
- **Per-host upstream budgets.** `TRACESETTLE_HOST_RATE_LIMIT_*` cap calls per
  upstream host, so one client cannot exhaust a free public endpoint's shared
  rate limit for everyone.
- **Bounded upstream caching.** Read-only GET responses (1Click status, Esplora
  transaction and address endpoints) are cached for
  `TRACESETTLE_CACHE_TTL` seconds (default 45) and keyed on the exact URL, so
  distinct investigations never share an entry. Only successful responses are
  cached; failures, timeouts, and incomplete results are never stored. Concurrent
  identical misses are coalesced into one upstream call.
- **No version disclosure.** The `Server` header is `TRACESETTLE`; the Python
  build and package version are not disclosed.

### Security-layer hardening

The guard layer adds its own boundary controls, all configurable by environment
variable and all documented in `docs/TRANSACTION_SECURITY.md`:

- **Fail-closed authorization.** No authorization, or any invalid one, means no
  execution. There is no "assume approved" path.
- **Transaction-bound, single-use, short-lived.** An authorization names the exact
  parameters it approved, carries a 90-second default expiry, and its nonce is
  consumed atomically on first successful use.
- **Constant-time secret comparison.** The API key is compared with
  `hmac.compare_digest`; the authorization signature is verified with
  `hmac.compare_digest`.
- **No key material in any response.** The signing key is never returned, logged,
  or included in metrics; the console never receives it. Asserted by the
  `no_key_material_in_output` invariant.
- **Client assertions are never trusted.** A caller-supplied `approved` or
  `skip_checks` flag produces a finding and a downgraded decision, never ALLOW.
- **Bounded guard bodies.** Guard request bodies are capped by
  `TRACESETTLE_GUARD_MAX_BODY_BYTES` (8 KiB) and rejected before being read.
- **Per-client rate limiting on guard routes**, keyed on the socket peer address
  so a spoofed `X-Forwarded-For` cannot bypass it; `429` carries `Retry-After`.
- **Bounded state.** Audit records, monitor events, incidents, and the
  replay-nonce store all have explicit caps, so a flood cannot exhaust memory.
  When durable state is configured, spent nonces and the limit counters live in
  SQLite instead, so they survive a restart (see **Durable state** below).
- **Structural invariants, checked by execution.** Forty-five guarantees at
  `GET /api/guard/invariants`, each mutation-tested so a checker that cannot fail
  is treated as a defect.
- **Honest audit claim.** In-place modification of an audit record is detectable;
  a whole-log rewrite with recomputed digests is *not*, and the README says so
  rather than claiming tamper-proofness.

### Per-service authentication

The guard's policy layer evaluates a transaction for the service named in the
request. Left there, one service could name another and inherit its policy. Each
service can therefore be issued a credential, and a guard request must resolve to
the identity its credential was issued for:

- **The credential is the identity.** A caller presents its credential in the
  `X-Service-Credential` header. The credential resolves to exactly one
  `service_id`; a request whose declared `service_id` differs is refused with
  `403`, so editing the field cannot adopt another identity. This is asserted by
  the `service_identity_cannot_be_forged` invariant.
- **Only hashes are stored.** The plaintext secret is shown once at mint time and
  never stored; the store keeps a one-way `sha256:` hash. This is asserted by the
  `service_credentials_are_hashed_at_rest` invariant. The store is written
  `0600`.
- **Constant-time comparison**, over every credential, so the check does not leak
  which credential matched or how many exist. A refused request gets a generic
  `401`; the credential is never logged or echoed.
- **Expiry, revocation, and rotation.** A credential can expire or be revoked
  (either is refused), and rotation issues a new secret and revokes the old one.
- **Mint and manage from the CLI** — no secret is ever committed:

  ```sh
  python3 -m tracesettle credentials mint treasury-agent --store /etc/tracesettle/credentials.json
  TRACESETTLE_SERVICE_CREDENTIALS=/etc/tracesettle/credentials.json \
  TRACESETTLE_REQUIRE_SERVICE_AUTH=1 python3 -m tracesettle serve --host 0.0.0.0 --port 8000
  ```
  → `mint` prints the secret exactly once; `credentials list` and
  `credentials revoke <id>` never print a secret. The store's read-modify-write is
  serialised with an exclusive `<store>.lock`, so concurrent `mint`/`revoke`
  commands cannot lose a change or restore a just-revoked credential. With
  `TRACESETTLE_REQUIRE_SERVICE_AUTH=1` and no store, the server refuses to start.
  Configure the store with `TRACESETTLE_SERVICE_CREDENTIALS` (a path) or
  `TRACESETTLE_SERVICE_CREDENTIALS_JSON` (inline JSON, for platforms without a
  mounted file). When no store is configured, the loopback development workflow
  is unchanged.

### Durable state

A spent authorization nonce and a service's velocity/volume counters decide
whether the next transaction is allowed. Kept only in process memory, they are
lost on a restart: a spent nonce becomes valid again and a limit resets to zero.
Setting `TRACESETTLE_GUARD_STATE_DB` moves that state into a SQLite file
(standard library only), so it survives a restart:

```sh
TRACESETTLE_GUARD_STATE_DB=/var/lib/tracesettle/guard.db \
TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
TRACESETTLE_API_KEY=change-me \
python3 -m tracesettle serve --host 0.0.0.0 --port 8000
```
→ a token signed once is refused as `REPLAYED` after a restart, and a spending
limit is still enforced after a restart. Unset, the guard keeps its in-memory
stores and the loopback development workflow is unchanged; the console and
`GET /api/guard/metrics` report the backend (`sqlite` or `in-memory`) so an
operator can see whether the run is durable.

- **Fail closed.** A store error yields `HOLD` with no authorization, never
  `ALLOW`. A database that cannot be opened stops start-up rather than running
  with a silently degraded control. A failed write latches the store degraded, so
  a limit that could not be persisted is never silently unenforced.
- **Atomic.** The counter read, the decision, and the counter write happen in one
  transaction, so two concurrent requests cannot both pass a limit; the nonce is
  a primary key, so exactly one use can win.
- **Bounded.** The counter and idempotency tables are pruned on a retention
  horizon (`TRACESETTLE_GUARD_STATE_RETENTION_SECONDS`, default 24h, far longer
  than any window), and the window read is index-backed, so evaluation cost does
  not grow with the number of past requests.
- **Single instance, by default.** A SQLite file is durable state for one
  application instance. To share one set of nonces and counters across several
  replicas, select the PostgreSQL backend (below). Design and scope are in
  `docs/DURABLE_STATE.md`.

### The learning loop store

The learning loop (see [The learning loop](#the-learning-loop-durable-safeguards))
needs a durable home for the safeguards it draws. Set
`TRACESETTLE_GUARD_SAFEGUARD_DB` to a SQLite path to enable it:

```sh
TRACESETTLE_GUARD_SAFEGUARD_DB=/var/lib/tracesettle/safeguards.db \
python3 -m tracesettle serve --host 127.0.0.1 --port 8000
```
→ `GET /api/guard/safeguards` lists the safeguards in force; the console's NEAR
tab shows them. Unset, the loop is inert and the guard behaves exactly as before.
A safeguard store that cannot be read is a **fail-closed** condition: the affected
request is tightened to `REQUIRE_APPROVAL`, never silently allowed.

### Shared state across instances (PostgreSQL)

SQLite is correct for one instance. For several replicas that must enforce the
same nonces, revocations, and limits, point the guard at a shared PostgreSQL
database. The driver is an optional extra, imported lazily, so the default
install and the default image stay standard-library only and need no database:

```sh
pip install "psycopg[binary]==3.3.6"                 # optional, only for this backend
export TRACESETTLE_GUARD_STATE_BACKEND=postgresql
export TRACESETTLE_GUARD_STATE_PG_DSN="postgresql://user:pass@db-host:5432/tracesettle"
export TRACESETTLE_GUARD_REQUIRE_POSTGRES=1          # refuse to start if PG is not active
TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
TRACESETTLE_API_KEY=change-me \
python3 -m tracesettle serve --host 0.0.0.0 --port 8000
```
→ a token signed by one instance is refused as `REPLAYED` by another, and a
spending limit is shared: the sum across all instances is enforced, not each
instance's own total. The console and `GET /api/guard/metrics` report
`backend: "postgresql"` and `durable: true`.

The PostgreSQL store keeps every guarantee above and adds the one SQLite cannot
give: an atomic decision across hosts. SQLite takes a whole-database write lock;
PostgreSQL has no equivalent, so the store serialises the read-decide-write
critical section with a transaction-scoped advisory lock (`pg_advisory_xact_lock`)
plus a bounded `lock_timeout`. A broken shared store fails closed (`HOLD`, no
authorization) and never falls back to process memory — a silent fallback would
reintroduce the replay the shared store exists to prevent. A dropped connection
is not a broken store: the next call reconnects, so a transient blip does not take
an instance out of service. Verified against a real server: cross-instance replay
refusal, a shared spend window, revocation visible across instances, and
fail-closed then recovery when the database is stopped and started.

### Fail-closed startup

Authentication is not optional on a public interface: the process refuses to
start rather than expose protected endpoints without it.

- **A public bind requires credentials, with no override.** Binding any
  non-loopback host (for example `0.0.0.0`) without both `TRACESETTLE_API_KEY`
  and `TRACESETTLE_GUARD_AUTH_KEY` exits with status `2` and a message naming the
  missing variables. Only a value that provably parses as a loopback address is
  treated as local, so an unknown or empty host fails closed. There is no
  environment variable that relaxes this: a public bind without credentials
  always refuses to start, so a deployment mistake cannot expose the endpoints.
- **`TRACESETTLE_REQUIRE_SERVICE_AUTH` is enforced.** Setting it without a
  credential store refuses to start on any binding.
- **The container inherits this.** The image binds `0.0.0.0`, so it now requires
  both credentials; the CI job proves it starts with them and refuses without
  them.

`POST /api/investigate` returns the structured report (`{"data": ...}`) by
default. `?format=json`, `?format=markdown`, and `?format=full` (all three, as
earlier versions returned) select other representations.

## Deploy

A minimal image is included. It runs as a non-root user and probes
`/api/health`. Because the image binds `0.0.0.0`, it now requires both
credentials (see **Fail-closed startup**):

```sh
docker build -t tracesettle .
docker run --rm -p 8000:8000 \
  -v tracesettle-state:/data \
  -e TRACESETTLE_GUARD_STATE_DB=/data/guard.db \
  -e TRACESETTLE_API_KEY=change-me \
  -e TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
  tracesettle
curl http://127.0.0.1:8000/api/health
```
→ the same image with neither credential exits `2` with
`refusing to start: ... requires authentication` instead of serving. The named
volume makes the durable state survive container replacement; drop it (and the
`TRACESETTLE_GUARD_STATE_DB` variable) to run with in-memory state. The container
user is uid `10001`, so the mounted volume must be writable by it.

`serve` reads its defaults from the environment, so the image needs no flags on
a container platform: `TRACESETTLE_HOST` (default `127.0.0.1`; the image sets
`0.0.0.0`) and `PORT` or `TRACESETTLE_PORT` (default `8000`). Always set both
`TRACESETTLE_API_KEY` and `TRACESETTLE_GUARD_AUTH_KEY` before exposing the
interface.

The default image is dependency-free (SQLite / in-memory). For the PostgreSQL
shared-state backend, build with the driver included:

```sh
docker build --build-arg TRACESETTLE_WITH_POSTGRES=1 -t tracesettle:pg .
docker run --rm -p 8000:8000 \
  -e TRACESETTLE_GUARD_STATE_BACKEND=postgresql \
  -e TRACESETTLE_GUARD_REQUIRE_POSTGRES=1 \
  -e TRACESETTLE_GUARD_STATE_PG_DSN="postgresql://user:pass@db-host:5432/tracesettle" \
  -e TRACESETTLE_API_KEY=change-me \
  -e TRACESETTLE_GUARD_AUTH_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \
  tracesettle:pg
```
→ two such containers pointed at one database enforce one set of nonces: a token
signed by the first is refused as `REPLAYED` by the second. The default build
(`docker build -t tracesettle .`) stays standard-library only, so no database
driver ships in an image that does not use one.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to `master`.
It performs no deployment, publish, or release, and needs no repository secrets:

- the full test suite (`python -m pytest tests/ -q`);
- static analysis (`python -m pyflakes tracesettle/ tests/ demo/`);
- byte-compilation of every module;
- the offline demo run twice, asserted byte-identical (determinism);
- the NEAR attack demonstration run twice, asserted byte-identical, with every
  scenario required to match its expected outcome;
- the agent lifecycle demonstration (`demo/near_agent_demo.py`) run twice,
  asserted byte-identical, requiring the malicious payment to `BLOCK` with the
  signer invoked `0` times and the legitimate payment to reach `VERIFIED`;
- a gate that fails if any non-standard-library import appears at module level
  (the optional PostgreSQL driver is allowed only as a lazy, function-body import);
- a PostgreSQL job (`postgres:16` service) that runs the distributed
  shared-state tests against a real server and then the full suite;
- a Docker build, a non-root runtime check (uid `10001`), a `/api/health`
  probe, a graceful-shutdown check, and a check that the image **refuses to
  start** without credentials.

The workflow grants `contents: read` only, pins every third-party action to an
immutable commit SHA (not a moving tag), and cancels superseded runs.

## Tests

```sh
python3 -m pytest tests/ -q          # 1444 passed, 27 skipped (1468 passed, 3 skipped with PostgreSQL)
python3 -m pytest tests/test_guard_authorization.py -q
python3 -m pytest tests/test_guard_invariants.py -q
python3 -m pytest tests/test_guard_end_to_end.py -q
python3 -m pytest tests/test_safety_invariants.py -q
python3 -m pytest tests/test_serviceauth.py tests/test_serviceauth_http.py -q
python3 -m pytest tests/test_securityconfig.py tests/test_failclosed_startup.py -q
python3 -m pytest tests/test_ui.py -q
python3 -m pytest tests/test_near_policy.py tests/test_near_access_keys.py -q
python3 -m pytest tests/test_near_agent_wrapper.py tests/test_near_attacks.py -q
python3 -m pytest tests/test_near_api.py tests/test_near_invariants.py -q
python3 -m pytest tests/test_near_agent_harness.py -q   # full lifecycle through the real boundary
python3 -m pytest tests/test_near_acceptance.py -q   # product-level wiring
```

Test coverage includes successful settlement, a failed intent with a verified
refund, a failed intent without a verified refund, a confirmed source with
incomplete downstream evidence, conflicting or unavailable status information,
invalid identifiers, malformed responses, API timeouts, missing fields, and
unreliable correlation. It also covers the Bitcoin refund path: an ambiguous
refund address history that must stay unconfirmed, a single verified on-chain
refund, a confirmed payout to the wrong address, an unreachable Bitcoin source,
a source returning raw bytes that do not match the claimed txid (contradictory),
raw bytes that are merely unavailable (a limitation, not a contradiction), an
address history that cannot be shown to be complete (insufficient evidence,
reported as unknown rather than unavailable), an address history whose page
budget stops mid-chain, a multi-page history that ends naturally, amount
denomination and fee handling, and a missing on-chain withdrawal recipient.
`tests/test_safety_invariants.py` fails the build if the engine ever claims a
refund or a destination delivery without the required evidence, and adds
state-transition invariants (reported never becomes confirmed, unavailable never
becomes confirmed, incomplete never becomes confirmed, contradictions surface).

Tests exercise the real adapter and engine code. Only the network transport is
substituted, and real Phase 1 captures are loaded from `evidence/raw/` rather
than recreated. Synthetic fixtures live in `tests/fixtures/synthetic/` and are
labelled as such.

The guard tests make no network calls at all: the controls, the authorization
authority, the replay store, the audit log, the monitor, the reference signer and
the API are all the real code. The one substitution is the executor, which is the
real `SimulatedExecutor` with a call counter — so "the signer refused" is asserted
as "the executor was never called". Coverage includes valid authorization, an
unapproved destination, amount limits, velocity and window-volume limits, an
unauthorized service identity, an expired authorization, replay, parameter
substitution, a missing authorization, a bad signature, a token from an untrusted
key, an edited token, a token bound to another service, signer enforcement, audit
records and chain verification, incident creation and resolution, provider and
RPC failure handling on the settlement side, and the end-to-end vertical slice
for both the permitted and the refused path.

The NEAR tests make no network calls and broadcast nothing. They exercise the
real policy parser, the real access-key analyser, the real wrapper, the real
guard controls, the real signer and the real API. Coverage includes: a policy
that is signed but not applied (never in force), a frozen agent, a disabled
action, a destination outside the policy list, the native scope gap (both when
the switch is off and on), an unreadable policy (`HOLD` for native, review for
Intents), a function-call key that cannot transfer NEAR, a full-access key that
forces review, the five outcomes, determinism, an invalid amount failing safe to
`UNKNOWN`, a client-supplied approval flag never honoured, and the settlement
assurance rule that a provider success claim is never independently verified
without decisive evidence. Each of the fifteen NEAR-specific invariants is mutation-tested.

## Read-only guarantee

TRACESETTLE cannot recover, reverse, freeze, or move funds. It cannot report a
refund or a delivery without verifiable on-chain evidence. When the evidence is
insufficient it says so and returns an explicit unknown.

The security layer adds one honest boundary to that guarantee. TRACESETTLE
cannot stop an arbitrary blockchain transaction. It can refuse to release a
transaction through a signer that calls it, explain why, record the attempt, and
verify the settlement afterward. Enforcement requires the signer to call the
boundary; the reference signer shows what that looks like, and it simulates
execution rather than signing anything.

## Hackathon submission

- **Track: `security` (AI Security & Defense).** The track's own hint is "spending
  limits, policy engines, sandboxed wallets... give AI money without giving it the
  keys to everything", which is precisely what the Transaction Guard, the
  Authorization Firewall, and the NEAR agent authorization wrapper are. A secondary
  `defi` track could be claimed through the NEAR Intents settlement verification,
  but the primary contribution is security.
- **The NEAR integration.** An agent-side authorization wrapper for the NEAR
  Intents Agent API: it reads the agent policy and its real enforcement scope, the
  NEAR access-key scope, and returns `ALLOW` / `REQUIRE_APPROVAL` / `BLOCK` /
  `HOLD` / `UNKNOWN` on the **actual** transaction parameters. Nine deterministic
  attack scenarios prove the boundary refuses. See
  [`docs/NEAR_INTEGRATION.md`](docs/NEAR_INTEGRATION.md). Verifiable execution (TEE)
  is researched and deliberately not integrated: see
  [`docs/TEE_RESEARCH.md`](docs/TEE_RESEARCH.md).
- **No artificial AI.** No LLM is used, and none was added to qualify for an AI
  category. Every decision is a deterministic, testable rule; the whole point is
  that a model must not be able to talk its way past the boundary.
- **Zero budget.** No paid service, no account, no transaction. The runtime is
  standard-library only and every external source is public and read-only.
- **Deadline: 2026-11-14T23:59:00Z.** The repository must be public by then; the
  submission is a single form POST and cannot be edited afterward.
- **Not yet done:** making the repository public, posting the demo on X, and sending
  the submission. All three require explicit human confirmation.
