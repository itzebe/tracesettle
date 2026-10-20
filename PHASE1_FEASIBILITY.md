# TRACESETTLE — Phase 1: Feasibility and API Verification

**Status:** complete. All findings below were verified against live endpoints on **2026-10-19** (UTC).
**Scope of this document:** feasibility only. No application code is implemented yet.

Every claim is tagged with the evidence that supports it. Evidence artefacts are stored verbatim in
[`evidence/raw/`](evidence/raw/). Where something could **not** be verified, it is marked
`UNVERIFIED` or `LIMITATION` rather than assumed.

---

## 0. Executive summary

| Question | Answer |
| --- | --- |
| Is there a documented, read-only way to retrieve NEAR Intents settlement status? | **Yes.** `GET https://1click.chaindefuser.com/v0/status?depositAddress=…` |
| Does it require a paid API key? | **No.** It answered with no `Authorization`/`X-API-Key` header, returning `200` and a fully populated `SUCCESS` record. |
| Can the whole pipeline (source tx → deposit → settlement → destination tx → refund) be reconstructed for one path? | **Yes, for the EVM `ORIGIN_CHAIN` swap path**, using one status call plus free public chain RPCs. |
| Is there a single reliable correlation key? | **Yes — the quote `depositAddress`.** It is the join key across the 1Click API, the public Explorer URL, and the origin-chain deposit tx. |
| Can settlement be independently verified rather than trusted? | **Yes.** The intent hash is embedded in `intents.near` NEAR-transaction logs and in the public solver relay; the NEAR tx and both EVM receipts can be re-fetched from public RPCs. |
| Is anything blocking a viable Phase 2? | **No blocker.** There are honest limitations (below), but a testable, supported scope exists. |

**Smallest viable scope:** a read-only investigation tool for the **1Click `ORIGIN_CHAIN` swap** on an
**EVM origin → EVM destination** corridor (verified instance: **ETH → USDC on Ethereum**), keyed on a
**deposit address**, with independent on-chain verification of the origin and destination legs.

---

## 1. The official `HACKATHON.md`

The hackathon ships an agent-facing instruction file. It is served live at
`https://nearhackathon.com/HACKATHON.md` and is also linked from the site root (`href="/HACKATHON.md"`).
It was fetched and stored verbatim at [`evidence/raw/HACKATHON.md`](evidence/raw/HACKATHON.md).

Key facts (quoted from the file):

- **Event:** NEAR HACKATHON. **Website:** `https://nearhackathon.com`.
- **Hackathon starts:** `2026-11-01T00:00:00Z`. **Development ends / submission deadline:** `2026-11-14T23:59:00Z`.
- **Judging starts:** `2026-11-16T00:00:00Z`. **Results announced by:** `2026-11-18T23:59:00Z`.
- Submission: one per team, `POST https://nearhackathon.com/api/applications` with a fixed JSON contract.
- The repository must be **public** by the deadline; a **public demo post on X** is required.
- Judging includes AI judges: *"write the README for a machine reader as well as a human one: what the
  product is, the problem it solves, and how to try it as 'do X - see Y' steps a judge can follow. No marketing."*
- Tracks are declared as ids in the submission. The track most relevant to TRACESETTLE is
  **`security` — "AI Security & Defense"** (spending limits, policy engines, reputation and scam detection).
  Secondary fits: **`thesis`** (onchain analytics, live dashboards, evidence-based) and
  **`defi`** / **`realworld`** (settlement rails).
- Constraints that bind this project: *"Sign transactions, spend tokens or deploy to mainnet"* and
  *"Commit secrets"* are on the **never-without-human-confirmation** list. This aligns exactly with the
  TRACESETTLE objective of a read-only, non-signing tool.

**Consequence for Phase 2:** the deliverable must include a README written for both a machine reader and a
human, runnable "do X → see Y" steps, a public repo, and a demo. Nothing in `HACKATHON.md` requires writes,
signing, or mainnet deployment for the product itself.

---

## 2. Documented intent-status API (1Click Swap API)

### 2.1 Endpoint and request schema

Source: official docs `api-reference/oneclick/check-swap-execution-status`, whose OpenAPI block is embedded
from `https://1click.chaindefuser.com/docs/v0/openapi.yaml` (downloaded, 1.9 MB, stored at
[`evidence/raw/oneclick_openapi.yaml`](evidence/raw/oneclick_openapi.yaml)).

```
GET https://1click.chaindefuser.com/v0/status
```

| Parameter | In | Required | Type |
| --- | --- | --- | --- |
| `depositAddress` | query | yes | string |
| `depositMemo` | query | no (required only when the quote returned a memo) | string |

`depositAddress` is **not an arbitrary transaction hash**. It is the unique deposit address issued by the
quote response. The docs are explicit: *"Retrieves the current status of a swap using the unique deposit
address from the quote."* (This matches prior art's warning: *"Status — read-only, keyed on the quote's
`depositAddress`, not an arbitrary hash."*)

### 2.2 Response schema

Documented `GetExecutionStatusResponse`: `correlationId`, `quoteResponse` (full `QuoteResponse`),
`status` (enum), `updatedAt`, `swapDetails` (`SwapDetails`). Required: all five.

`SwapDetails` fields documented: `intentHashes[]`, `nearTxHashes[]`, `amountIn`, `amountInFormatted`,
`amountInUsd`, `amountOut`, `amountOutFormatted`, `amountOutUsd`, `slippage`, `originChainTxHashes[]`
(`{hash, explorerUrl}`), `destinationChainTxHashes[]` (`{hash, explorerUrl}`), `refundedAmount`,
`refundedAmountFormatted`, `refundedAmountUsd`, `refundReason`, `depositedAmount`,
`depositedAmountFormatted`, `depositedAmountUsd`, `withdrawFee`, `referral`.

**Live verification (not just the docs).** A real, completed swap was retrieved with no auth header:

- Request: `GET /v0/status?depositAddress=0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B` → HTTP `200`.
- Raw response: [`evidence/raw/oneclick_status_SUCCESS.json`](evidence/raw/oneclick_status_SUCCESS.json).
- Observed values include `status: "SUCCESS"`, `intentHashes: ["7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG"]`,
  `nearTxHashes: ["FbrSoTHbQdwD6HxabhaozvQQVBA4kF2Qn2c3W2otp284", "5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb"]`,
  `originChainTxHashes[0].hash = 0xfca11aa0…01d2`, `destinationChainTxHashes[0].hash = 0x91cd1ede…f3f3`.

Note a real schema detail the docs do not state: in this live response `originChainTxHashes[].explorerUrl`
and `destinationChainTxHashes[].explorerUrl` were returned as **empty strings**, and several amount fields
were `null` before funding. The engine must treat `explorerUrl` as *present but possibly empty* and must not
assume non-null amounts.

**Dry vs. wet quote (verified).** `POST /v0/quote` with `"dry": true` returned `201` with
`quote`/`quoteRequest`/`signature`/`timestamp`/`correlationId` and **no `depositAddress`**
([`evidence/raw/oneclick_quote_response.json`](evidence/raw/oneclick_quote_response.json)) — matching the
documented rule that `dry: true` omits `depositAddress`, `timeWhenInactive`, and `deadline`. A `dry: false`
call returned a `depositAddress` and `deadline`. Therefore a **deposit address only exists after a live
(non-dry) quote**, which is why the investigation tool's primary input is a deposit address supplied by the
user rather than something the tool can synthesise for an arbitrary hash.

### 2.3 Supported statuses

**1Click `/v0/status`** (from the OpenAPI enum, and confirmed in the quickstart):

`PENDING_DEPOSIT`, `KNOWN_DEPOSIT_TX`, `INCOMPLETE_DEPOSIT`, `PROCESSING`, `SUCCESS`, `REFUNDED`, `FAILED`.

**Message-bus `get_status`** (a different, solver-facing surface) uses a different, smaller enum:
`PENDING`, `TX_BROADCASTED`, `SETTLED`, `NOT_FOUND_OR_NOT_VALID`.

These are two distinct status vocabularies for two distinct identifiers. **The engine must not merge them.**
This is a primary source of "contradictory evidence" the reconciliation engine must surface rather than
silently reconcile.

### 2.4 Authentication — what was actually observed

This matters because the objective forbids paid dependencies without justification.

| Test | Result |
| --- | --- |
| `GET /v0/status` with **no** auth header, unknown address | `404` (`Deposit address … not found`) |
| `GET /v0/status` with a **bogus** `X-API-Key` | `401` |
| `GET /v0/status` with a **bogus** `Authorization: Bearer` | `401` |
| `GET /v0/status` with **no** auth, a **real** address | `200` with full body |
| `GET /v0/tokens` with no auth | `200` |

**Finding:** the OpenAPI marks `/v0/status` as requiring `X-API-Key` **or** `JWT-auth`, but in practice an
*absent* credential is accepted and only an *invalid* credential is rejected with `401`. The endpoint is
therefore usable for a free, read-only tool. **This is an observed behaviour, not a documented guarantee**,
and the code must degrade gracefully (treat `401` as `UNAVAILABLE`, never crash) in case the operator
changes it. Rate-limit headers confirm a public unauthenticated budget:

```
x-ratelimit-limit-unauth: 1200
x-ratelimit-remaining-unauth: 1199
x-ratelimit-reset-unauth: 60
```

### 2.5 Documented / observed limitations

1. **Identifier is the deposit address, not a hash.** You cannot look up an intent hash or a tx hash on this
   endpoint. The docs' own examples use `depositAddress=your-deposit-address`.
2. **`404` means "no such deposit address", not "the swap failed."** Observed directly. The engine must map
   `404` to `NOT_FOUND`, never to `FAILED`.
3. **The public Explorer JSON API is gated.** `GET https://explorer.near-intents.org/api/v0/transactions`
   returned `400 {"error":{"code":"MISSING_TOKEN"}}` with no auth. Its OpenAPI (`exp_openapi.yaml`) declares
   both paths as `bearerAuth`-secured. The token comes from the **Partner Dashboard**, so this source is
   **not** free/self-serve and is out of scope.
4. **The Explorer *website* is JS-rendered and not a data API.** `curl` of a transaction page returned the
   Next.js shell; the per-transaction record loads client-side. It is still useful as a human-facing
   **evidence URL**, but not as a machine data source.
5. **`CONFIDENTIAL_INTENTS` paths are not publicly queryable.** Prior art states a confidential quote
   returns `401` without partner auth. `UNVERIFIED` here (not exercised), and out of scope.
6. **The `1Click` rate limit** for authenticated partners is documented as 1 request / 5 s; the observed
   unauthenticated budget is 1200 / 60 s. Both require backoff handling.

---

## 3. Stage-by-stage retrieval for one supported path

**Chosen path:** 1Click swap with `depositType: ORIGIN_CHAIN` and `recipientType: DESTINATION_CHAIN`, on an
**EVM origin chain → EVM destination chain** corridor. The verified example is
**Ethereum (ETH native) → Ethereum USDC**, `referral: "swapkit"`, which settled `SUCCESS`.

Stages:

```
1. Source tx        user sends origin asset to depositAddress on the origin chain
2. Deposit observed 1Click records the deposit (depositedAmount)
3. Settlement       intents.near executes execute_intents → token_diff / ft_withdraw events
4. Destination tx   solver withdraws the destination asset to recipient
5. Refund (cond.)   if the swap cannot execute, origin asset returns to refundTo
```

| Stage | Authoritative source | How to retrieve | Verified |
| --- | --- | --- | --- |
| Source tx | Origin-chain RPC (public) | `eth_getTransactionReceipt(originChainTxHashes[].hash)` | **Yes** — `0xfca11a…01d2` returned `status: 0x1` |
| Deposit observed | 1Click `/v0/status` | `swapDetails.depositedAmount` + `originChainTxHashes[]` | **Yes** — `depositedAmount = 145.987303918706045` |
| Settlement | `intents.near` on NEAR | NEAR RPC `tx` by `nearTxHashes[]`; intent hash appears in `EVENT_JSON` logs | **Yes** — intent hash found in 4 DIP-4 log events |
| Destination tx | Destination-chain RPC (public) | `eth_getTransactionReceipt(destinationChainTxHashes[].hash)` | **Yes** — `0x91cd1e…f3f3` returned `status: 0x1`, `to = 0xa0b8…eb48` (USDC) |
| Refund | 1Click `/v0/status` | `swapDetails.refundedAmount` / `refundReason` | Partially — `refundedAmount: "0"` observed on both a `PENDING_DEPOSIT` and a `SUCCESS` record; no `REFUNDED` sample captured |

### 3.1 Independent verification — the key result

The engine does **not** have to trust 1Click. Three independent cross-checks were demonstrated:

1. **NEAR RPC** (`https://free.rpc.fastnear.com`, no key) — `tx` by hash with `sender_account_id: intents.near`:
   - `FbrSoTHb…p284` → `final_execution_status: FINAL`, signer `bridge-mng.near`, receiver `omft.near`.
   - `5E3Gdbhw…ypFb` → `final_execution_status: FINAL`, signer/receiver `intents.near`.
2. **Intent hash present on-chain.** The `intents.near` receipt logs contain
   `EVENT_JSON:{"standard":"dip4","version":"0.4.3","event":"token_diff",…,"intent_hash":"7ypUiXpj…94dG",…}`
   (also `transfer` and `ft_withdraw` events). This lets the tool verify that the *specific* intent the
   status API named was actually executed, rather than trusting the API's own claim.
3. **Public solver relay** (`POST https://solver-relay-v2.chaindefuser.com/rpc`, no key):
   ```json
   {"result":{"intent_hash":"7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG","status":"SETTLED",
              "data":{"hash":"5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb"},
              "filled_amounts":{"nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near":"347350380510"}}}
   ```
   This `data.hash` matches one of the `nearTxHashes` from 1Click — an independent corroboration.

### 3.2 Other free public surfaces (verified reachable)

- **Bridge RPC** `POST https://bridge.chaindefuser.com/rpc` (no auth): `recent_deposits`,
  `supported_tokens` both responded `201` with valid JSON. Relevant for deposit/withdrawal legs and for
  resolving a deposit address to an `account_id` via `recent_deposits`.
- **NEAR RPC** `https://free.rpc.fastnear.com` and `https://rpc.mainnet.near.org` (no key): `status` → `200`.
- **EVM RPC** `https://ethereum-rpc.publicnode.com` (no key): `eth_getTransactionReceipt` → `200`.

---

## 4. Authoritative data source per stage

| Stage | Authoritative source | Secondary / corroborating source |
| --- | --- | --- |
| Quote & deposit address | 1Click `POST /v0/quote` | — |
| Deposit address → account | Bridge RPC `recent_deposits` | — |
| Source tx | Origin-chain RPC | `originChainTxHashes[].explorerUrl` (human URL) |
| Deposit observed | 1Click `/v0/status` (`depositedAmount`) | Bridge RPC `recent_deposits` |
| Settlement | **`intents.near` on-chain** (NEAR RPC logs) | Solver relay `get_status`; 1Click `intentHashes`/`nearTxHashes` |
| Destination tx | Destination-chain RPC | `destinationChainTxHashes[].explorerUrl` |
| Refund | 1Click `/v0/status` (`refundedAmount`, `refundReason`) | Origin-chain RPC (verify the refund tx) |

**Principle for the engine:** 1Click is the *discovery* layer (it names the hashes); the chain RPCs are the
*authority* layer (they confirm the events happened). The engine must label evidence from the former as
`REPORTED` and evidence from the latter as `CONFIRMED`.

---

## 5. Correlation identifiers

| Identifier | Correlates | Reliable? | Evidence |
| --- | --- | --- | --- |
| **`depositAddress`** | quote → status → explorer URL → origin deposit tx | **Yes — primary key** | Live status lookup succeeded on it; Explorer URL is `/transactions/<depositAddress>` |
| `correlationId` | one 1Click request/response | Yes, but per-request; changes between calls | Observed different values per call |
| `intentHashes[]` | 1Click → solver relay → NEAR logs | **Yes** | Same hash found in all three |
| `nearTxHashes[]` | 1Click → NEAR RPC | **Yes** | Both hashes resolved `FINAL` |
| `originChainTxHashes[].hash` | 1Click → origin-chain RPC | **Yes** | Receipt `status 0x1` |
| `destinationChainTxHashes[].hash` | 1Click → destination-chain RPC | **Yes** | Receipt `status 0x1` |
| `quoteResponse.signature` | quote authenticity | Yes, but **requires a public key to verify** — `UNVERIFIED` | Field is documented as an Ed25519 signature; no public key located yet |
| amounts / timestamps | (candidate correlation) | **NO — must not be used** | Two unrelated swaps can share an amount; this is explicitly forbidden by the brief |

**Correlation rule adopted:** link stages **only** through explicit identifiers returned by an authoritative
source. **Never** infer a relationship from amount or timestamp similarity.

### 5.1 Honest gaps

- A **deposit address cannot be derived** from a NEAR account, an intent hash, or a tx hash. Without the
  deposit address (or the `account_id` for the bridge lookup), the walk stops. The tool must say this
  plainly instead of guessing.
- **The status API has no reverse lookup by intent hash.** If a user supplies only an intent hash, the tool
  can still query the **solver relay** by that hash, but cannot reach the 1Click status record.

---

## 6. Prior art (inspection of existing public tools)

| Project | What it does | Relation to TRACESETTLE |
| --- | --- | --- |
| [`shreyaspadmakiran-defuse/intent-triager`](https://github.com/shreyaspadmakiran-defuse/intent-triager) | A Claude Code **skill** that triages a NEAR Intents swap from one identifier using **only public APIs**; walks deposit → pick-up → settlement → delivery; flags user-side mistakes; sanctions screen; prints a structured summary + plain brief | **Closest equivalent.** Confirms the exact surfaces found here (1Click status keyed by `depositAddress`, bridge RPC, solver relay, public explorers). It is prompt-driven, not a deterministic engine, and it is not a web app with a reconciliation model. |
| [`ysavchenko/near-intents-explorer`](https://github.com/ysavchenko/near-intents-explorer) | Continuously-running Go indexer + Postgres + SPA for **swap statistics** (solver edge in bps) | Requires **Postgres + a long-running indexer + backfill-from-head**; different goal (market analytics, not per-transaction investigation). |
| [`defuse-protocol/rust-near-indexer`](https://github.com/defuse-protocol/rust-near-indexer) | Rust indexer → ClickHouse, parses `execute_intents` events | Requires **ClickHouse + Redis**; heavy infra, out of scope for a solo read-only tool. |
| NEAR Intents **Explorer** (`explorer.near-intents.org`) | Human-facing swap explorer | JS-rendered; JSON API is partner-gated (`MISSING_TOKEN`). Usable only as an evidence URL. |

**Conclusion:** no existing free tool performs *deterministic, evidence-classified cross-stage reconciliation
with an explicit unknown/contradictory state machine*. That is the gap TRACESETTLE fills. The prior art also
validates the endpoint choices and warns about the same failure modes (deposit address vs tx hash confusion,
refund semantics, `NOT_FOUND` ≠ failure).

---

## 7. Features implementable without paid APIs or paid infrastructure

**Free (verified):**

- Quote inspection via `POST /v0/quote` with `dry: true` (read-only) and, where needed, a live quote to obtain
  a deposit address.
- Intent/swap status via `GET /v0/status?depositAddress=…`.
- Independent NEAR verification via a free NEAR RPC (`free.rpc.fastnear.com`).
- Independent EVM verification via a free EVM RPC (`ethereum-rpc.publicnode.com`).
- Intent settlement cross-check via the public solver relay.
- Bridge deposit/withdrawal lookups via the public bridge RPC.
- Human evidence URLs to `explorer.near-intents.org` and chain explorers.
- Hosting: static/SSR app on a free tier; **no database required** for the core feature.

**Not free / out of scope:**

- Explorer JSON API (`/api/v0/transactions`) — partner JWT.
- `CONFIDENTIAL_INTENTS` quotes — partner auth.
- Any high-volume indexer requiring Postgres/ClickHouse.

---

## 8. Proposed smallest viable scope for Phase 2

**Supported input:** a **deposit address** (the quote's `depositAddress`). Optionally an origin-chain tx hash
or an intent hash, with an explicit, honest message about what each can and cannot resolve.

**Supported path:** 1Click `ORIGIN_CHAIN` swap, **EVM origin → EVM destination** (verified: Ethereum → USDC).
Other corridors (UTXO, TON, Solana, …) are rendered generically but their destination receipts are
`UNAVAILABLE` unless a matching public RPC is configured — reported honestly, never faked.

**Core loop:** resolve identifier → fetch 1Click status → fetch solver-relay status by each `intentHash` →
fetch NEAR tx(s) → fetch origin/destination chain receipts → normalize into evidence items → run the
deterministic reconciliation rules → render a chronological, classified report with export.

**Explicit non-goals** (per the brief): no signing, no transaction execution, no custody, no swap UI, no
bridge, no trading bot, no token, no AI chatbot, no automated recovery, no fabricated data.

---

## 9. Limitations and risks carried into Phase 2

1. **Unauthenticated `/v0/status` is observed behaviour, not a contract.** Code must treat `401` as
   `UNAVAILABLE` and keep working. (Mitigation: graceful degradation; clearly label unavailable evidence.)
2. **No reverse lookup by intent hash on 1Click.** Mitigation: solver relay covers intent-hash input; state
   the boundary explicitly in the UI.
3. **Destination receipts require a per-chain public RPC.** Mitigation: a small RPC map; unknown chains →
   `UNAVAILABLE` (never `FAILED`).
4. **No `REFUNDED` sample was captured**, so refund-field behaviour is only documented + partially observed.
   Mitigation: implement refund handling from the schema, and make the "refund without evidence" test the
   gate that keeps the engine honest.
5. **`explorerUrl` may be empty** even for confirmed legs. Mitigation: build evidence URLs from a known
   template when the API omits them, and label them as constructed.
6. **`quoteResponse.signature` verification is `UNVERIFIED`** (no public key located). Mitigation: record the
   signature as evidence, mark its verification method `UNVERIFIED`, and do not claim authenticity.
7. **Rate limits** (1200/60 s unauth; 1/5 s partner). Mitigation: request timeouts, bounded retries with
   backoff, and a small response cache.
8. **Bitcoin refund correlation is not always possible from free data (found in Phase 4).** 1Click exposes
   no refund transaction hash for a Bitcoin origin. The only free way to find the payout is the refund
   address's own history, but a real refund address had **four** confirmed payouts to it
   (`evidence/raw/btc_address_history.json`). With no explicit identifier tying one to the intent, the
   refund stays `UNAVAILABLE` (`AMBIGUOUS_REFUND_PAYOUT`) rather than being guessed. A refund is confirmed
   only when exactly one payout matches, or when the provider names the transaction. The Explorer API's
   `bearerAuth` (partner-gated) is the only known source that could disambiguate, and it is out of scope.
   *(Update 2026-10-19: the provider later began naming the refund transaction in `originChainTxHashes`,
   so the explicit-identifier path now confirms this refund. The limitation above still holds whenever the
   provider names nothing. See the addendum in `docs/REFUND_VERIFICATION.md`.)*

---

## 10. Phase 1 conclusion

The feasibility question is **answered positively**: a free, read-only, independently-verifiable
cross-stage settlement investigation is possible today for the EVM `ORIGIN_CHAIN` swap path, keyed on the
deposit address, with `intents.near` on-chain logs as the settlement authority. The limitations above are
real but are exactly the kind the evidence model is designed to represent as `MISSING` / `UNAVAILABLE` /
`CONTRADICTORY` rather than to hide.

**Next concrete step:** Phase 2 — scaffold the application (transaction lookup → adapters → normalization →
reconciliation → report → UI → tests), implementing the reconciliation engine and its test suite first so
the "no refund/delivery claim without evidence" invariant is enforced from the start.
