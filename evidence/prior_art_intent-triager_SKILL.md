---
name: intent-triager
description: Triage a NEAR Intents / Defuse swap, cross-chain deposit, or withdrawal from an identifier (explorer link, account_id, tx hash, deposit address, or intent hash) — including a third-party aggregator link (LiFi, Rango, Socket, etc.) if the underlying route touched Defuse — using ONLY public APIs and chain explorers — no repo access, no prod/DB access needed. Walks the pipeline stage by stage, pinpoints the first missing step, screens the relevant address for sanctions risk, and reports back a structured summary plus a plain-language brief of what happened. Use when someone outside the codebase hands you a link/tx/account and asks "where is my swap/deposit", "what happened to this tx", or "is this stuck".
---

# Intent Triager

Portable triage skill for the Defuse / NEAR Intents pipeline. Everything it uses is a **public, unauthenticated (or freely-keyed) HTTP surface** — no source code, database, or internal infra access required. Anyone can run this with just curl.

Input: one identifier. Output: **(1)** how far the flow got, **(2)** the first missing step (if any), **(3)** a sanctions/risk screen where relevant, **(4)** a short structured + plain-language report.

## Step 0 — Work out what you're holding

| You have | It points at | Do |
|---|---|---|
| `explorer.near-intents.org/...` link | An intent / NEAR settlement | Pull the intent hash or account_id from the URL → check settlement, then walk backward if empty |
| `nearblocks.io/txns/<hash>` link | A NEAR tx (settlement or deposit call) | Confirms on-NEAR activity |
| Etherscan / Tronscan / Solscan / mempool.space link | A **source-chain deposit tx** | Read the transfer: `to` address (= deposit address), asset, amount |
| `account_id` + tx hash | The account and one on-chain event | Best case — run the full walk below |
| Deposit address only (`0x…`, `T…`, `bc1…`, a NEAR account) | Where funds were sent | Can't reverse-lookup address → account over public APIs. Confirm on-chain first, then **ask the user for their account_id** |

**If you don't have an account_id and the check needs one (bridge `recent_deposits`, `deposit_address`), ask for it before guessing.** One missing correlation key collapses a four-stage search into one lookup.

⚠️ **Deposit address ≠ tx hash.** These get pasted into the wrong field constantly (looks alike on TRON/UTXO addresses). If a "hash" doesn't resolve on the chain explorer, it's probably an address — treat it as the destination and go find the real tx.

## Step 0b — Third-party aggregator links (LiFi, Rango, Socket, etc.)

Some links aren't native to Defuse at all — they're multi-bridge aggregators (LiFi, Rango, Socket/Bungee, and others) that route through many possible bridges, of which Defuse/NEAR Intents may or may not be one. Don't assume the identifier resolves against this skill's toolbox — extract the underlying leg first, then check whether it actually touched Defuse.

1. **Recognize the aggregator** from the link's domain. Known ones with a documented public status API: `li.fi`/`scan.li.fi`/`jumper.exchange` (LiFi), `app.rango.exchange`/`explorer.rango.exchange` (Rango), `socketscan.io`/`bungee.exchange` (Socket). Pull whatever id it carries in the URL — a tx hash, or the aggregator's own `requestId`/tracking id.
2. **For a known aggregator, hit its own public status API** to get the underlying source/destination tx hashes and which bridge/tool it actually used (e.g. LiFi's is `GET https://li.quest/v1/status?txHash=<hash>`, keyed off the source tx hash). Some now gate parts of their API behind a free key — check the aggregator's current docs before assuming a call is fully open, rather than trusting a hardcoded example.
3. **For an aggregator not on that list**, don't guess an API shape. Instead: (a) check if the URL itself already carries a plain tx hash or source-chain address as a query param (`?tx=`, `?txHash=`, `?hash=`) — usable directly regardless of which aggregator it is; (b) if not, try fetching the page once — some trackers do server-render the tx hash even if the aggregator is unfamiliar; (c) if that doesn't surface it, **ask the user for the underlying source-chain tx hash** directly. Never invent an endpoint for an aggregator you don't actually know, and never scrape/guess your way to a number you'll report as fact.
4. **Whichever path got you the underlying tx, check the bridge/tool field in that data (or, absent that, check the tx itself on-chain) for whether it actually touched Defuse** (destination lands on `intents.near`, an `…omft.near` asset, or a known Defuse deposit/custody address). Only then switch into this skill's normal Step 2 walk. If it names or shows a different bridge (CCTP, Wormhole, Stargate, etc.), **say that plainly and stop** — none of the endpoints in this skill's toolbox will have a record of it, and continuing would just be guessing under a Defuse-shaped answer that doesn't apply.

## Step 1 — Identify the product

Two different things share the words "deposit address" and "sweep":

| | **Swap (1Click / Intents)** | **Bridge funding (no swap)** |
|---|---|---|
| Purpose | deposit asset A → receive asset B | bring external funds onto NEAR as `omft`, no swap |
| Deposit address tied to | a quote / intent | a `(account_id, chain)` pair |
| Has a `quote_id` + two assets (from/to)? | yes | no |

If there's no swap, no target asset, just "funding near.com" or an `…omft.near` balance appearing — it's bridge funding. Treat it as starting at Step 2 below with no upstream quote to check.

**A third shape exists: a direct router-to-intents call, with no deposit address at all.** Both shapes above create a discrete deposit address first, then wait for a separate transfer into it. Some aggregator-initiated routes (see Step 0b) skip that entirely — the router contract calls straight into the Defuse/near-intents integration *inside the same transaction* that moves the funds. Recognize it by: it came in via an aggregator, the receiving contract's logs/calldata tag the intents integration directly (e.g. a `"near"` tool field, `intents.near` or the router forwarding to a Defuse contract visible in the tx's own logs), and a 1Click `/v0/status?depositAddress=<tx hash>` lookup 404s. **If you're in this shape, there is nothing to trace as "the deposit address" — say that plainly instead of treating it as a failed lookup.** The origin tx itself is the whole deposit event; go straight to the account_id resolution note under Step 2a to find out what happened next.

**Don't stop at "no deposit address" — follow the asset's own Transfer trail, it usually reveals an ephemeral one anyway.** There's no *pre-existing, wait-for-it* deposit address in this shape (no address generated ahead of time that the funds are sent to and then sit at) — that part is correct. But the funds still have to land *somewhere* on-chain before they cross into Defuse's system, and that landing spot is almost always discoverable, generically, by reading the transaction's own Transfer logs (ERC-20 `Transfer` events, or native-value transfers) in order, right through to wherever the asset actually ends up — not stopping at the first router/aggregator contract in the call.

Concretely, check the address that log trail lands on:
- **`eth_getCode` on it** — if it comes back `0x`, it's an EOA, not a contract.
- **Its outgoing nonce/tx count** — if it's very low (often exactly `1`), it exists to receive once and immediately move the funds onward, not to hold a running balance.
- **How fast and how much it forwards** — a same/near-identical amount moving out within a few blocks of receiving it is a sweep, not coincidence.

An EOA matching that profile **is** functioning as a deposit address — just an ephemeral, single-use one created and swept within one tight sequence, instead of the "generate it, then wait" model. Report it as such, not as "nothing to trace." It's still not a stable, reusable address you can point the user back to next time (a fresh one gets minted per call), but for *this* triage it's real and worth naming.

Two more things worth noting once you find it: **where it forwards to** (follow one more hop — that's often the actual shared custody/intake point, and if you can gather enough of these across unrelated transactions, look for the same "many senders → one destination" pattern the Toolbox's custody test already describes, just one hop further down the chain than usual), and **whether the destination addresses share a distinctive pattern** (e.g. a common prefix, suggesting a deterministic/vanity deployment scheme) — that's a lead worth flagging as an observation, not a confirmed fact, since one example alone doesn't prove it's Defuse-controlled infrastructure rather than the aggregator's own.

## Step 2 — Walk the pipeline, stop at the first NO

Four plain-English milestones, each with its technical check behind it. **Always report progress using the milestone name, never the bare number** — "money sent" means something to a human, "stage 1" doesn't.

```
 Milestone 1        Milestone 2        Milestone 3        Milestone 4
 MONEY SENT    →    PICKED UP     →    SETTLED       →    DELIVERED
 (landed at the     (bridge saw it     (intent executed    (funds arrived
  deposit address)   + credited it     on intents.near)    at the final
                      on NEAR)                              destination)
```
A **pure Intents swap** (funds already in the user's `intents.near` balance) starts at milestone 3 — there's no milestone 1/2 to check. A **cross-chain deposit/swap** starts at milestone 1.

**Milestone 1 — MONEY SENT.** Did the deposit land on-chain? Open the source-chain explorer. Confirm the transfer hit the deposit address, right asset, right amount, enough confirmations.
- NO → user hasn't sent, wrong address, or underpaid (underpaid → expect a partial refund, not a credit).
- YES → check milestone 2.

**Milestone 2 — PICKED UP.** Did the bridge observe + credit it? (cross-chain only) Call `recent_deposits` on the public Bridge RPC, keyed by `account_id`. Also compare the **canonical** `deposit_address` for `(account_id, chain)` against the address the user actually used.
- **Empty result** → no row at all → never observed (detection gap), OR the address is registered under a **different account_id**. Check on-chain whether funds were **swept** into a shared custody address (many deposit addresses feeding one destination) — if so, the bridge did process it and funds are safe, just filed under another account. Lever: `notify_deposit` (see below).
- **Row present, pre-credited, not swept** → funds are still sitting at the deposit address; the credit step hasn't run yet. This can take a little time — re-check before escalating.
- **Row `CREDITED`/`COMPLETED`** (has `mint_tx_hash`) → credited on NEAR → check milestone 3. One tx can produce several rows (retries) — take the latest/terminal one, ignore earlier `FAILED` rows.

**Milestone 3 — SETTLED.** Did the intent settle on `intents.near`? Check the Intents Explorer / NEAR explorer, or `GET /v0/status` on the 1Click API (keyed by the quote's `depositAddress`).
- Status reads `PROCESSING` → funds credited, execution in flight (no solver fill yet, or still broadcasting). Give it a little time.
- Status reads `SUCCESS` → check milestone 4 (if a withdrawal was expected).
- Status reads `REFUNDED` → quote expired / no liquidity — expected, not a bug.
- Status reads `FAILED` / `FAILED_EXECUTION` → execution failed on-chain.
- Status reads `KYT_BLOCKED` → flagged by risk screening — run the sanctions check in Step 3.
- Nothing shows on the explorer at all and milestone 2 wasn't `CREDITED` yet → expected, nothing exists on NEAR pre-credit.

**Milestone 4 — DELIVERED.** Did the withdrawal arrive on the destination chain? `withdrawal_status` on the Bridge RPC (or the NearOne Omni transfer API for BTC/nBTC legs) + the destination-chain explorer.
- NO → payout leg stuck (gas, finalizer lag). Settlement itself is fine.
- YES → flow completed. If the user still sees nothing, it's likely explorer/history lag, not the pipeline.

## Step 2a — Is this actually a wrong deposit?

Before concluding "stuck" or "missing step," check whether the on-chain trail shows a **user-side mistake** instead. This looks identical to "hasn't been picked up yet" from the outside, but the fix is completely different — there's nothing on Defuse's end to unstick, and no amount of waiting resolves it. Be the advisor here, not just the reporter: catch it, name it plainly, and tell the user what to actually do next.

Check the deposit address + its on-chain trail against these, in roughly this order:

1. **Wrong asset.** A deposit address (or a quote's `depositType`) is bound to one specific asset. Decode what actually landed (chain explorer / token transfer) and compare it to what was expected. Different token → it was never going to be recognized as fulfilling anything, no matter how long they wait.
2. **Wrong chain.** Any EVM address looks identical across every EVM chain. If the expected chain's explorer shows nothing, check whether that same address received funds on a *different* chain instead — that confirms a chain mixup, not a detection gap, and changes the advice completely (funds are sitting somewhere real, just not where the system is watching).
3. **Underpaid / overpaid.** Compare the exact landed amount to what was expected. Underpaid → the pipeline is built to refund partials, not credit them, and that's expected behavior, not a bug. Overpaid → the excess typically isn't auto-swapped in; flag it so they don't assume the extra just adds to the trade.
4. **Missing memo/tag.** For memo-requiring chains/paths (XRP, Stellar, TON, some NEAR transfers), check whether the transfer actually included the required tag. No memo → it can look "arrived" on-chain while being functionally unattributable to the account, same practical outcome as sending to the wrong account.
5. **Deposited after the quote's deadline.** For a 1Click swap deposit address, compare the quote's `deadline` to the deposit's actual on-chain timestamp. Late → the terms it was quoted for no longer hold; expect a refund path, not the original swap executing.
6. **Not actually a Defuse address at all.** If the address doesn't match the bridge's own `deposit_address` for that account+chain, and its on-chain history shows no interaction with any known Defuse/bridge contract — say so plainly rather than continuing to search Defuse's systems for something that was never sent there (mistyped address, or copied from an unrelated service).

If you find one of these, **name it and stop treating it as a pipeline fault.** State plainly what happened (e.g. "this deposit address only ever recognizes USDC — the USDT you sent won't progress, regardless of wait time") and give the one concrete next step: usually resend correctly to a *fresh* deposit address/quote (don't reuse the old one if the asset or deadline was the problem), or, if funds landed at a real Defuse-controlled address just misclassified, escalate to support with the exact identifiers rather than telling them to keep waiting.

**No account_id, and the identifier itself isn't NEAR-format** (an EVM/BTC/TRON/etc. address or tx hash): don't try to derive a NEAR `account_id` yourself — there's no public math that turns a non-NEAR address into one, it's a server-side mapping only Defuse holds. Two different lookups can get it, and they are **not the same thing** — don't conflate them:

- **The admin panel** — an internal, authenticated tool, separate from anything public. If you (or whoever's running this triage) has access to it, look up the account_id there using the deposit address, chain name, and tx hash — print all three in full. This is not part of this skill's public toolbox and won't be available to everyone who picks this skill up; only mention it as an option if you actually have that access.
- **The public Intents Explorer** (`https://explorer.near-intents.org`) — no auth needed, but it's JS-rendered: a plain fetch (`curl`, or a fetch-tool that doesn't execute JS) reliably returns the same generic dashboard regardless of query params or URL shape (`?search=`, `?txHash=`, guessed `/api/*` routes all 404 — tried and confirmed), because the real per-transaction result only loads after the page's own client-side JS fires its own API call, which a non-browser fetch never triggers or waits for. Needs an actual browser / browser-automation tool to get a real result.

If neither is available to you, just ask the user for their NEAR account_id directly.

## Step 2b — Where's the money?

This is the actual question a user cares about. Answer it in one plain sentence, not a technical trail:

**Is the money still sitting at the deposit address, or has it moved on — and if it moved, where is it now?**

- Check the deposit address's balance/history on the source-chain explorer. Still there, in full → **it hasn't moved, it's waiting at the deposit address.** Say that plainly (and whether that's expected/normal-latency or actually stuck).
- If it's gone, follow it just far enough to answer "so where is it": swept toward the bridge (in transit, not credited yet) → credited into the account's NEAR Intents balance → settled/swapped there → sent onward and now at the final destination address. Stop as soon as you can say where it is — you don't need to narrate every intermediate step if you already know the current one.
- Cross-check what you see on-chain against what Defuse's own status says (1Click `/v0/status`, bridge `recent_deposits`/`withdrawal_status`) so it's not a single unverified source. If the two disagree (e.g. the API says done but nothing's shown up on-chain yet, or the reverse), say that plainly — "Defuse's system says X, but on-chain I only see Y so far" — rather than picking one and moving on.

**Fee questions** ("why is `withdrawFee` this number"): don't guess from memory — dry-quote the live 1Click API with the user's exact `depositType`/`recipientType` (see Toolbox). HOT-path assets (TON, some omni tokens) carry a gasless-withdraw fee; confidential unshields (`CONFIDENTIAL_INTENTS` → non-confidential recipient) apply a 2x buffer on top. Same-asset public `INTENTS → DESTINATION_CHAIN` has no such buffer. Only report a number you've confirmed against a live dry-quote response, not a remembered constant.

**"Can this actually be reproduced?" questions** (partner disputes a route/fee/behavior as wrong): a dry quote alone only proves the *pricing math* is consistent — it doesn't prove the scenario is actually executable right now (liquidity, deposit-address issuance, deadline handling). If the user needs that stronger confirmation, run a **wet quote** too (Toolbox) — with confirmation first, since it's a live write — and compare dry vs. wet. Both agreeing is real replication; a mismatch (e.g. wet is worse than dry) usually means liquidity/route conditions shifted between the two calls, which is itself worth reporting.

## Step 3 — Sanctions / risk screen

Run this whenever: the status reads `KYT_BLOCKED`/blocked/delayed, the user asks "is this address flagged", or you're about to advise firing `notify_deposit` / a withdrawal retry and want to rule out a sanctions hit first.

**Chainalysis Sanctions Oracle (public, on-chain, no API key)** — for EVM addresses, call the view function `isSanctioned(address)` on Chainalysis's public oracle contract via any public EVM RPC (`eth_call`). It's deployed across multiple EVM chains; confirm the current contract address for the chain in question from Chainalysis's own docs before calling it, since deployments/addresses can change.
```bash
curl -s https://ethereum-rpc.publicnode.com -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"<ORACLE_CONTRACT_ADDRESS>","data":"0x<isSanctioned-selector+padded-address>"},"latest"]}'
```
For non-EVM addresses, or a richer category/reason than a plain bool, Chainalysis's hosted screening API (`public.chainalysis.com`) needs a free API key — treat as optional/secondary and only use it if the requester already has one; don't ask a public user to sign up mid-triage.

Report the screen result as **clear** / **flagged (sanctioned)** / **not checked (non-EVM, no key available)** — never silently skip it if a block/delay status was involved.

## Toolbox — public surfaces only

### Bridge RPC — `POST https://bridge.chaindefuser.com/rpc`
JSON-RPC 2.0, `params` is a single-element array, no auth. `chain` = `<network>:<chainId>` (`eth:1`, `btc:mainnet`, `tron:mainnet`, `sol:mainnet`, `ton:mainnet`, `aleo:mainnet`, …).
```bash
# canonical deposit address the bridge expects for (account_id, chain)
curl -s -X POST https://bridge.chaindefuser.com/rpc -H 'Content-Type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"deposit_address","params":[{"account_id":"<acct>","chain":"eth:1"}]}'

# recent deposits for an account (omit "chain" for all chains). Rows carry status + mint_tx_hash
curl -s -X POST https://bridge.chaindefuser.com/rpc -H 'Content-Type: application/json' \
  -d '{"id":2,"jsonrpc":"2.0","method":"recent_deposits","params":[{"account_id":"<acct>"}]}'

# withdrawal status
curl -s -X POST https://bridge.chaindefuser.com/rpc -H 'Content-Type: application/json' \
  -d '{"id":3,"jsonrpc":"2.0","method":"withdrawal_status","params":[{"withdrawal_hash":"<hash>"}]}'
```
Other methods: `recent_withdrawals`, `withdrawal_estimate`, `supported_tokens`, `attestation`, `passive_withdrawal_*`.

**Reading `recent_deposits`:** filters only by `account_id` (+ optional `chain`/`status`), returns every status. Empty with no filters ⇒ no row exists at all ⇒ never observed. `total` is hardcoded `0` — ignore it, use the array + `hasMore`. Status progression: `PENDING → CREDITED → COMPLETED`, or `FAILED`.

### 1Click API — `https://1click.chaindefuser.com`
Public quote + status surface for swaps. Two modes — use dry by default, wet only to actually reproduce a scenario:

**Dry quote — read-only, always safe to run.** Verifies fees/routes/pricing without creating anything.
```bash
curl -s -X POST https://1click.chaindefuser.com/v0/quote -H 'Content-Type: application/json' -d '{
  "dry": true, "swapType": "EXACT_INPUT", "slippageTolerance": 100,
  "originAsset": "<ASSET>", "destinationAsset": "<ASSET>", "amount": "<AMOUNT>",
  "depositType": "<THEIRS>", "recipientType": "<THEIRS>",
  "refundTo": "intents.near", "refundType": "INTENTS", "recipient": "<DEST>",
  "deadline": "2026-12-31T00:00:00.000Z", "appFees": []
}'
```

**Wet quote — same body with `"dry": false`.** This is a real write: it mints a live quote and a real deposit address, and starts a countdown to `deadline`. Only fire it when you need to actually **replicate** the user's scenario end-to-end (e.g. confirm a reported fee/route holds up for a real deposit, not just the quoted number) — **confirm with the user first**, same as `notify_deposit`. Never leave it dangling: if you don't intend to fund the returned deposit address, say so, since an unfulfilled live quote just expires at `deadline` with no harm, but it did reserve a real quote slot.
```bash
curl -s -X POST https://1click.chaindefuser.com/v0/quote -H 'Content-Type: application/json' -d '{
  "dry": false, "swapType": "EXACT_INPUT", "slippageTolerance": 100,
  "originAsset": "<ASSET>", "destinationAsset": "<ASSET>", "amount": "<AMOUNT>",
  "depositType": "<THEIRS>", "recipientType": "<THEIRS>",
  "refundTo": "intents.near", "refundType": "INTENTS", "recipient": "<DEST>",
  "deadline": "2026-12-31T00:00:00.000Z", "appFees": []
}'
```
Compare the wet quote's `depositAddress`/fees/route against the dry quote and against what the user reported. A mismatch between dry and wet themselves is itself a signal (e.g. liquidity moved between calls).

**Status — read-only**, keyed on the quote's `depositAddress`, not an arbitrary hash.
```bash
curl -s "https://1click.chaindefuser.com/v0/status?depositAddress=<addr>"
```
`depositType: CONFIDENTIAL_INTENTS` returns 401 without partner auth on either mode — don't guess that shape, say it can't be quoted publicly.

### NearOne Omni Bridge (BTC / nBTC) — `mainnet.api.bridge.nearone.org`
Distinct from the Bridge RPC above and from HOT Omni. Use when the path involves `omni.bridge.near`, `omni-relayer.bridge.near`, `nbtc.bridge.near`, or a BTC txid.
```bash
curl -s "https://mainnet.api.bridge.nearone.org/api/v2/transfers/transfer?transaction_hash=<TX_HASH>"
```
Lifecycle fields: `initialized` → `signed` → `finalised` / `finalised_on_near` / `claimed` (null = not reached yet). One query can return several legs for the same hash — identify the right one by `transfer_message` (NEAR-origin) vs `utxo_transfer` (BTC-origin) direction.

### `notify_deposit` — the one public write (confirm before firing)
Re-feeds a deposit tx to the bridge so it gets (re)processed. Idempotent (dedup'd by tx hash). Use when a deposit landed on-chain but `recent_deposits` came back empty (never ingested).
```bash
curl -s -X POST https://bridge.chaindefuser.com/rpc -H 'Content-Type: application/json' -d '{"id":1,"jsonrpc":"2.0",
 "method":"notify_deposit","params":[{"chain":"tron:mainnet","deposit_address":"<addr>","tx_hash":"<REAL on-chain tx hash>"}]}'
# near/stellar also need near_sender_account / memo
```
- **Always confirm with the user before firing** — it's a real write against production, even though it's idempotent.
- Needs the **real on-chain tx hash**, not the deposit address — get it from the chain explorer yourself.
- Reading the response: `{}` = accepted · `"…already exists"` = no-op, row already there · `"Account was not found for deposit address …"` = no registry record for that address · `"Internal error"` = call it once, don't retry-loop; if it keeps happening this is past what public tools can fix — tell the user to escalate to support with the address + tx hash.

### Chain explorers
| Chain | URL pattern | Look for |
|---|---|---|
| Intents settlement / history | `https://explorer.near-intents.org` | intent hash → settlement record (history can lag) |
| NEAR / `intents.near` | `https://nearblocks.io/txns/<hash>` · `https://nearblocks.io/address/<account_id>` | settlement tx, `ft_transfer_call`, omft mint |
| Ethereum / EVM | `https://etherscan.io/tx/<hash>` (RPC `https://ethereum-rpc.publicnode.com`) | transfer into deposit address; sweep-out; whether the destination aggregates many senders (= bridge custody) |
| TRON | `https://tronscan.org/#/transaction/<hash>` | TRC-20 transfer in, sweep out |
| Solana | `https://solscan.io/tx/<hash>` | transfer in, sweep out |
| Bitcoin / UTXO | `https://mempool.space/tx/<hash>` | confirmations, sweep out |
| Aleo | `https://api.explorer.provable.com/v1/mainnet/transaction/<id>` | transaction record |

**"Swept to custody" test:** if funds left the deposit address into a destination that receives inflows from many other deposit addresses, that's the bridge's custody wallet — it was processed, funds are safe, even if it's not showing under the account_id you checked.

⚠️ **Print every hash, address, and URL in FULL, never truncated — no `...`, no ellipsis, anywhere, including inside prose.** This covers explorer/tracker links too, not just hashes/addresses: a shortened `https://explorer.near-intents.org/?search=0x1234...abcd` is useless to click or re-paste. They're all correlation keys for follow-up lookups.

## Output — structured summary + plain brief

```
## Summary
What this is: <one line — e.g. "Cross-chain USDC deposit, Ethereum → NEAR Intents, no swap">
Status: <one line — e.g. "Landed on-chain, credited on NEAR, settlement pending">

## Details
| Field | Value |
|---|---|
| account_id | <full, or "not provided — needed to check further"> |
| Identifiers | <every hash/address involved, in full> |
| Progress | <name the milestone reached in plain words — "money sent", "picked up", "settled", or "delivered" — plus what's still unconfirmed and why (e.g. "money sent and confirmed on-chain; can't confirm pick-up without the account_id"). Never report a bare stage number.> |
| Wrong deposit? | <no / yes — which kind (wrong asset, wrong chain, underpaid, missing memo, expired deadline, not a Defuse address) — if yes, this replaces "first missing step" as the real answer> |
| Where's the money | <one plain sentence — still at deposit address / in transit to NEAR / credited, sitting in the account / arrived at destination — plus "confirmed on-chain" or "only per Defuse's API, not yet confirmed on-chain" if you couldn't check both> |
| Risk screen | clear / flagged / not checked (<reason>) |
| Suggested next action | <if a wrong deposit: the concrete fix (resend correctly / escalate with identifiers) — otherwise a public check to re-run, notify_deposit (pending confirmation), a wet quote to replicate (pending confirmation), "wait — within normal latency", or "outside what public tools can resolve, escalate to support with these identifiers"> |
```

Then **one paragraph**, plain language, no internal jargon: what happened, where things stand right now, and what (if anything) the user should expect or do next.

If you don't have enough to fill "account_id" and confirming further progress needs it, ask for it before writing the report — don't guess.
