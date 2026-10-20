# TRACESETTLE — technical summary

Read-only settlement investigation for NEAR Intents (1Click) cross-chain swaps.
This document explains the problem, the engineering approach, and what the tool
can and cannot establish. Every capability named here is backed by code, tests,
or a captured response; the mapping is in "Claims and their evidence" below.

## The problem

A NEAR Intents (1Click) swap spans several systems, each with its own record and
its own status vocabulary:

1. the origin-chain deposit transaction (`status: 0x1` on EVM, confirmed height
   on Bitcoin);
2. the bridge credit into `intents.near`, carrying a memo that names the origin
   transaction;
3. the NEAR settlement, where the intent hash appears in on-chain
   intent-execution event logs;
4. the destination-chain delivery, an asset transfer in a destination receipt;
5. a refund, if the swap did not complete.

When something looks wrong, the user has a deposit address and a 1Click status
string (`SUCCESS`, `FAILED`, `REFUNDED`, `PENDING_DEPOSIT`). That string is a
**service statement**, not chain evidence. The failure mode this tool exists to
prevent is treating it as ground truth:

- a reported `FAILED` is not proof funds were lost;
- a reported `refundedAmount: "0"` is not proof no refund can occur;
- a transaction hash is not proof the event it describes is true;
- "not found" is not proof a transaction failed.

## What TRACESETTLE does

Given one supported identifier (a 1Click **deposit address**, or an **intent
hash** for settlement status only), it queries each applicable public source,
normalizes the responses into a single evidence stream, and reconciles that
stream into a per-stage verdict and an overall outcome. It is read-only: it
never signs, submits, holds, or moves anything, and never asks for a key.

### Stages

`SOURCE_CHAIN_DEPOSIT`, `BRIDGE_DEPOSIT_CREDIT`, `NEAR_SETTLEMENT`,
`DESTINATION_CHAIN_DELIVERY`, `REFUND`.

### Evidence classification

Every evidence item is classified, and the class is the tool's own statement of
how strongly the fact is established:

| Class | Meaning |
| --- | --- |
| `CONFIRMED` | Independently verified from an authoritative source (chain RPC, event logs). |
| `REPORTED` | A service says so; not independently checked. |
| `MISSING` | Not found. Explicitly **not** proof of failure. |
| `UNAVAILABLE` | The source needed to check could not be reached. |
| `INCOMPLETE` | The source answered, but a required search could not be completed. Insufficient evidence, not proof of absence. |
| `CONTRADICTORY` | Two pieces of evidence materially disagree. |
| `SIMULATED` | Clearly-labelled test evidence, never a live finding. |

Each decisive item also carries a `verification_method` string — for example
"locally recomputed txid over raw bytes; script-level recipient match" — so the
report states *how* a class was reached in the same place it states the class.

### What confirms a stage

A stage is confirmed only by its decisive evidence, never by a neighbouring
signal:

- **source deposit** — the origin-chain transaction executed (a successful
  receipt, or a confirmed Bitcoin transaction paying the deposit address);
- **bridge deposit credit** — an on-chain bridge transfer to `intents.near`
  whose `BRIDGED_FROM` memo names *this* deposit's origin transaction hash (for a
  Bitcoin origin, a `utxo_added` event names the origin Bitcoin txid);
- **settlement** — the investigated intent hash appears in on-chain
  intent-execution event logs. A NEAR transaction merely being included or final
  is not enough;
- **destination delivery** — the expected asset transfer to the expected
  recipient appears in the destination receipt logs;
- **refund** — a **confirmed** on-chain transaction pays the address recorded
  on-chain for this intent's withdrawal. A reported refund alone never confirms
  it.

## Differentiators

### 1. Provider claim vs. independently established fact

The tool keeps two questions separate that are easy to conflate: *did the
provider say a refund happened* and *is this specific transaction that refund*.

A provider naming a refund is a **discovery anchor**, not a conclusion. 1Click may
expose no refund transaction hash at all, or it may name one (its record for the
reference swap did both at different times). When it names none, TRACESETTLE has
to find the payout itself and decide whether it can be tied to *this* intent. It
can only do that by an explicit identifier — the withdrawal recipient recorded
on-chain — never by amount or timestamp. When it does name one, that hash is still
only a starting point: the tool fetches the raw bytes, recomputes the txid, and
matches the recipient script before the refund is confirmed.

### 2. Transaction identity is validated locally, not trusted

For Bitcoin, the tool fetches the transaction's **raw bytes** and recomputes the
txid itself (`SHA256d` over the non-witness serialization). If the bytes do not
hash to the requested id, the item is recorded as **contradictory**, never as a
confirmation. It then decodes the recipient address to its `scriptPubKey` and
matches an output, so a "confirmed" payout means a validated transaction paying
the expected script — not a host's word. The verification levels are
`EXPLORER_REPORTED` < `IDENTITY_LOCALLY_VALIDATED` < `SCRIPT_VALIDATED`, and the
tool reports the level it actually reached, never a stronger one.

### 3. Address-history completeness is checked, not assumed

To know whether a refund payout is *ambiguous*, the tool needs the refund
address's complete history. It compares the number of transactions actually
retrieved against the address's authoritative `tx_count`; a mismatch or an
unknown count yields `complete=False`, which is reported as **insufficient
evidence** (`INCOMPLETE`), never as "no payout exists". Incompleteness blocks
*uniqueness* but never turns zero candidates into ambiguity.

### 4. Correlation uses explicit identifiers only

Stages are joined by intent hash, deposit address, recipient address, and
transaction hash. Amount and timestamp similarity are never used to link
transactions, and a safety invariant plus a dedicated test enforce this.

### 5. Unavailable, incomplete, and contradictory are first-class

The tool distinguishes "the source is down" (`UNAVAILABLE`), "the source
answered but could not be searched exhaustively" (`INCOMPLETE`), and "two sources
disagree" (`CONTRADICTORY`). When a required source is unavailable it says so and
stays usable; it does not downgrade a stage to `FAILED`. A deterministic engine
(no LLM) maps evidence to verdicts, so identical evidence always produces an
identical result.

## Worked cases

- **Verified settlement** (real ETH→USDC swap, deposit address): all four
  forward stages `CONFIRMED`, outcome `SETTLED_VERIFIED`, each stage linking to
  its real explorer page.
- **Reported-only settlement** (intent hash alone): outcome
  `SETTLED_REPORTED_ONLY`. The intent-hash path has no reverse lookup to the
  origin or destination legs, so it can never confirm more than the settlement
  stage; when the solver relay answers, that statement is `REPORTED`.
- **Reported refund** (real BTC→TRON swap): the provider reports a refund. The
  tool never treats that report as confirmation. On 2026-10-19 the provider's
  record also named the refund transaction in `originChainTxHashes`, so the tool
  fetched the raw bytes, recomputed the txid, and matched the recipient script
  itself — the refund became `CONFIRMED` at `SCRIPT_VALIDATED`, with
  `discovery: "explicit"` recorded as the method. Earlier in the project the
  provider named no refund transaction; then the refund stayed unconfirmed. The
  verdict follows the evidence, not a fixed expectation. The solver relay, for the
  same intent, still reports `SETTLED`; both upstream statements are kept as
  `REPORTED` and neither is silently chosen over the other.

## Claims and their evidence

| Claim | Backed by |
| --- | --- |
| Read-only; no signing, custody, submission, or recovery. | No such code path; `grep` audit; stated in every report. |
| Provider statements are `REPORTED`, not `CONFIRMED`. | `adapters/oneclick.py`, `adapters/solver_relay.py`; tests. |
| Settlement is confirmed from on-chain intent logs, not a provider string. | `adapters/near_rpc.py`; `test_full_success_investigation`. |
| Bitcoin payout identity is locally recomputed, and a mismatch is contradictory. | `btc_verify.py`; `test_btc_refund_txid_bytes_mismatch_is_contradictory`. |
| Address-history completeness is verified against `tx_count`. | `btc_rpc.fetch_address_history`; `test_btc_address_history_incomplete_when_counts_differ`. |
| Correlation is never by amount or timestamp. | `test_engine_never_correlates_by_amount_or_timestamp`. |
| A refund or delivery is never claimed without required evidence. | `tests/test_safety_invariants.py`. |
| Zero-dep at runtime. | Import audit; README runtime-dependencies section. |

## Honest limits

- 1Click status is a service statement, reported and not independently verified.
- The 1Click status endpoint is keyed on the deposit address; there is **no
  documented reverse lookup** from an intent hash or transaction hash.
- Only chains with a configured public RPC can be independently verified; others
  are reported `UNAVAILABLE`, never `FAILED`.
- The bridge credit is confirmed from an on-chain `BRIDGED_FROM` memo. That memo
  is emitted by the bridge service, so it is strong identifier-based, on-chain
  corroboration — **not** cryptographic proof of the whole settlement.
- **Not every refund can be independently verified.** A refund is confirmed only
  when exactly one confirmed payout matches the on-chain withdrawal recipient, or
  when the provider names the transaction and it validates. An ambiguous history
  stays unconfirmed by design. Whether a given refund can be confirmed depends on
  what the provider exposes, which can change over time.
- A replayed/offline run shows the tool's analysis of real captured responses; it
  does not show that an endpoint is answering now.

## Reproducing

```sh
python3 -m pytest tests/ -q                 # 233 passed
python3 demo/demonstrate.py                 # live walkthrough
python3 demo/demonstrate.py --offline       # replay of real captures, no network
python3 -m tracesettle investigate <deposit address>
```
