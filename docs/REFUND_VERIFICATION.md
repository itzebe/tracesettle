# Independent refund verification — investigation and design

Status: **implemented, partial verification**. This document records what is
independently verifiable for a Bitcoin refund, what is not, and why. It is the
engineering record behind `tracesettle/btc_verify.py` and the refund-correlation
rules in `tracesettle/investigation.py`.

Nothing here is aspirational. Every claim is tied to a live observation or to an
official document, and the verification level the tool reports is the level it
actually achieves.

## 0. Verification tiers and the levels they prove

TRACESETTLE reports the level it actually reached for a Bitcoin payout, never a
stronger one. The levels are a conjunction of checks the tool itself performed
(`tracesettle.btc_verify.verification_level_for`):

| Level | Requires | What it proves | What it does not prove |
| - | - | - | - |
| `EXPLORER_REPORTED` | A host returned the transaction JSON | The host claims the transaction exists/confirmed | Nothing is locally checked |
| `IDENTITY_LOCALLY_VALIDATED` | Raw bytes fetched; txid recomputed (`SHA256d` over the non-witness form) and matched | The bytes hash to the requested txid | Block inclusion; that it is a refund; intent correlation |
| `SCRIPT_VALIDATED` | Identity validated **and** the recipient address decoded to its `scriptPubKey` and matched an output | The validated transaction pays the expected script | Intent correlation; that all funds were returned |

There is deliberately **no level above `SCRIPT_VALIDATED`**. A second Esplora host
is an availability fallback over the same chain state, not independent
corroboration, so it is never counted as a stronger check.

### Source-evaluation tiers (discovery, not strength)

Discovery tiers decide whether a payout may be *correlated* to the intent. They
are orthogonal to the verification level above.

| Tier | Evidence capability | What TRACESETTLE can establish | What it cannot establish alone | Failure behaviour |
| - | - | - | - | - |
| A | Explicit provider-supplied refund transaction id (`swapDetails.originChainTxHashes`) | A candidate transaction for independent validation | That it belongs to the refund merely because a provider named it | Preserve the claim; reject invalid/contradictory evidence |
| B | Confirmed payout found via the on-chain withdrawal recipient, on a demonstrably complete address history | A candidate payout and that the search scope was complete | That the payout belongs to the investigated intent | Unresolved correlation stays unverified |
| C | Multiple matching payouts, or several provider-named matches | That more than one candidate exists | Which one is the refund | `AMBIGUOUS` — never confirm |
| D | A complete search with no matching payout | That no payout to the address exists in the searched scope | That no refund occurred elsewhere | State absence as absence |
| E | Provider reports a refund, no independently correlated transaction | That the provider claims a refund | Independent confirmation | `REPORTED` — never confirm |
| — | Incomplete search or unavailable source | A search limitation or a retrieval failure | That no refund exists, or that it failed | `INCOMPLETE` (insufficient) or `UNAVAILABLE` (source down) |

A provider-supplied hash (Tier A) is a *discovery* anchor. It still has to pass the
same identity and script checks (Tier B's mechanics) before it can be at
`SCRIPT_VALIDATED`; the tier says how the candidate was found, the level says how
strongly it was checked. Every decisive evidence item also carries a
`verification_method` string stating how its level was reached (for example
"locally recomputed txid over raw bytes; script-level recipient match"), so the
report states the method in the same place it states the class.

## 1. The question

A swap provider reported a refund for a real BTC→TRON swap. Can TRACESETTLE
independently obtain and validate the actual Bitcoin refund transaction, without
trusting the provider's status field?

Known inputs:

| Field | Value |
| - | - |
| Deposit address | `bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm` |
| Reported refund recipient | `bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw` |
| Reported refunded amount | `11746` |
| Reported reason | `FEE_ESTIMATION_FAILED` |
| Intent hash | `69o3QALyLCrYnE7suvystyBemwnB3khdsCuRKYnPRgrn` |
| NEAR settlement tx | `83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1` |
| Bitcoin deposit tx | `9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226` |

## 2. Amount denomination (resolved, not assumed)

`11746` is **satoshis**, established from two independent, verifiable facts:

1. The bridge RPC (`POST https://bridge.chaindefuser.com/rpc`,
   `supported_tokens`) reports `btc:mainnet:native` with `decimals: 8`. The
   1Click quote uses the same 8-decimal base unit.
2. The provider's own arithmetic closes on the reported fields:
   `depositedAmount (13646) − refundFee (1900) = refundedAmount (11746)`.

So a satoshi figure is not a guess. The observed on-chain payout to the refund
address (`12884` sats) does **not** equal `11746`; the two figures are reported
side by side and are never reconciled by the tool.

## 3. Source evaluation (Phase 2.2)

| Source | Tx by txid | Raw bytes | Address history | Confirmation | Output scripts | Auth | Independent value | Limitations |
| - | - | - | - | - | - | - | - | - |
| Esplora — `mempool.space/api` | Yes | Yes (`/tx/{id}/hex`) | Yes (`/address/{a}/txs`) | Yes (`status.confirmed`) | Yes (address + value + type) | None | Full read access; local txid re-derivation possible | Single page of address history; not an authority on intent correlation |
| Esplora — `blockstream.info/api` | Yes | Yes | Yes | Yes | Yes | None | Second host, same API shape | Same underlying Esplora software; a useful *availability* fallback, **not** independent corroboration of chain state |
| Esplora — `/tx/{id}/outspend/{vout}` | n/a | n/a | n/a | Yes | n/a | None | Names the exact transaction that spends a UTXO | Only answers "who spent this output" |
| 1Click `/v0/status` | n/a | No | No | No | No | None observed | Provider claim only | **No refund tx hash field**; HTTP 521 during this work |
| Intents Explorer API | Yes | No | No | No | No | **JWT (partner-gated)** | Would search by tx hash / deposit address | Paid/partner credential; out of scope |
| Bridge indexer `bridge.chaindefuser.com/rpc` | No | No | No | No | No | None | `supported_tokens` only; refund/deposit methods return `Internal server error` | No usable refund lookup |
| BTC connector `btc-connector.bridge.near` | No | No | No | No | No | None | `get_config`, `required_balance_for_execute_refund` answer | Pending-info view methods are not publicly resolvable |

Two Esplora hosts are **not** treated as independent confirmation: they serve the
same open-source software over the same chain state. The tool records a second
host as an availability fallback and labels corroboration honestly.

## 4. What is independently verifiable (implemented)

For any Bitcoin transaction the tool retrieves, it can establish — and label —
these levels, in increasing strength:

1. **Explorer-reported inclusion** — an Esplora host reports the tx exists and is
   confirmed. Reported, not locally checked.
2. **Locally validated transaction identity** — the tool fetches the raw
   transaction bytes and recomputes the txid as `SHA256d` over the **non-witness**
   serialization, then compares it to the requested txid. This proves the bytes
   the host returned really hash to the id under investigation. Verified live for
   both the deposit and refund transactions in this case.
3. **Script-level recipient verification** — the tool decodes the recipient
   address to its exact `scriptPubKey` and matches it against an output's script,
   rather than comparing address strings.

A **cross-source** level is deliberately **not** offered: the two Esplora hosts
serve the same open-source software over the same chain state, so agreement
between them is an availability property, not independent corroboration of chain
state. The tool records a second host as a fallback and never claims more.

### Source limitations (what each capability does and does not give)

* **Raw transaction retrieval** (`GET /tx/{id}/hex`) — gives the exact bytes for
  local hashing. It does not by itself prove inclusion, and a 404 or transport
  failure is a retrieval problem, not a transaction outcome.
* **Local transaction-id recomputation** — proves the bytes match the identifier.
  It says nothing about block inclusion, refund semantics, or intent correlation.
* **Address decoding and script-level matching** — proves a payment goes to the
  *script* of the expected address. It does not prove the address belongs to the
  intent (a user wallet can be paid for many reasons).
* **Address-history completeness** — see §4.1. Equal counts alone are not
  completeness.
* **Confirmation and block inclusion** — `status.confirmed` is the host's report.
  The tool does not independently validate a block header or a merkle proof.
* **Outspend data** (`/tx/{id}/outspend/{vout}`) — names the transaction that
  spends a specific UTXO. It is a *correlation* aid only when the documented
  refund flow is the one that spent that outpoint; it is not a general refund
  finder, and it did not fire for the reference case.
* **Provider transaction-hash fields** — `originChainTxHashes`,
  `nearTxHashes`, `destinationChainTxHashes` exist. There is **no refund
  transaction hash field** in the observed schema; a refund is only ever implied
  by `status: "REFUNDED"` and `swapDetails.refundedAmount`.
* **Free public APIs** — keyless but rate-limited and occasionally down (the
  1Click status endpoint returned HTTP 521 throughout this work). A stronger
  source — the Intents Explorer API — requires a partner JWT.
* **Explorer-reported vs independently verified** — everything a host states
  (existence, confirmation, output values) is *reported* until the tool
  recomputes or matches it locally. Validating raw identity proves the bytes match
  the id; it does **not** prove inclusion, refund success, or intent correlation.

## 4.1 What "complete" address history actually means

`AddressHistory.complete` is true only when **both** hold:

1. the number of distinct transactions retrieved reaches the host's reported
   `tx_count` (`chain_stats.tx_count + mempool_stats.tx_count`), **and**
2. pagination ended naturally (a short page, or a 404 on the next page).

The tool does not assume the host is exhaustive. `tx_count` is a snapshot taken
before the pages are fetched, so a transaction confirmed in between can make the
count and the pages disagree; the tool resolves that conservatively (disagreement
means incomplete). Esplora serves confirmed history newest-first and does not
document record omission, but the count and the page chain are separate calls, so
"complete" means "the host's own count was reached and the page chain ended" — a
strong signal, not an external proof that no other record exists. A payout found
on a complete search is still only *a* payout to the address; it is never, by
itself, proof it belongs to the investigated intent.

## 5. What is NOT independently verifiable here (the exact remaining dependency)

The refund for **this specific intent** cannot be confirmed from free data,
because no free source ties a specific payout to the intent:

* The provider exposes **no refund transaction hash** (only `originChainTxHashes`,
  `nearTxHashes`, `destinationChainTxHashes`).
* The refund recipient `bc1q77w5l5…mdrgw` is the **user's own wallet**: the
  deposit transaction *spends* it, and it received **four** confirmed payouts
  (heights 917708, 921634, 971735, 972263) over roughly six months. Address
  history is therefore not intent-specific.
* The deposit UTXO (`9a80de…:0`) is spent by an unrelated batch transaction
  (`3ae5a12f…`), not by a refund transaction, so input-spend correlation does not
  fire for this case either.
* The connector contract that pins and enforces the refund does not expose a
  publicly resolvable pending-refund view, and the bridge indexer has no refund
  endpoint.
* The only documented source that could disambiguate — the Intents Explorer API,
  which can search by transaction hash — requires a partner JWT.

**Exact remaining dependency:** an authoritative, free (or explicitly provisioned)
source that maps this intent to its refund transaction hash — either the provider
exposing a refund tx hash, the bridge/connector exposing pending-refund records,
or partner access to the Intents Explorer API.

## 6. Consequence for reconciliation (implemented)

The tool reports the refund as **reported but not independently
confirmed** (`REFUND_REPORTED_UNVERIFIED`) for this case. Candidate selection is
deterministic and tiered, strongest anchor first (`tracesettle/btc_verify.py`):

| Tier | Anchor | Result when selected |
| - | - | - |
| A — `EXPLICIT_IDENTIFIER` | A transaction hash the provider itself names | Confirmed (still identity- and script-checked); level from the checks actually performed |
| B — `UNIQUE_ADDRESS_MATCH` | Exactly one confirmed payout to the resolved refund address, **on a provably complete history** | Confirmed, with the weaker anchor recorded |
| C — `AMBIGUOUS` | More than one candidate, or a provider-named hash that does not pay the refund address | Not confirmed; `AMBIGUOUS_REFUND_PAYOUT` |
| D — `NONE` | A complete history shows no payout to the refund address | Not confirmed; absence is stated as absence |
| — — `INCOMPLETE_SEARCH` | The address history could not be shown to be complete | Not confirmed; `INCOMPLETE_ADDRESS_HISTORY` (stage `UNKNOWN`) |
| — — source down | The history could not be retrieved at all | Not confirmed; `SOURCE_UNAVAILABLE` (stage `UNAVAILABLE`) |

Rules the engine enforces:

- It never selects one of several payouts by amount or timestamp.
- It never treats a unique address payout as proof of intent correlation: Tier B
  requires the address history to be *provably complete* (the reported
  `tx_count` must be reached **and** pagination must end naturally).
- An incomplete search is `UNKNOWN` (insufficient evidence), distinct from a
  source being down (`UNAVAILABLE`). Neither is "no refund".
- If a source returns raw bytes that do not hash to the requested txid, the
  evidence is marked `CONTRADICTORY` and the stage cannot be confirmed.
- Raw bytes merely being *unavailable* (a 404 or transport failure on `/hex`) is
  a limitation, never a contradiction: the payout may still be confirmed at the
  weaker `EXPLORER_REPORTED` level, and the limitation is recorded.

The reported `verification_level` is computed from the checks actually performed
on the confirmed transaction (`verification_level_for`), never from the discovery
tier, so a Tier A candidate whose raw bytes could not be fetched is reported at
`EXPLORER_REPORTED`, not `SCRIPT_VALIDATED`.

For this specific intent the result stays **unverified**: the refund address is
the user's own wallet with four confirmed payouts, the provider names no refund
hash, and no free source maps the intent to a specific payout. That is a
correlation gap, not a failed refund, and the tool says so.

## 7. Phase 2 closeout

This section closes out the source evaluation: what each capability was assessed
to be, what was built against it, and what remains an honest limitation. It is the
record behind the tier table in §3 and the levels in §0.

### 7.1 Source evaluation — capability matrix (closeout)

| Source | Tx by id | Raw bytes | Address history | Complete-search check | Auth | Independent value | Built against it | Limitation carried forward |
| - | - | - | - | - | - | - | - | - |
| Esplora — `mempool.space/api` | Yes | Yes (`/tx/{id}/hex`) | Yes (`/address/{a}/txs`, `/txs/chain/{id}`) | Yes (`tx_count`) | None | Primary Bitcoin source | `btc_rpc` (fetch, history, outspend, raw) | Pagination is capped by a page budget; the count is a snapshot |
| Esplora — `blockstream.info/api` | Yes | Yes | Yes | Yes | None | Availability fallback | `btc_rpc` (second host in the fallback chain) | Same Esplora software; not independent corroboration |
| Esplora — `/tx/{id}/outspend/{vout}` | n/a | n/a | n/a | n/a | None | Names the spender of a UTXO | `btc_rpc.fetch_outspend` | Only answers "who spent this output"; did not fire for the reference case |
| 1Click `/v0/status` | n/a | No | No | No | None observed | Provider claim only | `oneclick` | No refund tx hash field; HTTP 521 during this work |
| Intents Explorer API | Yes | No | No | No | **JWT (partner-gated)** | Would search by tx hash / deposit address | Not used | Paid/partner credential; out of scope |
| Bridge indexer `bridge.chaindefuser.com/rpc` | No | No | No | No | None | `supported_tokens` only | `assets` (denomination) | Refund/deposit methods return `Internal server error` |
| BTC connector `btc-connector.bridge.near` | No | No | No | No | None | `get_config`, `required_balance_for_execute_refund` | Not used | Pending-info view methods are not publicly resolvable |

### 7.2 What Phase 2 delivered against each capability

* **Transaction lookup** — `identifiers.classify_identifier` /
  `validate_deposit_address` accept a deposit address, an EVM/NEAR transaction
  hash, or an intent hash, and state what each can and cannot resolve.
* **Data-source adapters** — one module per source (`adapters/oneclick.py`,
  `adapters/near_rpc.py`, `adapters/evm_rpc.py`, `adapters/btc_rpc.py`,
  `adapters/solver_relay.py`), each returning a `SourceReport` (health) plus data,
  never mixing source health with transaction state.
* **Evidence normalization** — every observation becomes an `EvidenceItem` with a
  stage, event type, source, verification class, timestamp, URL, and limitations
  (`model.py`). Nothing is fabricated; absent fields stay absent.
* **Stage reconciliation** — `reconcile.reconcile` applies deterministic rules over
  the normalized evidence and returns per-stage assessments, contradictions, the
  last confirmed stage, and unresolved questions. No LLM participates.
* **Investigation report** — `report.build_report` renders the same result as
  structured JSON and Markdown, with an evidence-class legend and the tool's
  limitations.
* **User interface** — `ui.py`, a stdlib `http.server`, runs the workflow
  (identifier → investigate → chronological evidence → stage states → source
  records → export) with no external assets.
* **Automated tests** — 222 tests (`python3 -m pytest tests/ -q`), including the
  required scenarios and the safety invariants that fail the build on an
  unsupported claim.

### 7.3 Features that needed no paid API or paid infrastructure

The whole supported path runs on free, keyless public surfaces: Esplora (Bitcoin),
public NEAR RPC, public EVM RPC, and the 1Click status endpoint. The tool's runtime
is the Python standard library only; there is no database and no paid dependency.
The one capability that would require a paid/partner credential — searching intents
by transaction hash via the Intents Explorer API — is documented as out of scope
rather than assumed.

### 7.4 Limitations carried out of Phase 2 (unchanged, by design)

1. No free source maps a specific Bitcoin payout to an intent; correlation is
   identifier-based and stays unverified when no identifier ties the two together.
2. 1Click exposes no refund transaction hash.
3. Two Esplora hosts are not independent corroboration of chain state.
4. Address-history completeness is bounded by the page budget and rests on the
   host's own `tx_count`.
5. The 1Click status endpoint was repeatedly unavailable (HTTP 521) during this
   work; the tool degrades to `UNAVAILABLE` and never invents stages.

These are represented as `MISSING` / `UNAVAILABLE` / `INCOMPLETE` / `CONTRADICTORY`
evidence and surfaced in the report, never hidden.

## 8. Phase 3 evidence-model review

Phase 3 required the evidence model to distinguish verification classes precisely.
The review found and corrected three places where the model was looser than the
capabilities in §0 and §3 justify:

1. **Verification level was declared, not computed.** The refund evidence carried a
   level taken from the discovery tier. It is now computed from the checks actually
   performed (`verification_level_for`), so a candidate whose raw bytes could not be
   fetched cannot be reported as `SCRIPT_VALIDATED`.
2. **Completeness rested on a count alone.** `AddressHistory.complete` is now true
   only when the host's `tx_count` is reached **and** pagination ends naturally.
   This closes the case where a full page under a matching count was read as a
   complete search even though the page chain had not ended.
3. **An incomplete search was reported as a source outage.** A new
   `Verification.INCOMPLETE` class and `StageState.UNKNOWN` distinguish "the source
   answered but the search was not exhaustive" from "the source was down". Neither
   is treated as "no refund".

Raw bytes that do not hash to the requested txid remain `CONTRADICTORY`; raw bytes
merely being unavailable is a limitation, not a contradiction. The refund amount is
now recorded in satoshis with the recipient output kept separate from the
transaction's total output value and fee.

A fourth gap was closed in the same pass: the evidence model had no first-class
place to state *how* a classification was reached. `EvidenceItem.verification_method`
now carries that for every decisive item — a locally recomputed transaction id, a
script-level recipient match, an RPC inclusion check, a DIP-4 event-log parse, or a
plain upstream report — and the report and interface render it alongside the class.

## Addendum (2026-10-19): the provider began naming the refund transaction

The sections above are the record of what was true when the reference case was
first analysed: 1Click's `/v0/status` exposed **no** refund transaction hash, and
the status endpoint was returning HTTP 521. Both of those changed while the
submission was being prepared, and the tool handled the change without a code
change, which is the point of the design.

Observed on 2026-10-19:

* `/v0/status` answered HTTP 200 again.
* `swapDetails.originChainTxHashes` for the reference swap now lists **two**
  transactions: the refund transaction
  `377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f` and the
  deposit transaction
  `9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226`.

`originChainTxHashes` is documented only as "hashes and explorer URLs for all
transactions on the origin chain" (`evidence/raw/oneclick_openapi.yaml`). It is not
a dedicated refund field, so the tool does not assume an entry is a refund: it
classifies each origin-chain transaction by its on-chain recipient — a
transaction paying the quote's `refundTo` address is a refund candidate, one
paying the deposit address is the deposit. That is what happens here: the named
transaction pays the refund address, so it is treated as a refund candidate and
then independently validated (raw bytes fetched, txid recomputed, recipient script
matched). The result is `REFUND_VERIFIED` with the refund `CONFIRMED` at
`SCRIPT_VALIDATED`, discovered via the explicit provider-named hash
(`discovery: "explicit"`), and the evidence item records that method.

Two consequences worth stating plainly:

1. **The change did not require a code change.** A provider-supplied hash is a
   *discovery* anchor only; it flows through the same identity and script checks as
   any other candidate. The tool's honesty does not depend on the provider's field
   set staying the same.
2. **The solver relay still reports `SETTLED` for this intent** while 1Click
   reports `REFUNDED`. Both are `REPORTED` statements, and the engine records them
   as such; it does not silently pick one. The independently confirmed facts are
   the on-chain ones: the deposit, the bridge credit, the NEAR settlement, and the
   refund payout. The conflicting service statements remain visible in the
   evidence stream.

The earlier conclusion — "this refund cannot be confirmed from free data" — was
correct for the data available at the time. It is superseded by the provider
exposing the transaction, not by any change in the tool's logic.


