# AGENTS.md — TRACESETTLE

Persistent repo knowledge. Read this before working here.

## What this project is

A **read-only** cross-chain settlement investigation tool for **NEAR Intents** transactions.
It reconstructs available evidence around a transaction, identifies missing/contradictory information, and
emits an evidence-backed report.

**Hard invariants (never violate):**

- Never execute transactions, sign messages, hold funds, or request a private key / seed phrase.
- Never claim funds were recovered, refunded, or delivered without verified on-chain evidence.
- Never invent endpoints, response fields, transaction identifiers, or API capabilities.
- Never treat "not found" as proof of failure; never treat a reported failure as proof funds were lost;
  never treat `refundedAmount: "0"` as proof no refund can occur.
- Never infer a transaction relationship from amount or timestamp similarity alone.
- No LLM may decide whether a transaction is confirmed — reconciliation is deterministic.
- Simulated scenarios must be labelled clearly. Do not replace real evidence with mock data.

## Hackathon context

Official agent instructions: `https://nearhackathon.com/HACKATHON.md` (vendored at `docs/official/HACKATHON.md`).
Event window: **2026-11-01T00:00:00Z → 2026-11-14T23:59:00Z**. Repo must be **public** by the deadline and a
public X demo post is required. Judging includes AI judges — write the README for a machine reader as well as
a human, with "do X → see Y" steps and no marketing.

Do **not** perform, without the human's explicit confirmation: send the submission, post on X, make the repo
public / push / force-push, sign transactions, spend tokens, deploy to mainnet, or commit secrets.

Likely track: `security` (AI Security & Defense). Secondary: `thesis`, `defi`, `realworld`.

## Verified API surfaces (Phase 1, 2026-10-19)

All verified live; see `PHASE1_FEASIBILITY.md` and `evidence/README.md` for raw artefacts + curl repros.

| Surface | Endpoint | Auth | Notes |
| --- | --- | --- | --- |
| 1Click status | `GET https://1click.chaindefuser.com/v0/status?depositAddress=<addr>` | none in practice | Keyed on the quote **deposit address**, not a hash. `404` = not found (NOT failed). `401` only on *invalid* credentials. Rate limit headers: `x-ratelimit-limit-unauth: 1200/60s`. |
| 1Click quote | `POST https://1click.chaindefuser.com/v0/quote` | none | `dry: true` omits `depositAddress`/`deadline`. A live (`dry: false`) quote is needed to obtain a deposit address. |
| 1Click tokens | `GET https://1click.chaindefuser.com/v0/tokens` | none | asset list |
| Solver relay | `POST https://solver-relay-v2.chaindefuser.com/rpc` `get_status` | none | Status enum differs: `PENDING`/`TX_BROADCASTED`/`SETTLED`/`NOT_FOUND_OR_NOT_VALID`. |
| Bridge RPC | `POST https://bridge.chaindefuser.com/rpc` | none | `recent_deposits`, `supported_tokens`, `withdrawal_status`. |
| NEAR RPC | `POST https://free.rpc.fastnear.com` | none | `tx` by hash; pass `sender_account_id` (e.g. `intents.near`) or `tx` fails to parse. Intent hash appears in `intents.near` DIP-4 `EVENT_JSON` logs. |
| EVM RPC | `POST https://ethereum-rpc.publicnode.com` | none | `eth_getTransactionReceipt` confirms origin/destination legs. |

**Not free / out of scope:** Explorer JSON API `https://explorer.near-intents.org/api/v0/transactions`
(partner `bearerAuth` → `MISSING_TOKEN`); `CONFIDENTIAL_INTENTS` quotes (partner auth).

**Key correlation rule:** link stages only via explicit identifiers (`depositAddress` → `intentHashes[]` →
`nearTxHashes[]` → `originChainTxHashes[]` / `destinationChainTxHashes[]`). Never by amount/timestamp.

## Evidence classification vocabulary

`CONFIRMED` (authoritative on-chain source) Â· `REPORTED` (upstream service, not independently checked) Â·
`MISSING` Â· `CONTRADICTORY` Â· `UNAVAILABLE` Â· `SIMULATED`. Reconciliation returns an explicit **unknown**
when evidence is insufficient.

## Docs conventions

- Official docs are Mintlify pages: append `.md` to a page URL for raw markdown; index at `llms.txt`.
- Vendored copies live in `docs/official/`; live-verified responses in `evidence/raw/`.

## Local environment notes

- Python: `/usr/local/bin/python`. `pyyaml` was installed via `pip install pyyaml`.
- No database is used or required for the core feature.

## Phase 2 additions (TRACESETTLE MVP)

- **Runtime:** Python 3.11+ standard library only at runtime (verified on 3.13.15).
  `pytest` and `pyflakes` are dev-only, pinned in `requirements-dev.txt`. Do not add
  runtime dependencies (free infra, no DB).
- **Dev setup:** `python3 -m venv .venv && . .venv/bin/activate &&
  python -m pip install -r requirements-dev.txt`. Verified working in a clean venv
  with no globally installed pytest/pyflakes.
- **Tests:** `python3 -m pytest tests/ -q` (304 tests). `tests/conftest.py` provides
  `FakeOpener`, which substitutes only `urllib`'s opener; adapters, engine, report,
  and UI are the real code paths. Real captures are loaded from `evidence/raw/`;
  synthetic fixtures live in `tests/fixtures/synthetic/` and carry a `_provenance`
  field marking them synthetic. Never mix the two.
- **Determinism:** `reconcile.py` must stay deterministic. No LLM may decide whether
  a transaction is confirmed. Identical evidence must produce an identical result.
- **Decisive evidence:** a stage is `CONFIRMED` only by `DECISIVE_EVENT_TYPES[stage]`
  in `reconcile.py`. On-chain inclusion/execution is corroboration, never confirmation.
  Do not weaken this to make a test pass.
- **Safety invariants:** `SAFETY_INVARIANTS` in `reconcile.py` are asserted by
  `tests/test_safety_invariants.py`. Adding a claim path requires adding an invariant
  test that fails without the required evidence.
- **Origin attribution:** origin-chain transactions are attributed to deposit vs
  refund by comparing recipient addresses (explicit identifiers), never by amount or
  timestamp.
- **Per-stage availability:** an unavailable source produces `Verification.UNAVAILABLE`
  evidence for the affected stage, not a global downgrade. A `REPORTED` claim whose
  verification source was unavailable resolves to `UNAVAILABLE`.
- **Incomplete search vs source outage:** `Verification.INCOMPLETE` is for "the
  source answered but the required search could not be completed" (e.g. address
  history pagination stopped mid-chain, or a snapshot `tx_count` was not reached).
  It resolves to `StageState.UNKNOWN` (insufficient evidence), never
  `UNAVAILABLE` (source problem) and never `CONFIRMED`. `btc_rpc.AddressHistory.complete`
  is true only when the host's `tx_count` is reached **and** pagination ends
  naturally; equal counts alone are not completeness.
- **Verification levels are computed, not declared:** `btc_verify.verification_level_for`
  derives the level from the checks actually performed (`EXPLORER_REPORTED` <
  `IDENTITY_LOCALLY_VALIDATED` < `SCRIPT_VALIDATED`). A discovery tier (how a
  candidate was found) never raises the level. Raw bytes merely being unavailable
  is a limitation, not a contradiction; bytes that do not hash to the requested
  txid are `CONTRADICTORY`.
- **Amounts carry units:** refund evidence states amounts in satoshis and keeps the
  recipient output separate from the transaction's total output value and fee.
- **UI:** `tracesettle/ui.py` is a stdlib `http.server`. Never log raw identifiers.
  All client errors are generic; internals go to the server log only.
- **NEAR named accounts are lowercase.** `is_near_named_account` must reject
  mixed-case input, otherwise `0x...` strings are misclassified as NEAR accounts.
- **Lint:** `python3 -m pyflakes tracesettle/ tests/` must be clean.

## Audit findings (pre-submission, post-Phase-2)

- **Correlation is identifier-based, never amount/timestamp-based.** Two on-chain
  event streams can be linked only when they share an explicit identifier:
  - Settlement: the `intent_hash` in DIP-4 `EVENT_JSON` logs must equal one of the
    investigation's `expected_intent_hashes` (from 1Click or the input identifier).
    A NEAR tx can carry several intents; an unrelated one must not confirm ours.
  - Bridge credit: the `omft.near` -> `intents.near` `ft_transfer` memo
    `BRIDGED_FROM:{"txHash":"0x…"}` must name one of the investigation's
    `expected_origin_tx_hashes`. This is the authoritative on-chain evidence for
    `BRIDGE_DEPOSIT_CREDIT` (previously `REPORTED`-only).
  - When an expectation set is empty, no naming requirement is imposed. Passing the
    expectation is what makes confirmation meaningful, so always thread it from the
    orchestrator.
- **`reconcile()` signature** is
  `reconcile(evidence, source_statuses, expected_intent_hashes, expected_origin_tx_hashes)`.
  Off-target decisive evidence yields `REPORTED` with an explicit explanation, never
  `CONFIRMED`.
- **Refund availability:** a reported refund whose verification source was
  unreachable resolves the REFUND stage to `UNAVAILABLE` (outcome
  `REFUND_REPORTED_UNVERIFIED`), so the gap is visible rather than looking like a
  plain unverified report. A refund whose on-chain search could not be *completed*
  resolves to `UNKNOWN` (insufficient evidence) instead, and is still never
  confirmed.
- **Tests:** `python3 -m pytest tests/ -q` (304 tests).

## Independent verification (pre-submission)

- **Verified (2026-10-20):** full suite `224 passed`; `pyflakes` clean over
  `tracesettle/ tests/ demo/`; `compileall` OK; no non-stdlib runtime imports.
- **Live reproduction confirmed** through the HTTP interface: deposit address
  `0xb741c00f6d63b6ded0ccada1a82bcbadc38a572b` -> `SETTLED_VERIFIED`, all four stages
  `CONFIRMED`, REFUND `MISSING`, 17 evidence items, 11 safety invariants all PASS.
  Note 1Click nests the hash arrays under `swapDetails` in `/v0/status`.
  *(Evidence-item counts are live-dependent and drift as sources add or drop
  records; the stage states and the invariant results are the stable assertions.
  A later live run of the same case returned 18 items with the same verdict.)*
- **Defect found and fixed in this pass:** `_assess_stage` treated any
  `Verification.CONFIRMED` item as confirming its stage, even when its provenance was
  `Provenance.SIMULATED`. A fully simulated evidence set could therefore produce
  `SETTLED_VERIFIED`. Confirmed items now require
  `provenance is not Provenance.SIMULATED`. No production adapter emits `SIMULATED`
  (all emit `Provenance.REAL`), so this was latent, not reachable at runtime, but the
  invariant is now structural. New safety invariant
  `simulated_evidence_never_confirms` plus a regression test guard it.
- **Read-only re-confirmed:** the only non-GET upstream calls are JSON-RPC reads
  (`eth_getTransactionReceipt`, NEAR `tx`, solver `get_status`). No signing,
  custody, transaction submission, or recovery code exists.

## Final reproducibility pass (pre-submission)

- **Dev manifest added:** `requirements-dev.txt` pins `pytest==9.1.1`,
  `pyflakes==4.0.3`, and pytest's transitive deps (`iniconfig`, `packaging`,
  `pluggy`, `Pygments`). Runtime stays zero-dependency.
- **Clean-environment proof:** installed into a fresh `python3 -m venv .venv` that
  had no pytest/pyflakes (`ModuleNotFoundError` before install). All checks then
  ran from that venv: 224 collected, 224 passed, pyflakes clean, compileall OK, no
  external runtime imports, 15 modules imported.
- **Live reproduction re-confirmed (this run):** via `POST /api/investigate` ->
  `SETTLED_VERIFIED`, 17 evidence items, 11/11 safety invariants PASS.
- **New regression test:** `test_bridge_credit_origin_hash_match_is_case_insensitive`
  guards the hex case-insensitivity requirement. Mutation-checked: it fails if
  `.lower()` normalization is removed from `_names_expected_origin_tx`.
- **Docs corrected:** `reconcile.py` module docstring now lists all 11 invariants;
  README carries the current count (224), a runtime-dependencies section, and the
  "no real refunded transaction independently verified yet" limitation.
  *(Historical: that limitation was later removed once the reference BTC refund
  was independently verified on 2026-10-19; see the last section.)*

## Judge-ready demonstration pass

- **Second and third live cases verified (2026-10-20).** Both were taken from the
  public NEAR Intents explorer's embedded recent-transactions feed (a traceable
  source), then re-checked against 1Click status and NEAR RPC directly:
  - `bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm` — a real **refunded** BTC→TRON
    swap. At the time this was first checked the refund resolved to `UNAVAILABLE`
    (the reported refund could not be tied to a transaction), deposit credit
    `REPORTED`, destination `MISSING`, NEAR settlement `CONFIRMED`. This is now
    demo Case 3 and a README reproduction step. **Correction (2026-10-19):** the
    Bitcoin origin *does* have a configured public source (`adapters/btc_rpc.py`,
    mempool.space with a blockstream.info fallback); the earlier `UNSUPPORTED_CHAIN`
    label was wrong. With the provider now naming the refund transaction the case
    resolves to `REFUND_VERIFIED`. See the refund section above.
  - `494d57e5e385f36b1b4953a863f4c53785e000b9e72b61ac7fe4be47bdbed7ea` — an
    ETH→Base swap whose destination RPC returns HTTP 403, producing
    `DELIVERY_UNVERIFIED` with `UNAVAILABLE` stages. Not added to the demo
    because the 403 is an archive-gating artefact, not a stable capability test.
- **Free RPC archive gating (limitation, not a defect).** `publicnode.com` free
  endpoints return HTTP 403 (`Archive requests require a personal token`) for
  `eth_getTransactionReceipt` on some chains (observed on `base`, `arb`). The
  client classifies this as `UNAUTHORIZED` → the stage is `UNAVAILABLE`, never
  `FAILED`. This is exactly the honest-uncertainty behaviour the tool intends.
  The primary demo case is unaffected (its ETH RPC answers normally).
- **UI change (justified, minimal):** the Result panel now shows the supplied
  identifier, its detected type, and the supported path, which Phase 4A requires.
  `tests/test_ui.py::test_index_page_renders` asserts those labels are present.
- **Demo now shows three cases** (verified / reported-only / reported refund) and
  derives each explanation from the actual result, printing an honest NOTE if a
  run does not reproduce the expected outcome.

## Bitcoin refund verification (2026-10-20)

> **Partly superseded (2026-10-19 live re-check, see the last section).** This
> section records the state when the capability was built: 1Click exposed no
> refund tx hash, so the payout was discovered from the refund address's own
> history. The provider later began naming the refund transaction for the
> reference swap, so the explicit-identifier tier now fires for that case. The
> address-history tier and every rule below remain in force.

- **New capability:** a reported BTC refund is now independently confirmed from the
  on-chain payout, not just reported. `bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm`
  reconciles to `REFUND_VERIFIED` when the Bitcoin sources are reachable.
- **Why this works (evidence, not assumption):** 1Click status exposes
  `refundedAmount`/`refundReason` and `originChainTxHashes`, but **no refund tx
  hash**. The refund txid is therefore discovered from the refund address's own
  confirmed history (`GET /api/address/{addr}/txs` on mempool.space/blockstream.info).
- **Correlation anchor is the on-chain recipient, never the amount.** The tool
  reads the intent's withdrawal recipient from the NEAR settlement transaction logs
  (`ft_withdraw` DIP-4 events, recipient of the form `btc:<address>`), then requires
  a **confirmed** Bitcoin transaction paying that address. The quote's `refundTo`
  is only a hint; if it disagrees with the on-chain recipient, nothing is
  correlated and the refund stays reported.
- **New adapter:** `tracesettle/adapters/btc_rpc.py` (Esplora API). Two free hosts
  (mempool.space primary, blockstream.info fallback), no key. 404 → `NOT_FOUND`
  (not failure); both hosts down → `TIMEOUT`/`UNAVAILABLE`.
- **New NEAR extraction:** `utxo_added` bridge events give the Bitcoin origin txid
  (`utxo_storage_keys` = `"<txid>@<vout>"`), the BTC analogue of the EVM
  `BRIDGED_FROM` memo. `_intent_withdrawals` gives the refund destination.
- **Two new safety invariants (now 11 total):**
  `refund_confirmation_requires_onchain_evidence` (a refund stage is confirmed only
  by a `REFUND_TX_CONFIRMED` item with a tx hash) and
  `bitcoin_refund_requires_confirmed_payout` (a Bitcoin refund requires
  `confirmed=True`). `_assess_refund` enforces both; a merely `CONFIRMED` non-refund
  event, a hash-less refund, or an unconfirmed BTC payout can never confirm REFUND.
- **Ambiguous refund payouts are never confirmed.** A Bitcoin refund is confirmed
  only when *exactly one* confirmed payout matches the refund address, or when the
  provider itself names the transaction in `originChainTxHashes`. The real refunded
  swap `bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm` has **four** confirmed payouts to
  its withdrawal recipient (`bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw`) and
  1Click named none of them, so the refund stays `UNAVAILABLE`
  (`AMBIGUOUS_REFUND_PAYOUT`) and the outcome is `REFUND_REPORTED_UNVERIFIED`. The
  tool never picks one by amount or timestamp. Captured history:
  `evidence/raw/btc_address_history.json`; test:
  `test_btc_refund_real_address_history_is_ambiguous`.
- **UPDATE (2026-10-19): the provider now names the refund transaction.** On
  2026-10-19 the 1Click record for this swap listed **both** the refund tx
  (`377b55cb…721f`) and the deposit tx (`9a80de61…1226`) in
  `originChainTxHashes`, so the explicit-identifier path fires: the refund is
  validated (raw bytes fetched, txid recomputed, recipient script matched) and the
  outcome becomes `REFUND_VERIFIED` with the refund `CONFIRMED`
  (`discovery: "explicit"`). The ambiguity rule above is unchanged and still holds
  when the provider names nothing. The solver relay reports `SETTLED` for the same
  intent; both statements are kept as `REPORTED`. Fresh captures:
  `evidence/raw/oneclick_status_btc_REFUNDED.json`,
  `solver_relay_get_status_BTC_REFUNDED.json`,
  `btc_address_stats_refund.json`; offline replay `demo/replay_opener.py:refunded_swap_opener`.
  See `docs/REFUND_VERIFICATION.md` addendum. Lesson: verdicts must follow the live
  evidence, so demo prose is derived from the observed result, never hardcoded.
- **Amount differences are disclosed, not reconciled.** Reported 11746 sats vs
  observed 12884 sats are both printed; the tool does not claim the difference is an
  error (fees may be deducted).
- **Refund stage under a down status source.** `_assess_refund` now takes
  `source_statuses`. If the refund-reporting source (1Click) is unavailable and no
  refund was claimed or found, REFUND is `UNAVAILABLE`, not `MISSING` — with the
  source down we cannot even tell whether a refund was claimed. `MISSING` is
  reserved for the case where the status source answered and reported no refund.
- **Fixture provenance:** `tests/fixtures/synthetic/oneclick_status_btc_REFUNDED.json`
  is synthetic (the 1Click API returned HTTP 521 while writing these tests); its
  Bitcoin txids are real public chain data. Real BTC/NEAR captures live in
  `evidence/raw/`.
- **Tests:** 136 → 224. BTC adapter, refund confirmation rules,
  wrong-address payout, unreachable source, missing on-chain recipient, recipient
  mismatch, ambiguous multi-payout address history, refund state under a down status
  source, and end-to-end determinism.
- **Run:** `python3 -m pytest tests/ -q` (224 passed); `python -m pyflakes tracesettle/ tests/ demo/` clean.

## Bitcoin refund verification — reusable primitives (`btc_verify.py`)

Refund verification was refactored out of `investigation.py` into
`tracesettle/btc_verify.py`, so the rules are testable in isolation and cannot
silently weaken.

- **Address decoding is local and script-level.** `address_to_scriptpubkey` decodes
  P2WPKH, P2TR (bech32m), P2PKH, and P2SH to their exact `scriptPubKey`. Matching is
  done against the script, never the address string. Malformed input returns `None`
  and never raises.
- **Transaction identity is validated against raw bytes.** `compute_txid` recomputes
  the txid as `SHA256d` over the **non-witness** serialization; `verify_tx_identity`
  compares it to the claimed txid. An initial parser bug (hashing witness data) was
  caught by this check and fixed.
- **A txid/bytes mismatch is a contradiction, not a limitation.**
  `investigation._maybe_validate_identity` sets `identity_mismatch` when the returned
  bytes hash to a *different* txid; the refund is then marked `CONTRADICTORY`
  (`TXID_BYTES_MISMATCH`) and the outcome is `CONTRADICTORY`. Failure to *retrieve*
  bytes is only a limitation and never downgrades a stage on its own.
- **Candidate selection is tiered and deterministic** (`select_refund_candidate`):
  `EXPLICIT_IDENTIFIER` (provider-named hash) > `UNIQUE_ADDRESS_MATCH` (exactly one
  confirmed payout, on a **provably complete** address history) > `AMBIGUOUS` >
  `NONE`, with `INCOMPLETE_SEARCH` as a distinct non-answer. Incompleteness only
  blocks *uniqueness*; it never turns zero candidates into ambiguity.
- **History completeness is checked, not assumed.** `fetch_address_history` compares
  the number of transactions actually retrieved against the address's authoritative
  `tx_count`. A mismatch (or an unknown count) yields `complete=False`.
- **Explicit-identifier tier outranks the fallback.** When the provider names the
  refund transaction among `swapDetails.originChainTxHashes`, it is confirmed via
  that anchor (still identity- and script-checked) without relying on address
  history. Test: `test_btc_refund_explicit_named_hash_is_confirmed`.
- **New tests:** `tests/test_btc_verify.py` (23 unit tests: address vectors incl.
  BIP341, txid recomputation, mismatch, candidate tiers) and new adapter tests
  (raw-hex retrieval, outspend, address-history completeness) and investigation
  tests (script-level verification, contradiction, incomplete history, explicit
  hash).
- **Docs:** `docs/REFUND_VERIFICATION.md` Â§6 now documents the tier table and the
  rules the engine enforces.



## Phase 3 closeout — evidence model completeness (2026-10-20)

- **What changed.** `EvidenceItem` gained a first-class `verification_method`
  field (after `evidence_url`, serialized in `to_dict()`). It states *how* a
  classification was reached, so the class and its basis travel together instead
  of the method being left implicit in adapter prose. Populated in every adapter
  (`btc_rpc`, `near_rpc`, `evm_rpc`, `oneclick`, `solver_relay`), the EVM refund
  confirmation path in `investigation.py`, and the `UNAVAILABLE` / `INCOMPLETE` /
  `CONTRADICTORY` marker helpers.
- **Rendered.** The Markdown evidence table (`report.py`) and the web UI
  (`ui.py`) both gained a `Method` column. A reader can now see, per row, that a
  Bitcoin payout was reached by "locally recomputed txid over raw bytes;
  script-level recipient match" rather than by trusting an explorer.
- **Honesty guard.** `refund_payout_evidence` states "explorer-reported" when
  `identity_validated` is false, so the method string never claims a check that
  did not run.
- **Tests.** 222 -> 224. New: `test_btc_refund_evidence_states_its_verification_method`
  and `test_btc_refund_evidence_without_identity_validation_says_so`; the refund
  report test now also asserts the field is populated and the `| Method |` column
  is present. Full suite `224 passed`; `pyflakes` clean; `compileall` OK.
- **Docs.** README classification table gained the missing `INCOMPLETE` row and a
  note on `verification_method`; `docs/REFUND_VERIFICATION.md` section 0 records the
  field alongside the tier/level distinction; the `reconcile.py` docstring now
  lists all 11 invariants (was 9).

## Live re-verification and claims audit (2026-10-19)

Re-checked every external claim against live sources and audited the docs for
stale or overstated statements. The 1Click status endpoint (HTTP 521 earlier)
answered 200 again, and the demo was re-run against real endpoints.

- **The provider now names the refund transaction.** For the reference BTC→TRON
  swap, `swapDetails.originChainTxHashes` now lists both the refund tx
  (`377b55cb...721f`) and the deposit tx (`9a80de61...1226`). The tool's
  explicit-identifier path therefore fires and the refund resolves to
  `REFUND_VERIFIED` (refund `CONFIRMED`, `discovery: "explicit"`). **No code change
  was needed** — a provider hash is a discovery anchor that still passes the same
  raw-bytes txid recomputation and script match as any candidate.
- **A genuine two-source conflict is now visible.** The solver relay reports
  `SETTLED` for the same intent that 1Click reports `REFUNDED`. Both are preserved
  as `REPORTED` evidence; the engine does not silently pick one. The independently
  confirmed facts are the four on-chain stages.
- **Stale prose fixed (claims audit).** README steps 5/7 and the limits list, the
  demo's Case 3 explanation, `TECHNICAL_SUMMARY.md`, `AGENTS.md`, and
  `PHASE1_FEASIBILITY.md` all described the refund as permanently unconfirmable.
  Each now states the conditional rule (confirmed when the provider names it or
  exactly one payout matches; `UNAVAILABLE`/`AMBIGUOUS_REFUND_PAYOUT` otherwise).
  `docs/REFUND_VERIFICATION.md` keeps its historical record and gains a dated
  addendum, rather than rewriting what was true at the time.
- **Demo explanation is now data-driven.** `demo/demonstrate.py:_explain_refund`
  reads `discovery` back from the confirmed evidence instead of hardcoding how the
  payout was found, so the prose cannot go stale when upstream changes.
- **Offline replay extended to Case 3.** `demo/replay_opener.py:refunded_swap_opener`
  replays the captured 1Click status, solver relay, NEAR RPC, Bitcoin tx/hex, and
  address-history responses; `--offline` now runs all three cases with no network.
- **New captures.** `evidence/raw/oneclick_status_btc_REFUNDED.json`,
  `solver_relay_get_status_BTC_REFUNDED.json`, `btc_address_stats_refund.json`,
  documented in `evidence/README.md`.
- **Tests.** 224 → 233. New: `test_offline_refund_replay_confirms_from_a_validated_transaction`,
  `test_offline_refund_replay_preserves_the_conflicting_service_statements`, and
  the updated offline-demo assertion. Full suite `233 passed`; `pyflakes` clean;
  `compileall` OK; offline demo byte-identical across runs.
- **Lesson recorded.** Verdicts must follow the live evidence. Demo/report prose
  that asserts a fixed upstream behavior will go stale; derive it from the
  observed result instead.

## Tier 1/2 interface hardening (2026-10-31, HEAD `b7196e9` + this commit)

Security hardening of the read-only web interface, plus upstream caching. No
runtime dependency was added; the engine and evidence model are untouched, so no
verification was weakened.

- **Slowloris / resource exhaustion.** `InvestigationServer` sets a per-connection
  socket timeout (`TRACESETTLE_CLIENT_TIMEOUT`, default 10s) and a hard
  concurrency cap (`TRACESETTLE_MAX_CONCURRENCY`, default 16) via a
  `BoundedSemaphore`. The slot is taken in `process_request` (the accept loop),
  *before* `ThreadingMixIn` spawns a worker, so a connection flood cannot create
  unbounded threads; `process_request_thread` sets the timeout and releases in a
  `finally`, so a slot is returned on every path. Verified: 50 connections at
  cap 2 spawn 3 threads, not 51.
  Excess connections are answered `503` with `Retry-After` — the rejection
  half-closes and drains the socket so the 503 is delivered rather than lost to a
  RST. `handle_error` suppresses `BrokenPipeError`/`ConnectionResetError`/
  `TimeoutError` noise (a client that disconnects mid-response is normal, and a
  per-event traceback is a log-flood vector).
- **Bounded bodies.** `Content-Length` is validated against the 8 KiB cap before
  the body is read; a stalled read is caught and answered `408`.
- **Auth.** `TRACESETTLE_API_KEY` (env) gates `POST /api/investigate`; comparison
  is `hmac.compare_digest`. The key is never logged or echoed. `GET /` and
  `GET /api/health` stay open. Unset = open (loopback default).
- **Rate limits.** `ratelimit.TokenBucketLimiter` — per-client-IP on the
  investigate endpoint (keyed on `client_address`, so a spoofed
  `X-Forwarded-For` cannot bypass it) and per-upstream-host inside `HttpClient`.
  Bucket maps are LRU-bounded, so cycling keys cannot exhaust memory.
- **Caching.** `cache.TtlCache` — bounded, TTL, single-flight. `HttpClient`
  caches only GETs on `/v0/status`, `/tx/`, `/address/`, keyed on the exact URL,
  and only when `status is OK`; failures/timeouts/NOT_FOUND are never stored.
  A cached value is byte-identical to the live parse, so reconciliation is
  unaffected. POSTs are never cached.
- **Response optimization.** `POST /api/investigate` now returns `{"data": ...}`
  by default; `?format=json|markdown|full` select others, and `full` reproduces
  the old three-key shape for compatibility. The page requests `format=full`.
- **Version disclosure.** `Handler.version_string()` returns `TRACESETTLE`; the
  Python build and package version are not in the `Server` header. Verified live
  with `curl -I`.
- **New modules:** `tracesettle/ratelimit.py`, `tracesettle/cache.py`.
- **New tests:** `tests/test_ratelimit.py` (10), `tests/test_cache.py` (8),
  `tests/test_httpclient.py` (9), plus Phase 1/2/3/5 tests in `tests/test_ui.py`
  (slow client, concurrency cap + recovery, slot release on success/error, body
  bounding, idle-connection bounding, auth required/accepted/rejected/ungated,
  per-IP 429, forwarded-header non-bypass, `Retry-After`, cache reuse through the
  server, format selection, response-size bounds, Server header). `conftest.client_for`
  gained `cache`/`host_limiter`; `running_server(**server_kwargs)` forwards tunables.
- **Counts:** 254 → **304 passed**, 0 skipped; pyflakes clean; compileall OK;
  offline demo byte-identical; all three demo cases unchanged.
- **Verified live** (real server, `curl`): `Server: TRACESETTLE`; unauthenticated
  and wrong-key POST → `401`; correct key → `200`; rapid POSTs → `200 200 429 429`
  at burst 2; `?format=markdown` → Markdown; `?format=xml` → `400`; 20 KB body →
  `413`; `GET /api/health` → `200`; server log contained no key or identifier.

## Tier 1 follow-up — deposit-address classification + status-URL encoding (2026-10-31)

Two launch-critical defects found in review, both fixed with regression tests.

- **Deposit-address classification (`identifiers.py`).** `classify_identifier`
  previously returned `UNKNOWN` for legitimate TRON and legacy-Bitcoin deposit
  addresses. It now recognises each format by its exact encoding, never by length
  or a leading character alone:
  - TRON mainnet — Base58Check, payload `0x41` + 20 bytes, verified checksum.
  - Bitcoin legacy — Base58Check P2PKH (`0x00`) / P2SH (`0x05`).
  - Bitcoin segwit — bech32 v0 / bech32m v1 (delegated to
    `btc_verify.address_to_scriptpubkey`).
  - Solana — a base58 string decoding to exactly 32 bytes (`is_solana_address`);
    recognised by encoding but *not* routed as a deposit address (see below).
  Base58Check decoding moved to the new shared `tracesettle/base58.py`
  (`b58decode`, `b58check_decode`); `btc_verify._b58decode`/`_b58check` now
  delegate to it, so classification and script decoding cannot disagree.
- **Solana is recognised but not auto-classified.** Every 32-byte base58 value
  encodes to 43-44 characters (verified empirically over 25k random keys), which
  is exactly the NEAR-tx-hash / intent-hash window. So a Solana address is
  *indistinguishable* from those by the string alone. `classify_identifier`
  therefore returns `UNKNOWN` for the whole 43-44 char window rather than guess;
  the investigation adds a note naming all three possibilities and offers the
  intent-hash path. `is_solana_address` exposes the encoding check for callers
  that already know the chain. `validate_deposit_address` rejects such a value
  (it has no Solana branch: the ambiguous-hash check captures every real Solana
  key first) with a reason that names both the hash and the Solana key. This is
  the "preserve the assumption, attach a note, never silently reinterpret" rule.
- **Ordering bug caught and fixed while testing.** A 43-char run of `1`s is valid
  base58 and matched the permissive NEAR named-account rule before the ambiguous
  window check, which would have regressed existing intent-hash handling. The
  ambiguous window is now checked before the NEAR account rules in both
  `classify_identifier` and `validate_deposit_address`. `validate_deposit_address`
  also reports *why* a `T…` / `1…` / `3…` value failed (bad checksum) instead of a
  generic message.
- **Status-URL encoding (`adapters/oneclick.py`).** `build_status_url` interpolated
  the address raw into the query string, so `&`, `=`, `?` etc. would be parsed as
  query syntax. It now uses `urllib.parse.urlencode({"depositAddress": ...})`. The
  real HTTP request already used `params={...}` (urlencoded) and is unchanged; the
  string form is now safe too. Tests cover `&`, `=`, `?`, spaces, `/`, `#`, `+`,
  Unicode, an emoji, and a single-parameter round-trip, plus a live-request check.
- **Tests:** 306 → **355 passed**. New `tests/test_identifiers.py` (30) and 15
  new URL-encoding tests in `tests/test_adapters.py`. pyflakes clean; compileall
  OK; offline demo byte-identical to baseline `383e586`.
- **Overload test is deterministic now.** `_reject_overloaded` refuses in the
  accept loop; when it closes before a client finishes uploading its body the
  client sees a connection reset rather than an HTTP status. The test previously
  recorded only HTTP statuses, so that reset made it flaky (~1/40). It now
  records a connection-level refusal as a distinct, expected outcome and still
  requires every request to reach a definite outcome (no hangs), every HTTP
  response to be `200`/`503`, at least one `200` (so the pass is not vacuous),
  and recovery afterwards. Verified 30/30; the refusal path is genuinely
  exercised (4 refusals observed over 720 requests).

## Transaction security layer (guard) — 2026-11-01

The project moved from a settlement investigator to a transaction security
platform. The settlement engine is untouched; a new `tracesettle/guard/` package
sits *in front of* a signer.

- **Honest scope, repeated everywhere.** The guard cannot block an arbitrary
  blockchain transaction. It refuses to release one through a signer that calls
  it. The reference signer (`guard/signer.py`) simulates execution; no real
  transaction is ever signed or broadcast. Do not weaken this into a claim of
  prevention.
- **Vertical slice:** request → 7 deterministic controls → explained decision →
  transaction-bound HMAC authorization → independent signer validation →
  execution or refusal → hash-chained audit record.
- **All seven controls run on every request; no short-circuit.** The decision
  carries the full picture, not the first reason found.
- **An authorization is bound to the transaction, not just authenticated.**
  `service_id`/`operation`/`chain`/`asset`/`amount`/`destination` are canonicalised
  and signed. The signer re-derives the binding from the transaction it was asked
  to sign, so a genuine token minted for a *different* transaction is refused as
  `WRONG_PARAMETERS`. Single-use nonce, 90 s default expiry.
- **Amounts are `Decimal` end to end.** A limit of `0.3` admits `0.3` and refuses
  `0.30000000000000004`. Never parse a client amount with `float`.
- **Severity is compared by `rank`, never by the string value.** `"MEDIUM"` sorts
  after `"HIGH"` alphabetically; a string `max()` silently downgrades an outcome.
  This was a real defect caught by a test.
- **Ten structural invariants** live in `guard/invariants.py`, are exposed at
  `GET /api/guard/invariants`, and are asserted in `tests/test_guard_invariants.py`.
  Each checker is mutation-tested: a checker that cannot fail is a defect. Adding a
  guarantee means adding a checker *and* a mutation test that breaks it.
- **Audit log honesty.** In-place edit/reorder/removal is detected by chain
  recomputation. A whole-log rewrite with recomputed digests is **not** detected;
  `head_digest` is exposed for external anchoring. Do not describe the log as
  tamper-proof. A persistent log resumes its chain from the file on start-up, or a
  restart would break verification.
- **`SecurityMonitor._lock` is an `RLock`.** `open_incident` is called both
  standalone and from inside another locked section; a plain `Lock` deadlocks.
- **Client-supplied approval flags are never honoured** (`approved`,
  `skip_checks`, …). Their presence produces a finding and forces review.
- **Every security control fails closed.** A configured policy file or audit path
  that cannot be read is a hard failure, never a silent fallback to a weaker
  default.
- **No key material in any response.** The signing key is read only by
  `guard/authorization.load_key` from `TRACESETTLE_GUARD_AUTH_KEY`; it is never in
  `config.py`, never logged, never returned. An ephemeral key is generated when
  unset and reported as `ephemeral: true`.
- **Tests:** `python3 -m pytest tests/ -q` (577 passed on this branch after merging
  master, which brought the archive-RPC and deployment work; 185 new guard tests).
  New files:
  `test_guard_controls.py`, `test_guard_authorization.py`, `test_guard_invariants.py`,
  `test_guard_audit_monitor.py`, `test_guard_api.py`, `test_guard_ui.py`,
  `test_guard_end_to_end.py`, plus `tests/guard_helpers.py`. No guard test makes a
  network call; the only substitution is the executor (the real
  `SimulatedExecutor` with a call counter), so "refused" is asserted as "the
  executor was never called".
- **UI:** `GET /console` is the security operations console (single document, no
  third-party origins, restrictive CSP). `tracesettle/guard/console.py` holds it.
  The old investigation page links to it. Console tests assert the required
  sections, ARIA roles, reduced-motion support, and that no third-party origin or
  fabricated `LIVE` badge is present.
- **Hackathon track:** `security` (AI Security & Defense) — the track's own hint is
  "spending limits, policy engines". No LLM was added; decisions are deterministic
  by design, so a model cannot talk its way past the boundary.
- **Not done, and requiring explicit human confirmation:** making the repository
  public, posting the demo on X, sending the submission, and merging the PR.
## Archive RPC fallbacks + container deployment (remediation)

Live data drift: free public RPCs prune history, so the reference case stopped
verifying. The primary `publicnode.com` endpoint returns a **null receipt** for
the ETH→USDC origin (`0xfca11a…`, older than its ~2-day window) and
`free.rpc.fastnear.com` answers `UNKNOWN_TRANSACTION` for the historical NEAR
settlement. Both fixes below are additive; `reconcile.py` and the evidence model
are untouched, so no verification rule was weakened.

- **EVM archive fallbacks.** `ChainRpc` gained `fallback_urls` and an
  `endpoints()` helper (primary first, de-duplicated). `EVM_RPC_MAP` now lists
  archive-capable endpoints per chain (`eth.drpc.org` and
  `eth-mainnet.public.blastapi.io` for `eth`; `…drpc.org` for the rest).
  `evm_rpc.fetch_receipt` walks the endpoints in order.
- **NEAR archive fallback.** `NEAR_RPC_FALLBACK_URLS` (comma-separated,
  `TRACESETTLE_NEAR_RPC_FALLBACK_URL`, default `archival-rpc.mainnet.near.org`)
  is attached to `NEAR_RPC`. `near_rpc.fetch_tx` walks endpoints *and* signers.
- **Fallback answers are validated identically.** A fallback record passes the
  same identity/recipient/transfer checks as the primary. A wrong EVM hash is
  `MALFORMED` and is **not** retried elsewhere (never mis-correlated); a
  wrong-recipient fallback receipt yields a non-`CONFIRMED` transfer check.
- **Honest uncertainty is preserved.** Only a definitive `NOT_FOUND` tries the
  next endpoint; an unreachable endpoint (`TIMEOUT`/`RATE_LIMITED`/…) short-
  circuits — with the source down we cannot tell "absent" from "unknown", and
  fanning out on an outage only adds load. A miss on *every* endpoint stays
  `NOT_FOUND`; an outage stays `UNAVAILABLE`. Neither is ever `FAILED`.
- **Live result.** With the fallbacks, the reference case
  (`0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B`) reproduces `SETTLED_VERIFIED`
  with all four stages `CONFIRMED`; the EVM origin is fetched from `eth.drpc.org`
  and the NEAR settlement from `archival-rpc.mainnet.near.org`.
- **NEAR archive caveat (unchanged).** The free archive is deprecated and
  rate-limits hard (HTTP 429). Under a burst the NEAR stage degrades to
  `UNAVAILABLE`/`REPORTED` (outcome `DELIVERY_UNVERIFIED`), never to a false
  confirmation. Set `TRACESETTLE_NEAR_RPC_FALLBACK_URL` to a paid archive node
  for reliable historical lookups.
- **Container deployment.** Added a minimal non-root `Dockerfile` (uid 10001,
  `HEALTHCHECK` probes `/api/health`, `EXPOSE 8000`) and `.dockerignore`. Runtime
  stays zero-dependency, so the image needs no `pip install`. `serve` now reads
  `TRACESETTLE_HOST` and `PORT`/`TRACESETTLE_PORT` from the environment, so the
  image runs unchanged on Render/Fly/Railway/Cloud Run. Verified: image builds,
  runs non-root, reports `healthy`, and a live `POST /api/investigate` through
  the container returns `SETTLED_VERIFIED`.
- **Tests:** 355 → **372 passed**. New `tests/test_cli.py` (8: serve defaults and
  env-driven host/port/fallback) and 9 archive-fallback tests in
  `tests/test_adapters.py`. pyflakes clean; compileall OK; offline demo
  byte-identical to baseline `2b0213f4…`.
- **Provenance note.** This work reproduces the *content* of a local remediation
  commit (`639e032`) that was created in an earlier sandbox and never pushed; the
  commit object itself is unrecoverable (not on any remote, fork, or local
  object store). It is re-implemented here on top of `a145a89` and independently
  re-verified live.

## Integration with master after PR #3 (2026-11-01)

PR #2 was developed against `a145a89`. After PR #3 merged to master
(`e309fb79`), master was merged *into* the feature branch (merge commit,
parents `d0e3b144` + `e309fb79`) rather than rebasing, so both published
histories are preserved. Conflicts were confined to `AGENTS.md`, `README.md`,
and `tracesettle/config.py` (both sides appended to the same regions); each was
resolved as a union, keeping the guard settings *and* the serve/archive-fallback
settings. `ui.py` auto-merged: it carries the guard routes and the SIGTERM
handler. Full suite on the merged branch: **577 passed**. The 577 = 355 (master
base) + 185 (guard) + 37 (archive RPC + deployment), i.e. the PR #3 delta (392)
plus the guard delta (185) over the 355-test base.

## Phase 1 production hardening (2026-11-01, post PR #2/#3 merge)

Three items on the merged master `69382c5`, none of which recreate existing
functionality. Runtime stays standard-library only; no verification was weakened.

- **Verifiable per-service authentication (`tracesettle/serviceauth.py`).** The
  guard trusts a *declared* `service_id`, so one service could name another and
  inherit its policy. Now a service presents a credential (`X-Service-Credential`);
  `ServiceRegistry` resolves it to exactly one identity and `guard/api.py` refuses
  a request whose declared `service_id` differs with `403`. Only a one-way
  `sha256:` hash is stored (secret shown once at mint); comparison is
  constant-time over every credential; credentials expire, revoke, and rotate.
  Managed by `python3 -m tracesettle credentials mint|list|revoke` (store written
  `0600`; the read-modify-write is serialised with an exclusive `<store>.lock`, so
  concurrent commands cannot lose a change or restore a revoked credential).
  Scoped to the two service-facing routes (`evaluate`, `sign`); the
  administrative incident route stays on the API key, keeping the planes separate.
  When no store is configured the loopback workflow is unchanged.
- **Fail-closed security configuration (`tracesettle/securityconfig.py`).**
  `serve` validates *before* opening a socket. A non-loopback bind without both
  `TRACESETTLE_API_KEY` and `TRACESETTLE_GUARD_AUTH_KEY` exits `2` naming the
  missing variables; only a value that provably parses as loopback is local, so
  an unknown/empty host fails closed. `TRACESETTLE_REQUIRE_SERVICE_AUTH` without a
  store refuses on any binding. There is **no override**: a public bind without
  the required credentials always refuses, so no environment variable can expose
  the endpoints.
- **Automated CI security gates (`.github/workflows/ci.yml`).** On every PR and
  push to `master`: pytest, pyflakes, compileall, offline-demo determinism
  (byte-identical across two runs), a non-stdlib-runtime-import gate, and a Docker
  job (build, non-root uid `10001`, health, graceful shutdown, and a **refusal**
  check with no credentials). `permissions: contents: read`; every third-party
  action pinned to an immutable SHA (`checkout` v4.2.2, `setup-python` v5.3.0);
  no deployment/publish/release; needs no repository secrets.
- **Two new invariants (now 12 total).** `service_identity_cannot_be_forged` and
  `service_credentials_are_hashed_at_rest`, both checked by execution and
  mutation-tested. `_identity_matches` is enforced in `GuardAPI`, not only in the
  socket handler, so a direct caller cannot bypass it.
- **Tests:** 577 → **661 passed**. New `tests/test_serviceauth.py` (28),
  `tests/test_serviceauth_http.py` (12, real sockets),
  `tests/test_securityconfig.py` (25), `tests/test_failclosed_startup.py` (8,
  subprocess through `serve`), `tests/test_cli_credentials.py` (7), the two new
  invariants (2 parametrized) and their mutation tests (2). pyflakes
  clean; compileall OK; offline demo byte-identical (md5 `4864f13c…`).
- **Docker verified live:** image builds; no credentials → exit `2` with
  `refusing to start`; with both credentials → non-root uid `10001`, health
  `healthy`, `Server: TRACESETTLE`, graceful `SIGTERM` exit `0`.

## Durable authorization state (2026-11-01, HEAD `b3432de` + this change)

The guard's security-critical state — spent nonces, revoked authorizations, and
the velocity / volume / rejection counters — was process-local. A restart forgot a
spent nonce (a replay became valid again) and cleared every limit. This change
gives that state a home on disk, without a new runtime dependency.

- **New module `tracesettle/guard/state.py`.** `GuardStateStore` is a stdlib
  `sqlite3` store (`journal_mode=WAL`, `synchronous=FULL`, `busy_timeout`,
  `foreign_keys=ON`). Tables: `consumed_nonces` (nonce `PRIMARY KEY` = atomic
  single-use), `revoked_authorizations`, `counter_events` (DECISION /
  AUTHORIZATION_ISSUED / SIGNER), `idempotency`. Money is an exact decimal
  **string**, never a float. Numbered migrations run in a transaction; a database
  from a newer schema is refused rather than misread. `DurableReplayStore` and
  `DurableRevocationStore` structurally match the in-memory stores, so
  `AuthorizationAuthority` accepts them unchanged.
- **One decision = one transaction.** `GuardService.evaluate` runs the counter
  read, the controls, the idempotency claim, and the counter append inside
  `GuardStateStore.decision_cycle()` (`BEGIN IMMEDIATE`). Without it two
  concurrent evaluations both read an empty window and both authorize past the
  limit — a real breach. `test_without_the_atomic_cycle_the_limit_is_exceeded`
  neutralises the cycle and shows the breach, so the concurrency test is not
  vacuous. Process-local monitor/audit writes happen only after commit.
- **Fail closed, always.** A store error becomes `HOLD` (never `ALLOW`) with a
  `STATE_STORE_UNAVAILABLE` finding; `AuthorizationAuthority.validate` turns a
  consume error into `AuthState.STATE_STORE_UNAVAILABLE` (a refusal). A failed
  write latches the store `degraded` and every later read/write raises, so a
  counter that failed to persist cannot leave a limit silently unenforced.
- **Idempotency.** `request_id` claims a durable `request_key` before issuing an
  authorization, so a retried request is answered from the stored decision and is
  **not** counted twice in the window.
- **Config.** `TRACESETTLE_GUARD_STATE_DB` (unset = in-memory, the loopback
  default) and `TRACESETTLE_GUARD_STATE_BUSY_TIMEOUT_MS` (default 5000).
  `_build_guard_service` hard-fails at start-up on an unopenable policy, audit, or
  state database. The console/metrics report the backend honestly (`sqlite` vs
  `in-memory`).
- **Scope, stated honestly.** A SQLite file is durable state for **one** instance,
  not multi-instance shared state. The narrow `GuardStateStore` interface is the
  seam for a future shared backend; no PostgreSQL dependency is introduced.
- **Invariants:** 12 → **15 total**. New: `durable_nonce_is_single_use_across_restart`,
  `durable_counters_survive_restart`, and `state_store_failure_fails_closed`.
- **Tests:** 661 → **694 passed** (0 skipped). New `tests/test_guard_durable_state.py`
  (27): restart survival, real-HTTP replay refusal across two server lifetimes,
  atomic-cycle concurrency + mutation, degraded latch on a real closed connection,
  corrupt-database refusal, idempotency dedup, and builder/config wiring. pyflakes
  clean; compileall OK; no non-stdlib runtime imports; offline demo byte-identical
  (md5 `4864f13c…`).
- **Docker verified live:** builds; non-root uid `10001`; `/api/health` `200`;
  `Server: TRACESETTLE`; with a mounted writable volume and
  `TRACESETTLE_GUARD_STATE_DB` set, a token signed once is **REFUSED/REPLAYED**
  after a `docker restart` and a fresh token still executes.

### Independent review fix — durable state stays bounded (2026-11-01)

Adversarial review of PR #5 found one real defect; it is fixed on the same branch.

- **Defect: `counter_events` and `idempotency` grew without bound.** `prune_events`
  existed but had **no callers**, so the counter table grew with every decision.
  Worse, the window read (`WHERE at >= ?`) had no leading-`at` index — the v1
  indexes lead with `service_id`/`kind`, so SQLite did a full scan plus a temp
  b-tree. Measured **~1.6 ms/read at 50k rows and rising linearly**; the in-memory
  guard already bounds its equivalents (`deque(maxlen=…)`), so this was a parity
  and availability regression that could eventually stall the enforcement path.
- **Fix.** Schema **v2** adds `counter_events_at(at)` and `idempotency_at(at)`
  (migrated in place; a v1 database keeps its data). `DurableReplayStore` — the one
  object called on every signing attempt — now prunes consumed nonces, old counter
  events, and old idempotency keys on `prune_interval_seconds` (default 300s) with
  retention `TRACESETTLE_GUARD_STATE_RETENTION_SECONDS` (default 24h, well above
  any window). Pruning runs outside the decision transaction so it cannot roll a
  decision back. Measured after the fix: **~0.03 ms/read**, index search, no
  growth with table size.
- **Tests:** 694 → **699 passed** (0 skipped). New in
  `tests/test_guard_durable_state.py`: index-not-scan plan, prune drops old and
  keeps recent events, the signing path triggers the prune, idempotency retention,
  and a v1→v2 in-place migration that preserves data. `test_schema_version_is_recorded`
  now tracks `SCHEMA_VERSION` instead of a hardcoded `1`.
- **Not changed (verified correct, do not "fix"):** durable vs in-memory decision
  parity on identical sequences; cross-process exactly-one-winner and cross-process
  limit enforcement; SIGKILL crash recovery of a committed nonce; expiry and
  revocation surviving a restart; a configured auth key is stable across restarts
  (only an *unset* key mints an ephemeral one, and that is disclosed).
- **Docs:** `docs/DURABLE_STATE.md` §5 documents schema v2, the index rationale,
  and the retention rule; §8 adds the retention variable; README gains a
  **Bounded** bullet and the current count (699).

## PostgreSQL shared guard state (multi-instance durable authorization)

Adds an opt-in, shared durable-state backend so several TRACESETTLE instances
enforce one set of nonces, revocations, counters, and idempotency records. The
default (SQLite/in-memory) path and the settlement engine are unchanged.

- **New module `tracesettle/guard/state_pg.py`** — `PostgresGuardStateStore` +
  `open_postgres_state_store`. `psycopg` is imported **lazily** (inside the
  factory and constructor), so the package still imports nothing third-party at
  module load and the default image stays dependency-free. Selecting the
  PostgreSQL backend without the driver is a hard startup error, never a silent
  downgrade. Schema version 2, same table/index shape as SQLite
  (`BIGSERIAL`/`DOUBLE PRECISION`, `amount` as TEXT).
- **Atomicity, not a retry loop.** SQLite uses `BEGIN IMMEDIATE`; PostgreSQL has
  no equivalent, so `decision_cycle()` takes a transaction-scoped advisory lock
  (`pg_advisory_xact_lock(_DECISION_LOCK_KEY)`) with a bounded `SET LOCAL
  lock_timeout`. A second instance waits, then reads the winner's committed
  counters — deterministic, no re-run. Exceeding the wait is a fail-closed
  `StateStoreConflict`. Retryable SQLSTATEs `{40001, 40P01, 55P03}`.
- **Fail closed, and honest about failure.** A broken store raises
  `StateStoreError` → the guard returns `HOLD` with no authorization, and **never
  falls back to in-memory** (a silent fallback reintroduces the replay the shared
  store exists to prevent). A *dropped connection* is not a broken store: the next
  call reconnects (`_prepare`), so a transient blip does not take an instance out
  of service; a non-connection write failure still latches `_degraded` until
  restart. `_read_cursor` and `_raise_for` translate driver errors so no
  `psycopg` exception escapes the module; the DSN is never logged or put in an
  exception message.
- **Backend selection is explicit.** `open_state_store(path, *, backend="auto",
  pg_dsn=None, ...)` — `auto` (DSN→PG, path→SQLite, else memory), `sqlite`,
  `postgresql`, `memory`. `TRACESETTLE_GUARD_REQUIRE_POSTGRES=1` makes any
  non-PostgreSQL selection a startup error (no override). Config knobs in
  `config.py`: `GUARD_STATE_BACKEND`, `GUARD_STATE_PG_DSN`,
  `GUARD_STATE_PG_CONNECT_TIMEOUT_S`, `GUARD_STATE_PG_STATEMENT_TIMEOUT_MS`,
  `GUARD_REQUIRE_POSTGRES`. `ui._build_guard_service` threads them through;
  `guard/service.py` reports `state.backend` via `getattr(store, "backend", ...)`.
- **New invariant (16 total):** `postgres_shared_state_refuses_cross_instance_replay`.
  It is exercised for real only when `TRACESETTLE_GUARD_STATE_PG_DSN` is set;
  otherwise it reports `holds=True` but says plainly it was **not exercised**
  (never claims a guarantee it did not verify), and it deletes the nonce it
  consumes so an operator pinging `/api/guard/invariants` leaves no residue.
- **Tests:** `tests/test_guard_postgres.py` (21, real server; skip without
  `TRACESETTLE_TEST_PG_DSN`) and `tests/test_guard_state_backend.py` (12).
  `tests/pg_helpers.py` holds the DSN/availability helpers. Fixtures live in the
  test module (not imported from `pg_helpers`) because pyflakes flags
  fixture-as-name imports as redefinitions.
- **CI:** new `postgres` job with a `postgres:16` service runs the distributed
  tests then the full suite. The AST import gate was relaxed to allow a
  non-stdlib import **only** inside a function body and **only** from
  `{psycopg}`; a module-level third-party import still fails the build.
  `requirements-dev.txt` pins `psycopg[binary]==3.3.6` (dev/CI only).
- **Docker:** `--build-arg TRACESETTLE_WITH_POSTGRES=1` adds the driver; the
  default image is unchanged (verified: driver absent, still uid 10001 + healthy).
- **Counts:** 739 tests (716 pass + 23 skip without a server; 739 pass with one);
  pyflakes clean; compileall OK; offline demo byte-identical; default image
  healthy non-root, refuses to start without credentials (exit 2), graceful
  shutdown exit 0. Live two-container proof: token signed by instance A →
  `EXECUTED`, same token on instance B → `REPLAYED`; DB stopped → `HOLD` with no
  authorization; DB restarted → `ALLOW` (recovery).
- **Local dev DB:** `docker run -d --name ts-pg -p 15432:5432 -e
  POSTGRES_USER=ts -e POSTGRES_PASSWORD=devpass -e POSTGRES_DB=tsstate
  postgres:16-alpine`; `TRACESETTLE_TEST_PG_DSN="host=127.0.0.1 port=15432
  dbname=tsstate user=ts password=devpass"`.
- **Not changed (verified correct):** the SQLite/in-memory decision parity, the
  safety invariants, and the settlement engine.
- **Independent adversarial security review (pre-merge), 2026-11-01.** Reviewed
  PR #6 for practical bypasses (nonce replay, limit evasion, idempotency races,
  revocation, cross-service substitution, migration races, every failure path).
  **Two real defects found and fixed, each with a mutation-checked regression test:**
  - **Mid-decision reconnect (state_pg.py).** `_prepare` reconnected whenever the
    connection was closed, *including inside a `decision_cycle`*. A drop after the
    idempotency claim re-ran the remaining writes on a new transaction without the
    advisory lock and still returned `ALLOW`; the claim was lost, so the same key
    was authorized twice. Fix: a connection lost mid-decision is not reconnected —
    the decision fails closed (`HOLD`) and the store is not degraded; ordinary
    (non-decision) calls still reconnect. The exception classification in
    `decision_cycle` now treats a mid-decision `OperationalError`/`InterfaceError`
    as non-retryable (fail-closed `StateStoreError`), not a retryable conflict.
    Tests: `test_connection_drop_mid_decision_fails_closed_without_partial_state`,
    `test_a_mid_decision_drop_does_not_leave_the_store_usable_for_partial_writes`.
  - **Cross-service refusal attribution (signer.py + api.py).** A signer refusal
    was counted against `token.service_id`, attacker-controlled on a forged token.
    An authenticated attacker could name a victim service and, after
    `max_rejected_authorizations` refusals, drive the victim into `HOLD`. Fix:
    attribute to the verified requester (`request.expected_service_id or
    transaction.service_id`), and bind `expected_service_id` in the guard API to
    the authenticated caller, never a body field. Tests:
    `test_refusal_is_attributed_to_the_requester_not_the_forged_token`,
    `test_a_forged_token_cannot_drive_another_service_into_a_hold`,
    `test_sign_refusal_is_attributed_to_the_authenticated_caller`.
  - Everything else refused: concurrent single-token sign on 8 connections executed
    once; 20-thread and 8-process races never exceeded the shared window; replayed
    nonce/token, substituted parameters, wrong service, expired token all refused;
    lock-timeout and statement-timeout failed closed without latching degraded.
    Counts: **739 pass with PG / 716 pass + 23 skip without**; pyflakes clean;
    compileall OK; 16/16 invariants hold; offline demo byte-identical; Docker
    non-root (uid 10001) healthy, guard evaluate→sign→replay verified live.

## NEAR agent protection integration (2026-11-02, `feat/near-security-integration`)

A NEAR integration was added to the transaction security layer, ahead of the
submission deadline. It sits **in front of** a signer; it adds no trading,
swapping, bridging, custody, real signing, or fund recovery. The settlement
engine and its correlation rules are untouched.

- **New package `tracesettle/near/`** (stdlib only): `policy.py` (Intents agent
  policy read + scope analysis), `access_keys.py` (permission analysis),
  `agent_wrapper.py` (the agent-side boundary), `attacks.py` (nine scenarios),
  `settlement.py` (assurance view over the engine), `tee.py` (research only).
- **The wrapper returns one of five outcomes** — `ALLOW`, `REQUIRE_APPROVAL`
  (the mission's "WARN"), `BLOCK`, `HOLD`, `UNKNOWN` — from three independent
  checks, strictest-wins by an explicit severity `rank`. `UNKNOWN` is the
  strictest: "we could not prove it is safe" must never be weaker than a refusal.
  The wrapper reads the **actual parameters**, never the agent's explanation.
- **A policy is in force only when** `status == "APPLIED"` **and**
  `provider_policy_synced == true`. A requested or signed update is never
  active. `IntentsPolicy.in_force` encodes this.
- **The scope gap is stated, not hidden.** An Intents policy's `destinations`,
  `budget_usd`, `timelock_ms`, `schedule`, `owner_approval` protect the INTENTS
  path only. A native NEAR/EVM/Solana request is **not** protected by them; only
  the `native.*` method switch and an independent TraceSettle decision govern.
  `controls_applicable_to` / `controls_not_applicable_to` return the real sets.
- **Access-key facts the code states:** a function-call key cannot transfer NEAR
  and cannot attach NEAR to a call; an omitted `method_names` means **every**
  method; an omitted `allowance` means **unlimited** gas; an unrecognised
  permission is treated as **unrestricted**, never as safe. No private key is
  ever requested, derived, or stored.
- **No endpoint is invented.** With no `TRACESETTLE_NEAR_AGENT_API_URL` the
  adapter reports `UNCONFIGURED`. Fixtures are labelled `local_fixture=True`.
- **Every refusal is provable:** the executor is never called unless the outcome
  was `ALLOW`. Nine scenarios (A–I) assert this.
- **Five new invariants (now 21 total)**, each mutation-tested:
  `near_policy_must_be_in_force`, `near_native_scope_gap_is_always_stated`,
  `near_function_call_key_cannot_transfer_near`,
  `near_provider_success_is_never_verified_without_evidence`,
  `near_policy_selection_is_not_client_controlled`.
- **`/api/guard/near/agent-evaluate` is a service-facing route** and is bound to
  the authenticated service identity in `ui.py` (`_SERVICE_OPERATION_PATHS`).
  Found in review: without this a caller could declare another service's id.
- **TEE is researched, not integrated.** OutLayer is paid and non-refundable, so
  it is out of the zero-budget scope; NEAR AI Cloud attestations are not verified
  by this tool. `assess_verifiable_execution` claims protection **only** with a
  verified attestation. See `docs/TEE_RESEARCH.md`.
- **Tests:** 716 → **851 passed** (24 skipped; 875 with a server). New files
  `tests/test_near_{policy,access_keys,agent_wrapper,attacks,api,invariants}.py`
  plus NEAR cases in `tests/test_guard_ui.py` and `tests/test_serviceauth_http.py`.
  No NEAR test makes a network call.
- **CI** gained a NEAR attack-demonstration determinism step (run twice,
  byte-identical, every scenario must match expectation).
- **Not done, and requiring explicit human confirmation:** making the repository
  public, pushing, posting on X, and sending the submission.

## Independent security audit of the NEAR integration (2026-11-02)

Adversarial review of the NEAR agent-authorization integration. Two real defects
were found; both are fixed with mutation-checked regression tests. The full
suite went 851 → 861 passed, pyflakes clean, compileall OK, both demos
byte-identical.

- **CRITICAL — client-selectable enforcement policy (fixed).**
  `POST /api/guard/near/agent-evaluate` honoured a caller-supplied
  `policy_fixture` (and `agent_id`) *before* the operator's configuration. A
  caller could therefore hand the server a permissive policy and replace the
  operator's restrictive one: reproduced live, an operator-configured
  restrictive policy returned `BLOCK`, and the same request plus a client
  `policy_fixture` returned `ALLOW` / `permits_signing: true`. That is a total
  authorization bypass — the attacker chooses the rules it is judged by.
  **Fix:** policy resolution is now server-side only (operator fixture → Agent
  API → guard policy). `policy_fixture`/`agent_id` are ignored unless
  `TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION` is explicitly on, and that
  flag makes a **public binding refuse to start** (`securityconfig.validate_startup`,
  no override), matching the existing fail-closed pattern. New invariant
  `near_policy_selection_is_not_client_controlled` (21 total, 5 NEAR) plus
  `tests/test_near_api.py` (client fixture ignored, permissive fixture cannot
  flip BLOCK→ALLOW, operator fixture still honoured) and
  `tests/test_near_invariants.py` (mutation). Mutation-checked: reverting the
  guard fails the invariant and the API test.
- **HIGH — fixtures outside the shipped image (fixed).** Runtime code read
  fixtures from `tests/fixtures/near/`, but the Dockerfile copies only
  `tracesettle/` + `README.md`, so every NEAR route raised `FileNotFoundError`
  in the production image. Fixtures now live in `tracesettle/near/fixtures/` and
  are loaded package-relative (`attacks.py`, `guard/api.py`, `guard/invariants.py`,
  `demo/near_demo.py`). Regression test `tests/test_near_packaging.py` rebuilds
  the image layout. Verified: a directory holding only `tracesettle/` +
  `README.md` serves every NEAR route `200` with zero errors.
- **Production outage — wrong database (diagnosed, operator action required).**
  The production deployment returns HTTP 500 on every route. Root cause: the
  configured PostgreSQL DSN points at a database whose `schema_version` table
  says **5**, while the build understands **2**, so the guard refuses to start
  (`refusing to run against it`, exit 2). No code in the repository or its
  entire history ever defined a schema version above 2 (verified by scanning
  every blob in every ref), so the DSN targets a database owned by another
  application — the memory notes point at a shared Neon instance with the PACT
  project. **This is not a code defect:** the fail-closed behaviour is correct,
  and the remedy is to point `TRACESETTLE_GUARD_STATE_PG_DSN` at this project's
  own database (or a fresh one), not to widen the accepted schema range.
- **Verified sound (no change):** the five-outcome boundary and its
  signer-side re-validation (defeats destination substitution after approval);
  `parse_access_key` treating an unrecognised permission as unrestricted rather
  than safe; single-use nonces, expiry, and parameter binding; service-identity
  binding on the NEAR route; no key material in any response.
- **Not done, requires explicit human confirmation:** making the repository
  public, pushing, opening the PR, posting the demo, and sending the submission.

## Console lifecycle journey + duplicate-submit fix (2026-11-03)

Driven from a real browser (Playwright/Chromium) against the shipped server, then
fixed and regression-tested. Two defects, one new capability.

- **One click created two intents.** `#i-submit` carried both an `onclick` and the
  form's `onsubmit`, both calling `createIntent()`. The submit is now bound once,
  through the form only, with an in-flight `IN.busy` guard, a disabled button, and
  a payload-derived idempotency key. The key is threaded to the server as a
  top-level `idempotency_key` (`guard/api.py`), which
  `intents_store.create(..., idempotency_key=...)` already deduplicated on. An
  explicit transaction-level key still wins over the derived one.
- **404 on every console load.** The page requested a favicon that did not exist.
  The console now ships a same-origin inline SVG `<link rel="icon">`; there is
  still no third-party origin.
- **New: wallet-handoff / deposit step.** The Intents Lifecycle tab now shows the
  deposit address, any memo, the quoted fees and the quote expiry, with a copy
  affordance, plus a field to record the deposit hash through
  `/lifecycle/{id}/deposit`. `stepIntent(action, body, targetId)` renders each
  step in its own panel, so quote, handoff, deposit, monitor and assurance are
  distinct. The tool still never signs, sends, or holds funds.
- **Tests:** 924 -> **929**. New regression tests cover the idempotency dedup, the
  transaction-level key precedence, the single submit binding, the handoff and
  deposit elements, and the inline favicon. `pyflakes` clean; `compileall` OK;
  offline demo byte-identical (`4864f13c…`).
- **Publication secret audit (full history, `gitleaks` 8.28.0):** 6 findings, all
  confirmed false positives — the public USDC contract address (`0xa0b8…eB48`,
  flagged by the generic-api-key entropy heuristic in three test files), a
  self-documenting `X-API-Key: totally-invalid-key-123` placeholder used to prove
  a 401, and the vendored 1Click OpenAPI's own `Authorization: Bearer
  YOUR_JWT_TOKEN` example. A targeted scan for real credential formats (PATs,
  cloud keys, JWTs, PEM private keys) over every blob in every ref returned
  nothing. No real credential exists in the history. The remote URL's token lives
  only in the untracked `.git/config`.

## Release-workflow pass: real-HTTP lifecycle acceptance + publication audit (2026-11-03)

Completed the pre-submission release workflow (audit → push → PR → CI). No
verification rule was weakened and no production configuration was touched.

- **Genuine gap closed: the lifecycle was never driven over a real socket.** The
  lifecycle tests in `tests/test_near_lifecycle.py` call the lifecycle object
  directly, so a route registered under the wrong path, gated by the wrong flag,
  or answered without a body would pass every direct-call test and fail in the
  product. `tests/test_near_acceptance.py` now drives the **whole journey over a
  real HTTP socket** (transport substituted, everything else real): create →
  authorize → live quote → approve → status → assurance; a blocked intent cannot
  obtain a fundable deposit address; and the routes 404 when the lifecycle is
  disabled. Counts: 938 → **941 passed, 24 skipped**; `pyflakes` clean;
  `compileall` OK; offline demo byte-identical (`4864f13c…`); near demo
  byte-identical (`037fa3ab…`).
- **Run the suite in a clean environment.** Ambient `TRACESETTLE_*` variables in
  the shell (from a locally launched server) make ~45 tests fail, because they
  read the same config the tests set. Use
  `env -u TRACESETTLE_API_KEY -u TRACESETTLE_GUARD_AUTH_KEY -u TRACESETTLE_INTENTS_DB … python -m pytest tests/ -q`.
- **Branch reconciliation:** `feat/near-security-integration` is a clean
  fast-forward from `master` (`80f8f95`); the recovery commit `d1d17fb` was
  already an ancestor (merged via PR #9). No merge/rebase was needed. Head after
  this pass: `a284c502`.
- **Secret audit of the FULL publication history** (after `git fetch --unshallow`;
  the clone was shallow, so the boundary commit was NOT the whole history).
  Re-run with `gitleaks 8.21.2` (`--log-opts="--all"`) plus targeted greps: 59
  findings, **all confirmed false positives** — 57 `generic-api-key` matches are
  public identifiers (Bitcoin txids, addresses and scriptPubKeys in `evidence/raw/`
  and public EVM token contracts in tests) and the literal placeholder
  `totally-invalid-key-123`; 2 `curl-auth-header` matches are the vendored 1Click
  OpenAPI `Bearer YOUR_JWT_TOKEN` example and a `# no auth header` reproduction
  comment. No private keys, no seed phrases, no PATs, no cloud keys, no JWTs, no
  real credentials. The ephemeral CI Postgres service password
  (`tracesettle:tracesettle`) is a throwaway container credential. **One residual
  exposure, outside this branch:** the unrelated `knotwork-backup` branch (a VR
  prototype, not TraceSettle) carries `.openhands/memory/MEMORY.md` with the
  owner's personal email and sandbox notes. Deleting that branch (or scrubbing the
  file from its history) needs a token with admin rights and the owner's explicit
  decision; it is NOT done here.
- **Repository visibility cannot be changed by this token.** `$GITHUB_TOKEN` is a
  GitHub App installation token (`ghu_`) with `x-accepted-github-permissions:
  metadata=read` and contents write only. REST `PATCH {private:false}` /
  `{visibility:public}`, `gh repo edit --visibility public`, and the GraphQL
  `updateRepository` mutation all return `403 Resource not accessible by
  integration` (GraphQL `UpdateRepositoryInput` does not accept `visibility`/
  `isPrivate`). Changing visibility requires the owner (UI) or a classic PAT with
  `repo` scope.
- **PR #10** (`feat: add NEAR agent authorization and settlement security`, base
  `master`) exists and was updated with the current head and evidence. CI on
  `a284c502` is **green**: all four jobs (Tests and static analysis, PostgreSQL
  shared-state integration, Docker build and runtime, Vercel container image)
  succeeded.
- **Authorized actions completed:** pushed `feat/near-security-integration`
  (`d69f9c8..a284c50`), updated PR #10. **Not done:** merge, production deploy, X
  post, submission.

## Settlement-engine defect fix + independent origin verification (2026-11-04, HEAD `897ebb8`)

Two findings from the final pre-submission audit, both fixed with
mutation-checked regression tests. The reconciliation engine stays deterministic;
no verification rule was weakened.

- **Defect: a reverted origin transaction was reported `CONFIRMED`.** A receipt
  with `status: "0x0"` was still treated as a decisive source-chain deposit,
  because inclusion in a block was taken as success. Inclusion proves the
  transaction was *mined*, not that it *succeeded*. `reconcile.py` now has
  `_is_confirmed_revert()` (an EVM `REVERTED` receipt or `execution_succeeded:
  False`) and a material-conflict branch: a confirmed revert yields
  `CONTRADICTORY`, never `CONFIRMED`. Verified: `reverted origin -> CONTRADICTORY
  | outcome: INCOMPLETE`; a successful origin still confirms; a *reported-only*
  revert stays `REPORTED` (only a confirmed revert is decisive).
- **New safety invariant `reverted_execution_never_confirms`** (12 total). It
  fails if any `CONFIRMED` stage carries a confirmed-revert evidence item.
  Mutation-tested: neutralising `_confirmed_revert` to `False` makes
  `test_reverted_origin_transaction_is_never_confirmed` fail, so the guard is not
  vacuous. `tests/test_safety_invariants.py` grew 4 tests.
- **Gap: the deposit hash was a claim with no independent check.**
  `tracesettle/near/origin_verify.py` (new) reads the origin chain directly and
  returns `OriginVerdict` in {`VERIFIED`, `UNCONFIRMED`, `CONTRADICTORY`,
  `NOT_FOUND`, `UNAVAILABLE`, `UNSUPPORTED`}. Matching is by **explicit
  identifier** — the decoded recipient script/token contract and, when the quote
  states it, the amount — never a provider's word and never amount/timestamp
  similarity. A token deposit requires a matching ERC-20 `Transfer` log; a native
  deposit checks the top-level recipient (the receipt does not carry `value`, so
  the amount is disclosed as not checked, never guessed).
- **Wiring.** `NearIntentsLifecycle._origin_verification()` derives the origin
  chain from the **evaluated transaction** (`decision.transaction.chain`; the
  asset id's `nep141:<chain>-…` prefix is only a fallback — a bridge asset id
  like `nep141:eth.omft.near` does not name its chain). `refresh_status` attaches
  the verdict; `get()` replays the stored verdict with **no second network call**;
  `guard/api.py` exposes `verify-origin`; the console gained the button and
  `renderOriginVerification()`. A check that cannot run (no source, or an outage)
  is reported and never breaks the status read.
- **Assurance evidence is now inspectable.** `StageAssurance` carries
  `supporting_evidence_ids`/`conflicting_evidence_ids` and
  `NearSettlementAssurance` carries the normalized `evidence` list, so a
  `VERIFIED` claim names the exact evidence behind each stage. `report.py` and the
  console thread it through.
- **Live re-check.** The reference ETH→USDC deposit
  (`0xfca11aa0…ba01d2`, deposit address `0xB741c0…A572B`) verifies `VERIFIED`
  against the real chain (receipt status `0x1`, pays the deposit address),
  reproduced across runs. The earlier one-off `UNAVAILABLE`/`MALFORMED` was a
  transient `eth.drpc.org` hiccup, not a defect.
- **Packaging.** New test imports `origin_verify` from a package-only copy, so a
  runtime dependency on the test tree would fail the build.
- **Counts:** 942 → **972 passed, 24 skipped** (996 collected); pyflakes clean;
  compileall OK; offline demo byte-identical (`4864f13c…`); 23 guard invariants +
  12 settlement invariants hold.
- **Secret audit (publication gate).** gitleaks 8.21.2 over the full history (60
  commits) + a targeted high-confidence scan of every reachable blob: **no
  credentials**. Matches are public chain data (Bitcoin output scripts,
  addresses, txids) and a self-documenting `totally-invalid-key-123` placeholder.
- **Repository visibility is still blocked.** The GitHub App token has no
  `Administration` permission: `PATCH /repos` and `gh repo edit --visibility
  public` both return `403 Resource not accessible by integration`, and the
  browser session is logged out. This is a permission limit, not a security
  finding — the secret audit passed. The owner must flip visibility in the UI or
  supply a classic PAT with `repo` scope. No merge, production deploy, X post or
  submission was performed.

## Mission 5 — chain-allowlist bypass fixed; final release pass (2026-11-04)

Live end-to-end execution of the reference ETH→USDC swap through the real
lifecycle exposed a genuine, exploitable defect in the NEAR lifecycle. It is
fixed with mutation-checked regression tests and a new structural invariant.

- **Defect: the evaluated chain was taken from the caller, not the origin asset.**
  `near/lifecycle.py::_chain_of` split an asset id on `-`, so every *native* omft
  asset derived `near` (`nep141:eth.omft.near` -> `near`), and
  `create_and_authorize` used `payload["chain"] or _chain_of(origin_asset)` for
  the value the guard evaluates its chain allowlist against. Two consequences:
  (1) a request that omitted `chain` was evaluated against the wrong chain, and
  (2) a caller could declare `chain: "near"` for an ETH-origin transfer. Either
  let a service permitted on one chain fund a transfer on another — a
  chain-allowlist bypass. Reproduced: a service allowed only on `near` received
  `ALLOW` for a `nep141:eth.omft.near` settlement.
- **Fix.** `_chain_of` now delegates to the canonical `assets.chain_of`, so the
  chain cannot disagree with the guard and the verifiers; and
  `create_and_authorize` derives the chain from the origin asset and **refuses**
  an explicit `chain` that disagrees with it (`LifecycleError`). No legitimate
  flow regresses: omitting `chain`, or declaring the correct one, still allows.
- **Invariant (now 25 total; 9 NEAR).**
  `near_chain_is_derived_from_the_origin_asset` derives the chain from a native
  asset and drives the real lifecycle to confirm a contradicting declared chain is
  refused. Mutation-tested twice: restoring the `"near"` derivation fails it, and
  dropping the conflict refusal fails it.
- **Also fixed in this pass:** the origin-verification fallback used the same
  buggy derivation, so a native ETH origin was checked against `near` and reported
  `UNSUPPORTED`. With the fix, the reference origin verifies `VERIFIED` on `eth`.
- **Tests:** 1000 -> **1007 passed, 24 skipped**; with a local PostgreSQL 17
  (installed via apt for this pass) **1031 passed, 0 skipped**. New: 2 invariant
  mutation tests, 4 lifecycle regression tests, packaging invariant count 24 -> 25.
  pyflakes clean; compileall OK; offline demo byte-identical (`4864f13c…`); near
  demo byte-identical (`a76d72ab…`).
- **Live reproduction (real HTTP, real provider).** The reference swap
  (deposit address `0xB741c0…A572B`) run through the real lifecycle returns
  provider `SUCCESS`, destination verification `VERIFIED` (receipt `0x1`, pays the
  intended recipient), and assurance `SETTLEMENT_VERIFIED` with both legs
  `CONFIRMED` — provider success alone never raises the level.
- **Secret audit (publication gate) re-run:** gitleaks 8.21.2 full history, 59
  findings, all false positives (see above). Repository visibility remains blocked
  (App token lacks `Administration`; browser logged out); the authorized push and
  PR update proceed, the visibility flip does not.
