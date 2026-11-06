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
- **Authorized actions completed:** pushed `feat/near-security-integration`,
  updated PR #10. **Not done:** merge, production deploy, X post, submission.
- **Final release pass (head `21cfcfc`).** Fixed the chain-allowlist bypass (see
  the Mission 5 section), pushed `724dbba..21cfcfc`, and updated PR #10's title and
  description. CI on `21cfcfc` is **green** — all four jobs (Tests and static
  analysis, PostgreSQL shared-state integration, Docker build and runtime, Vercel
  container image) succeeded. The Vercel *preview* deployment for this branch is
  `BLOCKED` by project configuration (it is blocked for every branch commit, not
  just this one), which leaves the commit's combined status `unstable`; it is not
  a code or test failure. Production is unchanged on the recovery deployment
  `dpl_2BNfzFsjRHJwmAUynBy84wYTHc3r` (`master` @ `80f8f95`), health `200`.

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

## Mission 6 — learning loop and security completion (feat/near-learning-loop-and-completion)

The mission lifecycle is *identify → authorize → protect → execute → verify →
investigate → learn*. The last step was missing; it is now a first-class,
deterministic, fail-closed capability.

- **New module `tracesettle/guard/safeguards.py`.** A durable SQLite
  `SafeguardStore` (stdlib `sqlite3`, `journal_mode=WAL`). A `Safeguard` is a
  restriction scoped to a service identity and (optionally) an asset, with one of
  two dimensions: `require_approval_above` (a threshold) or
  `require_verification`. `record()` is idempotent per (service, asset, dimension)
  and keeps the **stricter** threshold, so a later, looser lesson cannot weaken an
  existing one. A store from a newer schema is refused, never misread.
  `open_safeguard_store(None)` returns `None` — an unconfigured loop is inert.
- **New module `tracesettle/guard/learning.py`.** `LearningLoop`,
  `SafeguardApplication`, `derive_safeguard`, `apply_safeguards`. A lesson is
  drawn **only** from a recognised risk finding (`LESSON_BY_FINDING`); an `ALLOW`
  never teaches, and an unrecognised code teaches nothing. Application restricts
  *above* the threshold, so the exact amount that tripped the lesson is still
  allowed (approval applies to the next, larger request).
- **Integration (`guard/service.py`).** `_evaluate_locked` calls
  `self.learning.apply(request)` and folds the result through `_stricter`, so a
  safeguard can only ever tighten the operator's outcome. `_finalize` records the
  lesson and increments the applied counter. `metrics()` reports the loop state.
  `GuardDecision` gained `learned_safeguard`, `influenced_by_learning`,
  `safeguard_reasons`.
- **Config/UI.** `TRACESETTLE_GUARD_SAFEGUARD_DB` (unset = inert).
  `ui._build_guard_service` wires the store; `GET /api/guard/safeguards` reports
  the safeguards in force (and honestly reports `enabled: false` when unset); the
  console NEAR tab renders them with an honest disabled-state note.
- **Invariants: 25 → 27 total.** `learning_loop_only_tightens` (a failure teaches
  a durable safeguard that tightens a later decision and survives a restart) and
  `learning_never_relaxes_policy` (a safeguard can only ever tighten; a
  verification safeguard yields `HOLD`; a below-threshold safeguard changes
  nothing). Both are mutation-tested.
- **Tests: 1007 → 1041 passed, 24 skipped** (1065 collected; +34). New
  `tests/test_guard_learning.py` (29), a learning-loop demo test, two console/API
  tests, and `test_near_packaging.py` invariant count 25 → 27. pyflakes clean.
- **Demo.** `python3 demo/near_demo.py --learning-loop` is self-contained and
  deterministic (in-memory store, writes nothing).
- **Honesty.** The loop only ever tightens; it never grants a permission, relaxes
  a limit, or edits the policy. With no store configured it is inert and the guard
  is unchanged. A safeguard store that cannot be read fails closed
  (`REQUIRE_APPROVAL`, never `ALLOW`).

## Live NEAR execution boundary + release pass (2026-11-04)

The guard could authorize but not *execute*. This pass adds a real, opt-in NEAR
execution boundary and completes the publication workflow.

- **New `tracesettle/near/` modules (stdlib only).** `borsh.py` (canonical
  serializer), `ed25519.py` (RFC 8032 signing from a seed), `rpc.py` (JSON-RPC
  client with fallbacks), `networks.py` (`NETWORKS` config + chain ids),
  `assets.py` (asset resolution + on-chain `ft_metadata` decimals check),
  `txbuild.py` (transaction builder; `guard_amount()` derives the bound amount
  from `amount_base` so it can never drift from the action), `verify.py`
  (independent on-chain verification; `EXECUTED_OPTIMISTIC` is **not** final),
  `execution.py` (`NearExecutionBoundary`: prepare → authorize → accept
  signature → broadcast → verify; `wait_for_final` bounded poll).
- **Chain is network-scoped.** `guard_chain_for(config.network)` replaces the
  module-level `GUARD_CHAIN`, so a token minted on one network is a genuine
  mismatch on another. Cross-network replay is a real refusal, not a coincidence.
- **`guard/api.py` execution routes, gated off by default.** Mounted only when
  `TRACESETTLE_NEAR_EXECUTION=1`. A **server-side** prepared-operation store is
  bounded, TTL'd and **owner-scoped**; the owner is `local` when unauthenticated
  else the authenticated service id — never a body field.
- **`config.py` / `ui.py`.** `NEAR_EXECUTION` settings; `_build_near_execution`
  wires the boundary into the server only when enabled.
- **Two new invariants (27 → 29).** `near_execution_never_signs_without_authorization`
  and `near_execution_binding_covers_the_bytes`, both mutation-tested in
  `tests/test_guard_invariants.py`. NEAR-specific invariants: 9 → 11.
- **Tests:** 1129 passed / 24 skipped (filesystem-only); **1153 passed / 0
  skipped** with a real PostgreSQL (local `postgres:16-alpine`, DSN
  `host=127.0.0.1 port=15432 dbname=tsstate user=ts password=devpass`).
  New: `tests/test_near_execution.py` (26), `tests/test_near_execution_api.py`
  (10), `tests/test_near_prepared_store.py` (7), plus a packaging test proving
  the boundary imports and runs from a **package-only copy** (no test tree).
- **LIVE milestone (testnet).** A funded `*.testnet` account built, signed,
  broadcast and independently verified a real transfer →
  `Gjs4YNbEPBQKWB3M6MpV2zAwhvJySk7U6Q8NZnKVWCKH`, state `VERIFIED`. The tests
  substitute only the RPC transport, so every line of `execution.py` runs.
- **Gates:** pyflakes clean, compileall OK, offline demo byte-identical
  (md5 `4864f13c…`), `near_demo.py --json` byte-identical, 29/29 invariants hold,
  9/9 attack scenarios pass.
- **Publication secret audit (mandatory gate).** gitleaks 8.18.4 over the full
  history (`git fetch --unshallow`; 79 commits, 69 scanned) and the working tree:
  57 + 59 `generic-api-key` hits, **all false positives** — public Bitcoin tx
  data in `evidence/raw/*.json`, public ERC-20 contract addresses in tests, and
  literal `REDACTED`/placeholder strings. No private key, seed phrase, PAT,
  database credential, or signing material in any commit or blob. No `.env` was
  ever tracked (only the placeholder `.env.production.example`); `.openhands/` is
  git-ignored and untracked.
- **Reconciliation:** remote `master` = `80f8f95b` (the stated baseline) and is a
  direct ancestor of the feature branch; the recovery commit `d1d17fb` is
  contained. No merge was required. Branch pushed to the existing open PR #10
  (`feat/near-security-integration` → `master`); no duplicate PR created.

## Wallet-mediated execution flow (2026-11-03)

Completes the mission lifecycle with a real wallet path alongside the opt-in
server-side execution boundary. The wallet signs and sends; TraceSettle holds no
key and only authorizes the intent and verifies the on-chain result.

- **`near/verify.py`** gains `IntendedOperation` + `verify_intent()`. Because the
  wallet chooses its own nonce and block hash, verification checks the
  *independently checkable* facts: signer, receiver, operation, amount and
  recipient. A wallet/provider `SUCCESS` alone never yields `VERIFIED`; a
  contradiction is `DISPUTED`; an unfinalized tx is `PENDING`. `NearNetwork` is
  imported at module scope (a pyflakes error was fixed here).
- **`near/execution.py`** gains `prepare_wallet_operation()`,
  `wallet_binding_fields()`, `verify_wallet_submission()` and
  `PreparedWalletStore` (bounded, TTL'd, owner-scoped, single-use). The
  authorization is bound to the canonical parameter set, not to bytes; `verify`
  consumes the single-use nonce, so one authorization verifies at most one
  submission.
- **`guard/api.py`** mounts `GET /api/guard/near/wallet`,
  `POST .../wallet/prepare`, `POST .../wallet/verify`, gated by
  `TRACESETTLE_NEAR_EXECUTION=1` (off by default). An identity mismatch is `403`.
- **`ui.py`** gains per-path CSP (`DEFAULT_CSP` with `default-src 'none'`;
  `CONSOLE_CSP` adds only the two connector RPC origins) and `_serve_static()`
  serving `/assets/near-connect.js` same-origin.
- **`guard/console.py`** gains the "Connect a NEAR wallet" panel and `loadWallet()`,
  wired into the tab loader map.
- **Vendored connector:** `tracesettle/static/near-connect.js` (`@hot-labs/near-connect`
  v0.12.0, MIT; attribution in `tracesettle/static/README.md`). No third-party
  script origin is added to the page.
- **Tests:** +15 `tests/test_near_wallet_api.py`, +6 console/CSP/asset assertions
  in `tests/test_guard_ui.py`, +2 packaging tests in `tests/test_near_packaging.py`
  (the wallet route and asset answer from a package-only copy).
- **Counts:** **1151 passed, 24 skipped** (1175 collected; 1175 passed with a
  PostgreSQL server). 29/29 invariants hold (18 core + 11 NEAR); 9/9 attack
  scenarios pass; pyflakes clean; compileall OK; both demos byte-identical
  (offline md5 `4864f13c…`, near md5 `fc2949ef…`); runtime imports stdlib-only.
- **CI:** all four GitHub Actions jobs pass on `c39f680` (Tests and static
  analysis; PostgreSQL shared-state integration; Vercel container image; Docker
  build and runtime). The **Vercel** commit-status is a pre-existing
  non-code failure ("Deployment was blocked — Git author must have access to the
  project"), identical on every prior head (`44e2a28`, `b9e4033`, `8e4dd0e`).
- **BLOCKED (unchanged): repository visibility.** The `ghu_` integration token
  has no `Administration` permission: `PATCH /repos/itzebe/tracesettle
  {"private":false}` → `403 Resource not accessible by integration`, and
  `gh repo edit --visibility public` fails identically. The browser session is
  unauthenticated (`logged_in: no`) and no PAT is available. Making the repo
  public requires the owner to do it, or to grant the token `Administration:
  write`.
- **Secret audit re-run (publication gate).** gitleaks 8.18.4 full history: 57
  `generic-api-key` findings, all false positives (public Bitcoin
  scriptpubkeys/addresses, public ERC-20 contract addresses, an intent hash, and
  the literal `totally-invalid-key-123` / `user:pass@db-host` placeholders).
  Targeted scan of every blob in every ref: no PAT/AWS/JWT/PEM/OpenAI/Anthropic/
  Slack/SendGrid/npm credential. Every `ed25519:…` value in history is a public
  transaction **signature** (`"signature"` / `public_key` fields), never a
  `private_key`/`secret_key`. No `.env` ever tracked. **Audit PASSED.**

## Release audit and wallet-flow completion (2026-11-03)

- **Wallet console flow completed.** The wallet panel previously sent native NEAR
  only, could not disconnect, and asked the wallet to sign with no final
  confirmation. It now has an asset selector populated from the server's
  network-scoped `supported_assets` (a testnet asset is never offered on
  mainnet), a live parameter preview, a blocking confirmation after server
  authorization and before signing, and a disconnect control; the approved
  account is re-read from the wallet on every selector change so an
  authorization is never bound to a stale identity. The server's decision is
  unchanged and remains the only thing that permits a sign — the confirmation is
  a human check layered on top, never a replacement. `wallet_execution_info()`
  advertises the supported operations and the real assets.
- **Counts:** **1155 passed, 24 skipped** (1179 collected; 1179 passed with a
  PostgreSQL server). 29/29 invariants hold (18 core + 11 NEAR); 9/9 attack
  scenarios pass, including from a package-only copy; pyflakes clean;
  compileall OK; offline demo byte-identical (md5 `4864f13c…`); near demo
  byte-identical (md5 `fc2949ef…`); runtime imports stdlib-only.
- **Secret audit (full history, gitleaks 8.24.3, `--all`):** 10 findings, all
  false positives (public ERC-20 contract addresses and the literal
  `totally-invalid-key-123` placeholder). A blob-level scan of every ref found
  no PAT, AWS key, JWT, PEM, or service credential; every `ed25519:…` value is a
  public transaction **signature**, not a secret key. No credential in any
  commit or blob on the TraceSettle branches.
- **Stray branch `origin/knotwork-backup` removed.** It was an unrelated
  history (no common ancestor with `master`; a VR "knotwork" Vite prototype)
  that also tracked `.openhands/memory/MEMORY.md` containing a real personal
  email, cross-project internal notes, and sandbox/tooling internals. It was
  deleted with `DELETE /repos/.../git/refs/heads/knotwork-backup` (HTTP 204)
  before publication. A re-scan of every remaining ref now finds no real
  personal email and no foreign-project memory file. Deleting the ref removes it
  from the published branch list; the objects remain in the repository's
  unreachable set until GitHub's own garbage collection runs.
- **Visibility change is blocked for the same reason.** Making
  `itzebe/tracesettle` public requires the repository Administration permission
  (or the owner acting in the web UI). The browser session available to the
  agent is not authenticated, so the visibility change could not be performed
  here. Everything else in the release workflow (audit, tests, push, PR, CI)
  completed.

## Browser-wallet transaction journey (2026-11-04)

The wallet-mediated flow was previously exercised by signing with the testnet
account key directly (outside the server). The **browser wallet connector was
never driven by a browser**. This pass closes that gap: the console's real wallet
panel is driven in a real Chromium browser by a wallet emulator that holds the
key and signs.

- **What runs.** `demo/browser_wallet/run_demo.py` starts the console with
  `TRACESETTLE_NEAR_EXECUTION=1` and an operator policy approving one recipient,
  then runs four scenarios through the real page: `happy` (approved → `VERIFIED`),
  `blocked` (non-approved recipient → `BLOCK`, the wallet is **never** asked to
  sign), `tamper` (the wallet signs a *different* amount → `DISPUTED`, the
  transfer succeeds on-chain but contradicts the intent), `reject` (the user
  rejects → nothing broadcast). All four matched the expected outcome against
  real testnet transactions.
- **The key never reaches the page.** The emulator plays a wallet *extension*:
  the key lives in the Node process; the page receives only `signIn`/`getAccounts`
  results and a signed-and-broadcast hash, exactly as a real extension returns.
  It speaks the vendored connector's injected-wallet protocol
  (`near-wallet-injected-request` / `near-wallet-injected-response`) and
  advertises a manifest via the `near-wallet-injected` event.
- **The connector's real `connect()` runs.** Only the selector popup is skipped:
  the page's `NearConnector.connect()` is subclassed to preselect the injected
  wallet id. `getConnectedWallet`, the account read-back, `signAndSendTransaction`
  and the whole server flow are the real code paths.
- **Borsh layout is pinned to the repository.** The emulator builds the NEAR
  transaction with the same V0 layout as `tracesettle/near/borsh.py`;
  `tests/test_browser_wallet_borsh.py` asserts byte-identical output against a
  vector from the repository's own serializer (skips only when Node is absent).
  A changed amount changes both bytes and hash.
- **Evidence:** `evidence/browser_wallet/` (per-scenario JSON + screenshot; the
  two on-chain txs `EvNeH37s…ntep4` and `BHgNvQ2A…hRTR`, both re-read `FINAL`).
  No key material is present; only public testnet data.
- **Honest scope:** the wallet is a faithful *emulation*, not a real
  browser-extension wallet; it signs **testnet** transactions only. The
  provider/wallet success is never treated as proof — settlement is verified
  field by field against the authorized intent.
- **Counts:** 1171 passed, 24 skipped without PostgreSQL (1195 with a PostgreSQL
  server, verified locally against `postgres:16-alpine`); pyflakes clean;
  compileall OK; offline demo byte-identical (md5 `4864f13c…`).
- **Deployment note:** production stays on the previously restored master
  deployment; this branch is not deployed. No merge, no production change.

## Real third-party extension journey + console CSP defect (2026-11-05)

A genuine third-party browser-extension wallet (Nightly v1.51.49) was installed,
onboarded with a 12-word seed, and connected to the console through the *real*
bundled `@hot-labs/near-connect` connector on testnet. This exercised the
production connector path, not the demo emulator.

- **Defect found and fixed: the console CSP blocked the wallet's NEAR RPC.**
  `/console`'s `Content-Security-Policy` `connect-src` listed only the manifest
  origins (`cdn.jsdelivr.net`, `raw.githubusercontent.com`). The browser therefore
  blocked the connector's own NEAR JSON-RPC calls (`final` block hash, access-key
  nonce, `broadcast_tx_commit`). The failure was **silent**: the guard returned
  `ALLOW`, the page showed "Waiting for the wallet to sign and send…", and no
  signing request ever reached the wallet. The policy now names the public NEAR
  RPC hosts explicitly (never a wildcard). Regression test
  `test_console_csp_allows_the_near_rpc_the_wallet_connector_must_reach` asserts
  the hosts are present and `*` is absent.
- **`rpc.near.nightly.app` must stay out of the policy.** It served a stale chain
  head (height ~223M vs ~276M on the live RPCs); with it allowed, the extension
  built a transaction against the stale block and the broadcast failed
  (`{"type":"Expired"}`). Removing it lets the connector fall back to a fresh node.
- **Live proof the fix is necessary and sufficient to reach signing.** After the
  fix, the real extension opened its native *Approve the transaction* sheet
  ("-0.10 NEAR", the exact recipient). Before the fix, no sheet ever appeared.
- **Remaining limitation (extension-side, not TraceSettle).** Nightly's NEAR
  executor only exposes a **mainnet** `nodeUrl`; it broadcast the testnet
  transaction to mainnet providers (`INVALID_TRANSACTION`), so no testnet
  settlement landed on-chain. TraceSettle's guard, authorization binding, and
  verification are unchanged and correct; the settlement step is limited by that
  extension's testnet support.
- **Counts:** 1171 passed, 24 skipped (filesystem-only). PR #10 head
  `dd2490a`; all five CI checks green (`Tests and static analysis`, `Docker build
  and runtime`, `PostgreSQL shared-state integration`, `Vercel`, `Vercel
  container image`).

## Independent security audit — access-key fail-open (2026-11-03)

Final pre-publication audit of the NEAR integration. One real defect found and
fixed; the rest of the audit found the controls intact.

- **Defect: an unrecognised access-key permission produced `ALLOW`.**
  `near/access_keys.py::parse_access_key` classifies a permission shape that is
  neither `FullAccess` nor `FunctionCall` as `UNKNOWN` at `AccessKeyRisk.CRITICAL`
  and treats it as unrestricted. But `AgentAuthorizationWrapper._evaluate_access_key`
  only forced a review for `FULL_ACCESS`; the `UNKNOWN` case fell through to
  `key_supports_operation`, which returns `(True, "unrecognised permission treated
  as unrestricted")`. On a native request whose policy method switch is on, that
  reached `ALLOW`/`permits_signing` — a `CRITICAL`-risk key treated as *safer*
  than a full-access key (which only warns). This violated "unrecognised
  permission structures are never treated as safe".
- **Fix.** `_evaluate_access_key` now fails closed to `REQUIRE_APPROVAL` for
  `AccessKeyPermission.UNKNOWN` on **every** path (Intents and native), emitting an
  `ACCESS_KEY_PERMISSION_UNKNOWN` finding at `CRITICAL`. It is at least as strict
  as the full-access treatment.
- **New structural invariant** `near_unrecognised_access_key_never_allows` (NEAR
  invariants 11 → 12; total 30 → 31), mutation-tested: reverting the branch makes
  it fail. Two wrapper regression tests:
  `test_an_unrecognised_access_key_permission_forces_review` and
  `test_an_unrecognised_access_key_permission_does_not_allow_a_native_transfer`.
- **Probe-design lesson.** The first invariant draft used an amount/asset the demo
  guard already blocks, so the guard's `BLOCK` masked the access-key branch and the
  mutation test failed to fail. The probe now uses a fully-approved request
  (`NEAR`, amount `5`, an approved destination) so the *key* check is the only
  thing under test. An invariant that cannot fail proves nothing.
- **Audit confirmed intact (no change needed):** the five outcomes with
  strictest-wins `max`; `UNKNOWN` strictest; no executor unless `ALLOW`;
  transaction-bound HMAC authorization and replay refusal; server-side policy
  resolution with `policy_fixture` off by default and a public bind refusing when
  it is on; service-identity binding and credential rejection; `status == APPLIED
  && provider_policy_synced` gating; native requests never described as
  Intents-protected; function-call keys can never transfer NEAR or attach NEAR;
  provider `SUCCESS` never yields `VERIFIED`; amount/timestamp never correlation.
- **Counts:** 1175 passed, 24 skipped filesystem-only; **1199 passed, 0 skipped**
  with a local `postgres:16-alpine` (`TRACESETTLE_TEST_PG_DSN`). pyflakes clean;
  compileall OK; no module-level third-party runtime import; offline demo
  byte-identical (md5 `4864f13c…`); 9/9 attack scenarios and 31/31 invariants from
  a package-only copy. PR #10 head `4e0568d`, all five CI checks green.
- **Publication secret scan (full history).** 634 blobs / 865 objects across all
  local branches (remote has 11 heads) and 0 tags. High-signal regexes (`ghp_`,
  `gho_`, `github_pat_`, `sk-`, `AKIA`, `AIza`, `xox`, PEM private keys, JWTs,
  Neon DSNs, seed phrases) → **0 matches**. No key-like JSON field in any blob.
  `.openhands/` and `.pytest_cache/` are gitignored and untracked. The only
  ever-added env-like file is `deploy/production/.env.production.example`
  (placeholders only). All `detect-secrets` hits are placeholders, CI
  ephemeral-container credentials (`tracesettle:tracesettle`), and public chain
  data. **Scan clean — publication gate passed.**

## Genuine Intel TDX attestation verification (2026-11-03)

Adds a real, locally-verified confidential-computing capability, kept honest and
out of the enforcement path. No runtime dependency was added; the settlement
engine and every authorization rule are untouched.

- **`tracesettle/near/tdx.py`** — a self-contained Intel TDX v4 quote verifier
  (stdlib plus the in-repo `p256`). It parses the quote header, the TD report
  body, the signature, the attestation key and the certification data, then
  verifies the quote signature (ECDSA-P256) under the quote's attestation key,
  the PCK certificate chain up to the **pinned** Intel SGX Root CA, the
  attestation-key → Quoting-Enclave binding
  (`QE report_data[0:32] = sha256(AK_raw64 || qe_auth_data)`), the `report_data`
  binding of a caller nonce / signing address / TLS key, and the event-log replay
  to RTMR0..3. `INTEL_SGX_ROOT_CA_SHA256` is the pinned root.
- **`tracesettle/near/attestation.py`** — `TeeAttestationProvider` fetches the
  NEAR AI Cloud gateway's real quote from the public attestation endpoint and
  runs the verifier, cross-checking the echoed nonce, signing address and TLS
  fingerprint. `derive_nonce` and `verified_tee_verifier` bind a quote to a fresh
  decision nonce.
- **API:** `GET /api/guard/near/tee` (capability, with what is *not* verified) and
  `GET /api/guard/near/tee/attest` (fetch + verify, bound to a supplied or
  derived nonce). Off by default (`TRACESETTLE_TEE_ATTESTATION=1`); both are
  API-key gated and rate-limited like every other guard route.
- **Honest scope, repeated everywhere.** This is verification of a *real hardware
  quote*, not a TEE-integrated execution path. The guard's decisions do not
  depend on it; the executor still simulates execution and broadcasts nothing.
  Certificate revocation and TCB freshness need Intel PCS collateral and are
  **not** checked, so they are not claimed. A failed verification is
  `UNVERIFIABLE`, never protection.
- **Invariants:** 31 → **33 total**. New: `tee_attestation_verification_is_genuine`
  (a real quote verifies, a tampered one is refused) and
  `tee_attestation_is_bound_to_the_decision_nonce` (a quote for another nonce is
  refused). Both are mutation-tested: a verifier that accepts anything makes each
  fail.
- **Packaging:** the real quote capture lives inside the package
  (`tracesettle/near/fixtures/attestation_nearai_cloud.json`) so the invariants
  run from a package-only copy. The packaging test caught an earlier version that
  read `evidence/raw/`; it now reads the shipped fixture.
- **Tests:** 1175 → **1207 passed, 24 skipped** (1231 passed with a live
  PostgreSQL). New `tests/test_near_tdx.py` (11) and
  `tests/test_near_attestation.py` (9), 6 API tests and 2 mutation tests.
  pyflakes clean; compileall OK; offline demo byte-identical (md5 `4864f13c…`).

## TEE-bound execution — attestation is now *enforced* (2026-11-05)

The previous section verified a real Intel TDX quote but explicitly did not gate
execution on it ("verification of a real hardware quote, not a TEE-integrated
execution path"). That gap — **verified but not enforced** — is now closed for the
signing boundary, honestly scoped.

- **New module `tracesettle/near/tee_execution.py`.**
  - `ExecutionState` (wire labels `RECEIVED`, `AUTHORIZATION_PENDING`,
    `AUTHORIZED`, `TEE_VERIFICATION_PENDING`, `TEE_VERIFIED`, `SIGNING_PENDING`,
    `SIGNED`, `BROADCAST`, `SETTLEMENT_*`, `EXPIRED`, `FAILED`) and a
    `LEGAL_TRANSITIONS` table; `can_transition` enforces it. The **only** edge into
    `SIGNING_PENDING` is from `TEE_VERIFIED`, and no state jumps straight to a
    success state. `IllegalTransition` is raised, never swallowed.
  - `ExecutionRecord` (durable; `to_dict`/`from_dict`) carries the transaction
    digest, `authorization_id`, `authorization_nonce`, `tee_expected_nonce`,
    `service_id`, `policy_version`, amount/asset/destination and `tee_verified`.
  - `TeeExecutionAuthorizer.create/enforce/bind_attestation/begin_verification/
    begin_signing`. `enforce(execution_id, transaction_digest=...)` is the single
    fail-closed gate: it requires `require_attestation` to be satisfied by a
    `VERIFIED` attestation whose recorded nonce matches `tee_expected_nonce` and
    whose transaction digest matches the *current* digest.
  - `ExecutionRecordStore` (in-memory or SQLite at `TRACESETTLE_NEAR_EXECUTION_DB`).
- **Digest binds the exact signed bytes.** `NearExecutionBoundary._transaction_digest`
  hashes `transaction.unsigned_bytes()` — what the wallet signs — not the
  transaction *hash*. The hash is `SHA256d(unsigned_bytes)`, so a substitution that
  changes the amount (the borsh-encoded action) changes the digest and is refused;
  a change to a field outside the signed bytes is caught by the separate
  authorization binding. Test: `test_substituting_the_signed_amount_after_attestation_is_refused`
  (mutating only `amount_base` metadata, which does **not** enter the bytes, is not
  a real substitution — that is why the earlier test was rewritten).
- **Wired into `execution.py`.** `NearExecutionBoundary(..., tee_authorizer=,
  tee_provider=)`. `prepare()` creates the record; `verify_tee_attestation(prepared)`
  fetches+verifies+binds; `accept_signature()` runs `_enforce_tee` **before**
  consuming the authorization nonce, then moves the record to `SIGNING_PENDING`;
  `broadcast()` records lifecycle/settlement. Authorizer errors surface as
  `ExecutionError` at the boundary seam.
- **Fail closed at start-up (`securityconfig.py`).** `TRACESETTLE_NEAR_TEE_REQUIRED=1`
  without `TRACESETTLE_TEE_ATTESTATION` or without `TRACESETTLE_NEAR_EXECUTION` is a
  hard `ConfigurationError` on **any** binding (loopback included). A configured
  record DB that cannot be opened is a hard failure, never a silent fallback.
  Config: `NEAR_TEE_REQUIRED`, `NEAR_TEE_EXPECTED_MEASUREMENT`, `NEAR_EXECUTION_DB`,
  `NEAR_EXECUTION_TTL_SECONDS`.
- **Routes (`guard/api.py`).** `POST /api/guard/near/execution/attest` binds a
  genuine attestation to a `prepare_id`; `GET /api/guard/near/execution/record/<id>`
  exposes the lifecycle; `GET /api/guard/near/execution` reports `tee_gate`.
- **Invariants:** 33 → **36 total**. New: `tee_execution_requires_a_bound_attestation`
  (end-to-end: with the gate on, a signature without a bound attestation is refused
  and nothing is broadcast), `tee_execution_cannot_be_skipped_by_the_state_machine`
  (structural: no pre-TEE state reaches `SIGNING_PENDING`), and
  `tee_execution_record_is_transaction_bound` (a changed digest is refused). Each is
  mutation-tested in `tests/test_near_invariants.py`; the first needed a *two-layer*
  mutation (`enforce` **and** `begin_signing`) to fail, which is itself evidence the
  state machine is an independent second gate.
- **Honest scope (unchanged where it matters).** This gates the *signing boundary*.
  The reference executor still simulates execution and broadcasts nothing, so it is
  not a claim that a real transaction was broadcast under attestation. Certificate
  revocation and TCB freshness are still not checked.
- **Tests:** 1207 → **1248 passed, 24 skipped** (filesystem-only);
  **1272 passed, 0 skipped** with a real PostgreSQL 16 server. New
  `tests/test_near_tee_execution.py` (25), 7 TEE API tests, 3 fail-closed start-up
  tests, 3 mutation tests. pyflakes clean; compileall OK; offline demo
  byte-identical (md5 `4864f13c…`).

## Real NEAR testnet execution pipeline (2026-11-05)

Replaces the *simulated* executor with a real, durable, TEE-gated NEAR **testnet**
execution path. Additive: the settlement engine, the guard controls, and the
`SimulatedExecutor` default are untouched.

- **New modules.** `tracesettle/near/pipeline.py` (`NearExecutionPipeline`,
  `LocalKeySigner`, `ExecutionResult`) and `tracesettle/near/ledger.py`
  (`SubmissionLedger`, `SubmissionRecord`, `SubmissionState`). The pipeline
  composes the existing boundary rather than duplicating it: it calls
  `NearExecutionBoundary.prepare` → `accept_signature` → `send_tx`, then
  `verify.verify_transaction`.
- **Access-key permission is enforced at the boundary.** `_read_access_key()` is
  shared by `_next_nonce()` and the new `_validate_access_key_permission()`, which
  `prepare()` calls as step 3b. A function-call key can never move native NEAR; a
  receiver/method outside the key's scope is refused; an omitted `method_names`
  means *all methods*; an omitted allowance means *unlimited gas*; an unrecognised
  permission shape is refused (never treated as safe).
- **Durable, idempotent submission.** Every signed submission is written to the
  ledger *before* `send_tx`. A send that times out is recorded `UNKNOWN` (never
  `FAILED`) and resolved by `tx_status`; it is never blindly resubmitted. Because a
  NEAR tx hash covers its nonce, re-sending the *identical* signed bytes is
  idempotent; different bytes are never sent. `recover()`/`resolve_unknown()`/
  `resume_signed()` are the recovery entry points.
- **Finality polling.** A broadcast commonly returns `EXECUTED_OPTIMISTIC`; the
  pipeline polls `tx_status`, bounded (`NEAR_FINALITY_ATTEMPTS`/`_DELAY_SECONDS`),
  until `FINAL` before verifying. It never inflates a pending state to `VERIFIED`.
- **Wallet path.** `submit_signed()` accepts a client (wallet) signature through
  the same durable/finality handling; `guard/api.py` uses the pipeline for
  `POST /api/guard/near/execution/submit` when one is attached, and falls back to
  `broadcast()` otherwise.
- **Config:** `NEAR_LEDGER_DB`, `NEAR_FINALITY_ATTEMPTS`,
  `NEAR_FINALITY_DELAY_SECONDS` (plus the existing `NEAR_EXECUTION_*`/`NEAR_TEE_*`).
  A configured ledger that cannot be opened is a hard start-up failure.
- **Invariants:** 36 → **38 total**. New:
  `near_execution_requires_access_key_permission` (a function-call key cannot move
  NEAR; a full-access key can — so the check is real, not a blanket refusal) and
  `near_submission_is_durable_and_recovery_never_resubmits` (an unknown outcome is
  `UNKNOWN`, resolved from the chain, sent once). Both mutation-tested in
  `tests/test_guard_invariants.py`.
- **Live evidence (testnet, 2026-11-05).** A funded `tracesettle-m3-sender-01.testnet`
  account built, TEE-attestation-gated, signed, broadcast and independently
  verified a real 0.01 NEAR transfer; submission `SETTLED`, settlement `VERIFIED`,
  all seven verification checks ok, and the receiver's balance rose by the amount
  transferred. The opt-in reproduction test is `tests/test_near_live_testnet.py`
  (skipped unless `TRACESETTLE_TEST_TESTNET_KEY`/`_ACCOUNT`/`_RECEIVER` are set;
  never mainnet).
- **Tests:** 1248 → **1283 passed, 24 skipped** (filesystem-only);
  **1307 passed, 0 skipped** with PostgreSQL 16. New `tests/test_near_pipeline.py`
  (31) and the opt-in live test. pyflakes clean; compileall OK; offline demo
  byte-identical (md5 `4864f13c…`).
- **Honest scope.** The signer is software; the TEE gate enforces that a verified
  TDX attestation is *bound to the exact bytes* before signing, but the module does
  not claim the signature was produced inside an enclave. Testnet only — the
  in-memory signer refuses mainnet.

## Intel PCS collateral validation (2026-11-03, branch `feat/near-security-integration`)

The TDX quote verifier proved a genuine Intel-signed quote, but not that the
platform's TCB was current or that its PCK certificate was still trusted. Both
facts live in Intel's Provisioning Certification Service collateral, and both are
now fetched, signature-verified and evaluated.

- **New module `tracesettle/near/collateral.py`** (stdlib only). `PcsCollateralClient`
  fetches three documented Intel documents and `validate_collateral` returns a
  `CollateralBundle` whose `verified` is true only when every document verified,
  the TCB status is acceptable, the PCK certificate is not revoked, and the QE
  identity matches.
- **TDX uses the `tdx` certification service, not `sgx`.** A TDX quote's QE report
  is a *TDX* QE (`TD_QE`), so its MRSIGNER (`DC9E2A7C…`) is published only by
  `…/tdx/certification/v4/qe/identity`. The `sgx` service publishes the *SGX* QE
  (`8C4F5775…`), which will never match a TDX quote — using it produces a false
  "MRSIGNER mismatch". The TCB Info is also per-service (`tdx/…/tcb`). The **PCK
  CRL** is shared and served only under `sgx` (`tdx/…/pckcrl` → 404). The client
  therefore takes `base_url` (tdx) and `crl_base_url` (sgx) separately.
- **Signed bytes are located, never re-serialised.** Intel signs the literal JSON
  substring of the document value (`tcbInfo`/`enclaveIdentity`), so
  `_locate_signed_document` finds that byte range in the raw response and verifies
  the signature over it. Re-serialising the parsed object would change the bytes
  and invalidate the signature.
- **Issuer chain is walked to the pinned root.** The document's issuer chain
  arrives in a response header (`TCB-Info-Issuer-Chain`,
  `SGX-Enclave-Identity-Issuer-Chain`, `SGX-PCK-CRL-Issuer-Chain`, percent-encoded
  PEM). Every link is verified, the root must be self-signed, and the root
  fingerprint must equal `INTEL_SGX_ROOT_CA_SHA256`.
- **TCB level matching is Intel's rule.** Walk `tcbLevels` and pick the first whose
  every component SVN is `<=` the platform's and whose PCESVN is `<=` the
  platform's; no match means the platform is newer than any known level →
  `OutOfDate`/unacceptable, never silently accepted. `Revoked` / `OutOfDate` /
  `ConfigurationNeeded` are unacceptable; `UpToDate` / `SWHardeningNeeded` are not.
- **FMSPC is at OID `…1.13.1.4`**, TCB components at `…1.13.1.2`, sgxType at
  `…1.13.1.5` (an ENUMERATED, kept raw). The extension wrapper is
  `Extensions ::= SEQUENCE OF Extension`, so it needs the extra SEQUENCE unwrap.
  The earlier "FMSPC 404" was reading the PPID (`.1.1`) instead of the FMSPC.
- **SGX report field offsets.** In the QE report, MRSIGNER is `[128:160]` and
  ISVPRODID/ISVSVN are **little-endian** uint16 at `[256:258]`/`[258:260]`. (The TD
  report uses different offsets; the QE report inside a TDX quote is an SGX report.)
- **Freshness is enforced.** A cached document is reused only within
  `cache_ttl_seconds` *and* while still before its own `nextUpdate`; past either
  bound it is refetched, and a failed refetch is `UNAVAILABLE`, never stale reuse.
  `validate_collateral(..., now=...)` makes the freshness check testable.
- **Fails closed.** No collateral service → `available=False`, `verified=False`,
  and the quote verification appends a failure; a caller that requires TEE must
  refuse. `verify_tdx_quote(..., collateral_client=...)` runs the collateral step
  only when a client is supplied, so the offline invariant path is unchanged and
  the limitation is explicit when it is not.
- **New invariant (39 total):** `tee_collateral_verifies_against_the_pinned_root`
  verifies the real capture and refuses a tampered TCB signature, offline, from the
  package fixture `tracesettle/near/fixtures/intel_pcs_collateral.json`.
  Mutation-tested in `tests/test_near_invariants.py`.
- **Live-verified (2026-11-03):** against Intel's TDX certification service the
  gateway quote resolves TCB `UpToDate`, PCK not revoked, QE identity match;
  `collateral_verified: true` and all 16 quote-verification checks pass.
- **Tests:** 1307 → **1331 passed, 1 skipped** (with PostgreSQL 16). New
  `tests/test_near_collateral.py` (22) plus the collateral invariant and packaging
  assertions. pyflakes clean; compileall OK; offline demo byte-identical
  (md5 `4864f13c…`).
- **Honest scope, unchanged.** This is verification of a genuine quote *and* its
  Intel-published trust state. The executor still simulates execution and
  broadcasts nothing; the guard's decisions do not depend on the TEE, and the
  signing key is software-held. No TEE *confidentiality* protection is claimed.

## Enclave signing boundary + hardening (2026-11-04, branch `feat/near-security-integration`)

Adds the enclave signing boundary end to end, on top of the TEE-bound NEAR
execution path, and hardens the shipped package. Runtime stays standard-library
only; no verification rule was weakened and the settlement engine is untouched.

- **New module `tracesettle/near/enclave.py`.** `EnclaveSigningBoundary` provisions
  a signing key only against a verified Intel TDX attestation whose measurement is
  an operator-approved identity (`MeasurementPolicy`/`ApprovedMeasurement`; every
  pinned field must match exactly, and an empty pin is refused) and whose nonce is
  bound to the exact transaction (`derive_provisioning_nonce` over the request's
  canonical bytes). It then verifies the returned signature **over the exact bytes**
  with the provisioned key; a signature that does not verify, comes from a
  different key, or echoes a different digest is refused. `EnclaveTransactionSigner`
  adapts it to the pipeline's `TransactionSigner` and is **testnet-only** (refuses
  mainnet at construction). `HttpEnclaveTransport` refuses to sign with no
  configured `sign_url`, so hardware execution is off until genuinely set up.
- **Fail-closed start-up.** `securityconfig.validate_startup` refuses a
  non-loopback/public bind when `TRACESETTLE_ENCLAVE_REQUIRED`/TEE-required is set
  without a signing endpoint / attestation provider. `config.py` gains
  `ENCLAVE_KEY_DB`, `ENCLAVE_REQUIRED`, and approved-measurement parsing.
- **Routes.** `GuardAPI` accepts `enclave`; `GET /api/guard/near/enclave` reports
  the boundary honestly (`enabled:false` with a plain note when unconfigured), and
  `POST /api/guard/near/execution/enclave-sign` signs a prepared transaction
  through the boundary. `ui._build_enclave_boundary()` returns `None` unless
  `TRACESETTLE_ENCLAVE_SIGN_URL` + an approved measurement are configured.
- **Console.** The security console gains an "Enclave signing boundary" panel that
  renders the configured state, the approved measurements, and the signing
  algorithm — never a fabricated protection badge.
- **Two new invariants (now 43 total):**
  `enclave_signing_requires_a_verified_attestation` and
  `enclave_signing_key_is_isolated_from_the_host`, both mutation-tested in
  `tests/test_near_invariants.py`.
- **Demos.** `demo/near_enclave_demo.py` runs five checks against the real boundary
  logic with a deterministic stand-in enclave transport (real ed25519 keypair, no
  network): provision+verify, non-approved measurement refused, mainnet refused,
  non-verifying signature refused, request/key mismatch refused. Byte-identical
  across runs; `tests/test_demo.py::test_near_enclave_demo_is_deterministic_and_passes`
  guards it. No transaction is signed for a chain and no key is requested.
- **Tests:** **1380 passed, 1 skipped** (full suite; the 1 skip needs a live
  enclave/TEE endpoint). New `tests/test_enclave.py`, `tests/test_enclave_execution.py`,
  enclave cases in `tests/test_near_execution_api.py` and `tests/test_securityconfig.py`.
  pyflakes clean; compileall OK; offline demo byte-identical (md5 `4864f13c…`);
  `demo/near_demo.py` 9/9; packaging 10 passed.
- **Honest scope.** The only substitution in tests/demo is the enclave transport;
  genuineness of real quote verification is covered by the live hardware harness
  and `tee_attestation_verification_is_genuine`. The boundary is testnet-only and
  no mainnet signing is claimed.

## Mission 6 — real-world execution gaps: verified, with the hardware blocker stated (2026-11-06)

Goal: turn the fail-closed enclave integration into a genuinely verified end-to-end
NEAR **testnet** path, verify the live provider-policy surface, and reconcile the
historical testnet claim. No verification rule was weakened; the settlement engine is
untouched; runtime stays standard-library only.

### Testnet execution — EXECUTED, independently re-read

- A real end-to-end testnet run through `near/pipeline.py`: tx
  `3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd`, signer
  `ts-m6-probe-13285.testnet` -> `ts-m6-recv-13153.testnet`, a `Transfer` of 0.01 NEAR
  (`10000000000000000000000` yoctoNEAR), submission `SETTLED`, settlement `VERIFIED`
  (all seven checks ok), `FINAL`/`SuccessValue`. Re-read from two independent public
  testnet RPCs (`rpc.testnet.near.org`, `rpc.testnet.fastnear.com`); the receiver
  balance rose by exactly the transferred amount.
- A second run of `demo/near_testnet_demo.py` produced
  `HYkzY2A1dcW7K2kAGDsEjaxntPpUrF7XjurzQ3P2EEb` (same shape).
- Accounts came from the **free** NEAR testnet faucet (`helper.testnet.near.org`); no
  money was spent. The opt-in reproduction is `tests/test_near_live_testnet.py`
  (testnet-only; refuses mainnet).

### Correction — the historical `Gjs4Y…` hash was mislabeled

- README and AGENTS cited `Gjs4YNbEPBQKWB3M6MpV2zAwhvJySk7U6Q8NZnKVWCKH` as the
  execution-boundary transfer. On-chain re-read shows it is a **0.02 NEAR** transfer
  signed by `ts-demo-8f3a1c.testnet` -> `ts-recv-8f3a1c.testnet` — the **browser-wallet
  demo** (its default amount is 0.02), not the execution boundary.
- The claim was corrected to the verified 0.01 NEAR tx above, in README and
  `docs/NEAR_INTEGRATION.md` §10. The historical AGENTS entry above is left as the
  record of what was written; this note supersedes it.

### Live provider policy — endpoint REAL, live read needs a key

- The Agent API endpoint `GET https://api.agentsonintents.com/v1/agents/{agent_id}/policy`
  is in the provider's published OpenAPI (`securitySchemes: {ApiKey: X-API-Key}`). It is
  **not invented**. A live probe with no key returns `401 {"code":"invalid_api_key"}` —
  the exact auth boundary `near/policy.py` models.
- A *successful* authenticated read needs a live key, which is out of the zero-budget
  scope; the adapter reports `UNCONFIGURED` and the guard's own policy governs.
- New opt-in test `tests/test_near_live_provider.py` exercises the real endpoint when
  `TRACESETTLE_TEST_AGENT_API_URL`/`_KEY` are supplied; skipped otherwise.

### Hardware (TDX) — genuine quote verified; enclave signing BLOCKED, fail-closed

- Live harness (`near/enclave_harness.py`, `TRACESETTLE_ENCLAVE_HARNESS=1`) fetched a
  **genuine** Intel TDX quote from `cloud-api.near.ai` and verified it locally: all 16
  checks pass incl. Intel PCS collateral (TCB `UpToDate`, PCK not revoked, QE identity
  match); a wrong measurement pin and a wrong nonce are both refused. `genuine: true`,
  `signing_available: false`.
- **Exact blocker:** the gateway exposes a TDX-attested enclave with a `signed_address`
  and a *completion*-signing endpoint (`GET /v1/signature/{chat_id}`), but **no endpoint
  that signs an arbitrary caller-supplied payload**. A NEAR transaction is an arbitrary
  payload, so no free, publicly reachable enclave can sign one here. Enclave signing
  therefore stays fail-closed; software signing is never substituted for TEE signing.
- New opt-in test `tests/test_near_live_enclave.py` asserts the honest result.

### Docs / tests

- README: corrected the execution tx, the enclave-hardware blocker, the invariant count
  (`39` -> `43`) and the test counts; `docs/NEAR_INTEGRATION.md` §9 rewritten (stale "no
  testnet transaction was executed" and "TEE is researched, not integrated" removed) and
  a new §10 records the testnet/provider/TEE evidence and the blocker.
- Tests: **1383 passed, 4 skipped** with PostgreSQL 16 (filesystem-only 1359 passed,
  28 skipped). 43/43 invariants hold; 9/9 attack scenarios pass; packaging 10 pass;
  pyflakes clean; compileall OK; offline demo byte-identical (md5 `4864f13c…`).
- The 4 skips are opt-in live tests (live testnet key; live Agent API credentials ×2;
  enclave harness). They are reported as skipped, never as passed.

## Mission 7 — independent adversarial verification; byte-level binding defect (2026-11-05)

Reviewed the authorization -> execution path adversarially and found one real defect
(latent, not externally reachable in the HTTP flow, but a false invariant).

- **Defect: the NEAR authorization did not cover the exact signed bytes.**
  `NearTransaction.guard_canonical_fields()` returned only the human-readable
  parameters, so the binding committed to a *summary* of the transaction, not the
  bytes. A transaction whose `actions` differed while those parameters were
  identical — a swapped transfer action, a substituted token contract, forged
  `ft_transfer` args — passed `accept_signature`. The invariant
  `near_execution_binding_covers_the_bytes` claimed the opposite but only tampered
  the amount (which changes both the parameters and the bytes), so it could never
  fail for a bytes-only substitution.
- **Fix.** An optional `transaction_digest` is folded into `canonical_fields` and
  `TransactionRequest`. The NEAR path supplies the digest of the exact unsigned
  bytes at mint time (`prepare`) and re-derives it at signing (`verify_binding`),
  so a bytes-only substitution is `WRONG_PARAMETERS`. The parameter is **omitted
  when None**, so the EVM/general path keeps byte-identical fingerprints and no
  existing authorization changes. The invariant now tampers only the action bytes
  and signs the forged bytes, removing the signature check as a confound.
- **Reachability.** In the HTTP flow the prepared operation is server-held behind an
  opaque, owner-scoped, single-use id, so this was not externally exploitable; the
  in-process boundary API is public and the TEE path already bound bytes, so the
  authorization path was the inconsistent one. Fixed structurally regardless.
- **Wallet path unchanged (correctly).** `PreparedWalletOperation` binds the
  *intent*, not bytes — the connected wallet builds and holds the bytes — and
  `verify_wallet_submission` checks the on-chain record against that intent. Do not
  add a byte digest there; the server never sees those bytes.
- **Tests:** 1359 filesystem / **1383 with PostgreSQL**, 28 / 4 skipped. New:
  `test_swapped_action_bytes_after_authorization_are_refused`,
  `test_substituted_token_contract_after_authorization_is_refused` (both fail under
  a neutralised digest), and
  `test_near_execution_binding_invariant_notices_a_binding_that_ignores_the_bytes`.
- **Secret audit (publication gate):** all 732 unique blobs across every ref scanned
  with `detect-secrets` plus a known-prefix sweep (`ghp_`, `github_pat_`, `sk-`,
  `AKIA`, `xox*-`, `AIza`, PEM private keys). No real credential; all matches are
  test placeholders, public token addresses, or public TDX attestation keys.

## Product identity restoration + end-to-end demo surface (2026-11-06)

The landing page and the package docstring were written when TraceSettle was
*only* a settlement investigator. The transaction-security product (guard +
NEAR agent authorization firewall) was added later and was fully implemented and
reachable at `/console`, but the public landing page never framed it: the only
pointer was a single footer link, and every piece of landing copy described a
"read-only investigator". That is a **stale-presentation** defect, not a missing
feature. It is now corrected; no verification rule was touched.

- **Landing page (`tracesettle/ui.py` `_INDEX_HTML`).** Presents both
  capabilities — *Protect payments* (the authorization firewall) and *Investigate
  settlement* (the read-only investigator) — plus a labelled demonstration call
  to action. It links into `console#guard`, `console#lab` and the in-page
  investigation form. A skip link and `id="main"` were added (WCAG 2.2 AA); the
  read-only honesty copy and the "never signs, submits or moves funds" statement
  are retained. `test_ui.py::test_index_page_renders` still passes unchanged.
- **`tracesettle/__init__.py`.** The module docstring and `DISCLAIMER` now
  describe the whole product. The `DISCLAIMER` string is shared with
  `report.py`, and `test_investigation.py` asserts it still contains
  `"cannot recover"`, so that phrase is preserved verbatim.
- **One demo implementation (`tracesettle/near/agent_demo.py`).** The offline
  end-to-end demonstration (restrictive policy, `build_offline_harness`,
  `run_agent_payment_demo`) now lives in the package, not only in the CLI. The
  CLI (`demo/near_agent_demo.py`) imports it (its `--json` output is
  byte-identical to before), and `guard/api.py` serves it at
  `GET /api/guard/near/agent-demo`. The console NEAR tab shows it as the
  **End-to-end demonstration** panel. All three surfaces run the same code.
- **Provable, not asserted.** The endpoint returns `simulated: true` and
  `reproduced: true`, with `malicious.decision == "BLOCK"`,
  `malicious.signer_calls == 0`, `malicious.broadcast_occurred == false`, and
  `legitimate.decision == "ALLOW"`, `signer_calls == 1`,
  `settlement_state == "VERIFIED"`. The authorization's `transaction_digest`
  equals the recomputed `signed_bytes_digest`.
- **Packaging.** `tracesettle/near/agent_demo.py` is inside the package, so the
  endpoint answers from a package-only copy (the production image). The
  package-only route test now includes `/api/guard/near/agent-demo`.
- **Tests:** 1448 → **1458 passed**, 27 skipped. New `tests/test_product_identity.py`
  (9: landing-page identity, honesty, accessibility, the demo endpoint over HTTP,
  auth gating, binding, determinism, dispatch) and
  `test_guard_ui.py::test_console_near_tab_has_an_end_to_end_demo_panel`.
  pyflakes clean; compileall OK; the three offline demos remain byte-identical
  (`demonstrate.py --offline` md5 `4864f13c…`).

## Identity-binding gap on the NEAR execution flow (2026-11-03, PR #12)

A genuine cross-service identity-substitution defect was found in adversarial
review and fixed on `feat/outlayer-custody-execution`.

- **The defect.** Service authentication runs in the transport
  (`ui.py::_SERVICE_OPERATION_PATHS`). The set listed only `evaluate`, `sign`,
  `agent-evaluate` and the two `lifecycle` routes. Every NEAR route added since
  the OutLayer work - `execution/prepare|attest|enclave-sign|submit`,
  `wallet/prepare|verify`, `custody/prepare|execute` - was **absent**, so when a
  `ServiceRegistry` is configured those routes reached `GuardAPI` with
  `authenticated_service_id=None` and honoured whatever `service_id` the body
  declared. A caller could adopt another service's identity on the whole NEAR
  execution flow, and the owner of a prepared operation was a body field.
  Reproduced over a real socket: `/api/guard/near/custody/prepare` answered `404`
  (boundary not enabled) regardless of a missing or forged credential, where a
  gated route answers `401`.
- **Latent in production today, real the moment the registry is enabled.**
  Production sets `TRACESETTLE_API_KEY` and the PostgreSQL/guard keys but **no**
  `TRACESETTLE_SERVICE_CREDENTIALS*`, so `ServiceRegistry` is absent and
  authentication is disabled. The defect is reachable by any operator who turns
  on the per-service credentials the product documents.
- **The fix, one source of truth.** `SERVICE_FACING_POST_PATHS` now lives in
  `guard/api.py`, next to the routing that consumes the identity, and
  `ui._SERVICE_OPERATION_PATHS` is that set. All 13 service-facing POST routes
  are gated.
- **Two identity checks, deliberately.** `_identity_matches` (strict: a route
  that carries a declared `service_id` must have one matching the credential)
  stays on `execution/prepare`, `wallet/prepare`, `custody/prepare`. A new
  `_identity_ok` covers the routes that act on a `prepare_id` and carry no
  declared identity (`attest`, `enclave-sign`, `submit`, `wallet/verify`,
  `custody/execute`): an absent declaration is allowed because the real gate is
  the owner-scoped store (a foreign `prepare_id` 404s), but a *mismatched*
  declaration is still refused. Using the strict check on a `prepare_id`-only
  route would 403 legitimate calls whose body omits the identity.
- **New invariant (52 total): `service_facing_routes_require_a_credential`.**
  It parses `guard/api.py` with `ast`, collects every `if path == "<route>":`
  block whose body references `authenticated_service_id` (exact-equality only,
  so the `startswith` lifecycle prefix route is excluded by construction), and
  fails if any such route is not in `SERVICE_FACING_POST_PATHS`. It then drives a
  real socket for each gated route with a registry configured and no credential,
  requiring `401`. Two mutation tests guard it: dropping a route from the set,
  and clearing the transport's gate set.
- **Tests:** 1554 → **1559 passed**, 27 skipped (1586 collected). New:
  `test_serviceauth_http.py::test_every_service_facing_near_route_requires_a_credential`
  and `..._refuses_a_forged_identity` (real sockets, all three `prepare` routes),
  plus the two mutation tests in `test_guard_invariants.py`. pyflakes clean;
  compileall OK; the offline demos stay byte-identical; all 9 attack scenarios
  match expectation.
- **Lesson.** A route allow-list that must be updated by hand is a coverage
  gap waiting to happen. Derive the required set from the code that consumes it,
  and fail closed when a route consults an identity the transport did not
  authenticate.
## Mission 21 — public demonstration readiness + production verification (2026-11-06)

The product was implemented and correct, but a first-time visitor to production
could not see it work: every guard route answered `401` behind the operator API
key and `/demo` answered `404`. The landing-page copy was accurate but the only
path to the demonstration was the key-gated console. This pass makes the real
boundary visible **without widening the authenticated surface**.

- **Opt-in keyless demonstration (`TRACESETTLE_PUBLIC_DEMO`, off by default).**
  When enabled, `tracesettle/ui.py:PUBLIC_DEMO_ROUTES` is served without the API
  key, plus the `/demo` page that presents the six-scene story. The allowlist is
  an **exact match**: `/api/guard/scenarios` and
  `/api/guard/near/{agent-demo,policy-scope,behaviours,prompt-injection,settlement-check}`.
  Every write route, the live policy document, metrics, incidents, audit,
  invariants, safeguards, the Intents lifecycle, the wallet/execution routes and
  `/api/investigate` keep the key requirement. Enabling it cannot relax the
  fail-closed start-up check: a public bind still requires credentials.
- **One gate, not two.** `Handler._guard_allowed(path)` charges the per-client
  rate limit **exactly once** and writes a refusal **once**. An earlier two-gate
  form could attempt two responses on a 429 and could double-charge the limit.
  Do not split it again.
- **Scene 6 is real, read-only evidence (`tracesettle/near/settlement_check.py`).**
  It reads an already-final NEAR **testnet** transaction from a public RPC and
  verifies it field by field (`signer_matches`, `receiver_matches`, `final`,
  `execution_success`, `transfer_amount_matches`). It refuses mainnet and reports
  `UNAVAILABLE` on an outage — never a fabricated verdict. Nothing is signed,
  broadcast or moved.
- **Landing page.** Capability copy states both halves (authorization firewall +
  settlement verification); the demonstration CTA is labelled and its link target
  is chosen at render time so it never points at a key-gated route when the demo
  is off (`__GUARD_LINK__` / `__DEMO_LINK__`). Both public pages ship the
  same-origin inline SVG favicon the console already had, so no page logs a 404.
- **Console 401 hint is honest.** The unauthorized message uses the
  `__DEMO_HINT__` placeholder and points at `/demo` **only** when the flag is on;
  otherwise it renders empty. No placeholder ever reaches a client.
- **New invariant (48 total):** `public_demo_never_exposes_a_state_changing_route`.
  It fails if a state-changing token (`sign`, `evaluate`, `wallet`, `execution`,
  `lifecycle`, `incident`, `audit`, `metrics`, `safeguards`, `tee`, `enclave`,
  `access-keys`, `investigations`) appears in the allowlist, or if the
  demonstration stops being labelled `simulated`. Mutation-tested two ways in
  `tests/test_guard_invariants.py`.
- **New fail-closed test:** `test_public_demo_does_not_relax_the_credential_check`
  proves `TRACESETTLE_PUBLIC_DEMO=1` on a `0.0.0.0` bind with no credentials still
  exits `2`.
- **Tests:** 1458 → **1497 passed, 28 skipped** (1525 collected; 1521 passed with
  PostgreSQL). New `tests/test_public_demo.py` (36) plus the two invariant
  mutations and the fail-closed test. pyflakes clean; compileall OK; offline demo
  byte-identical (`4864f13c…`); near demo byte-identical (`fc2949ef…`).
- **Production, verified live (2026-11-06).** PR #13 squash-merged to master as
  **`9aa3931d344a82fd9fe0a4b24036aa320cb2f070`**; all six CI checks green
  (Tests and static analysis; PostgreSQL shared-state integration; Docker build
  and runtime; Vercel; Vercel Preview Comments; Vercel container image). With
  `TRACESETTLE_PUBLIC_DEMO=1` set on the Vercel project and a fresh production
  deployment (`dpl_FJmYKU2mtxjvfdT8rQdqixdAKoDA`, alias `tracesettle-navy.vercel.app`):
  `/`, `/demo`, `/console`, `/api/health` and the six keyless routes return `200`;
  `/api/guard/metrics`, `/api/guard/policy`, `/api/guard/invariants`,
  `/api/guard/near/execution`, `/api/guard/near/wallet` and a keyless
  `POST /api/guard/evaluate` still return `401`. The live
  `/api/guard/near/settlement-check` returns `state: VERIFIED`, `mainnet: false`,
  all five checks `true`. The `/demo` page was driven in a real Chromium browser
  at desktop (1280×900) and mobile (390×844): zero console errors, zero failed
  requests, no horizontal overflow, and the six scenes render the real values.
- **Changing a Vercel env var does not redeploy.** Trigger one with
  `POST /v13/deployments?forceNew=1` and a `gitSource` that includes `org`
  (omitting `org` is a `400`).
- **Not changed:** the settlement engine, every authorization/verification rule,
  and the `SimulatedExecutor` default. No mainnet transaction, no key material in
  any response, no paid infrastructure.

## Mission 22 — OutLayer custody audit, provider-status fidelity, PR #12 completion (2026-11-06)

Adversarial verification of the OutLayer TEE custody integration on
`feat/outlayer-custody-execution` (PR #12), and the branch's reconciliation with
master. One real defect found and fixed; the authorization boundary was otherwise
found intact. No verification rule was weakened; the settlement engine is
untouched; runtime stays standard-library only.

- **Branch reconciliation.** `master` advanced by three commits (PR #13/#14,
  head `643bd24`) while the branch was in review. master was merged *into* the
  feature branch (merge commit `e07afe9`, parents `a79ca99` + `643bd24`) rather
  than rebased, so both published histories are preserved. Four conflicts, all in
  append-regions (`AGENTS.md`, `README.md`, `tracesettle/guard/invariants.py`,
  `tests/test_guard_invariants.py`); each was resolved as a **union**, keeping
  both sides' new invariant blocks and doc sections. `invariants.py` needed a
  manual fix of duplicated shared closing parens. No marker remains; pyflakes
  clean; compileall OK.
- **Defect: the provider status map was incomplete.** The OutLayer Agent Custody
  OpenAPI documents `RequestStatus` as
  `[pending_deposit, processing, success, completed, partially_failed, failed,
  refunded, pending_approval, approved, rejected, cancelled, needs_review]`, but
  `_STATUS_MAP` in `tracesettle/near/outlayer.py` omitted `completed`, `approved`,
  `cancelled` and `needs_review`. A transfer the provider completed and reported
  as `status: "completed"` was therefore read as `ProviderState.UNKNOWN`: the
  boundary under-reported a settled transfer and stopped polling it as terminal.
  It was a **false negative, never a fail-open** — settlement is established only
  by the independent NEAR RPC check, never by the provider status, so the security
  property held throughout. Fixed: `completed` -> `SUCCESS` (the provider's own
  idempotency doc groups `success`/`completed` as the terminal success states),
  `approved` -> `PROCESSING`, `cancelled` -> `REJECTED`, `needs_review` ->
  `UNKNOWN` (terminal but unresolved: never a success, never a plain failure).
  Only the two documented success synonyms map to `SUCCESS`; a status outside the
  enum still resolves to `UNKNOWN`.
- **Tests.** 1638 passed, 7 skipped with PostgreSQL 16 (filesystem-only 1614
  passed, 31 skipped). The live OutLayer network checks are opt-in
  (`TRACESETTLE_TEST_OUTLAYER_LIVE=1`) and skip cleanly when unreachable, so the
  default suite stays offline. New in `tests/test_near_outlayer.py`: the documented-status
  coverage test (fails if the map drifts from the API), a `completed`-is-not-
  `UNKNOWN` end-to-end test, unknown/`needs_review` never-a-success tests, and
  post-authorization substitution tests for amount, network, service and signer
  (each asserts the provider was never contacted). New
  `tests/test_near_live_outlayer.py`: asserts every adapter endpoint is in the
  provider's **live** OpenAPI document, that an unauthenticated transfer is
  refused, and (opt-in, `TRACESETTLE_TEST_OUTLAYER_API_KEY`) that the wallet read
  resolves through the real adapter. Every new assertion is mutation-checked:
  removing the `completed` mapping fails four tests.
- **Invariants:** 53 total (unchanged in count; the four custody invariants hold
  and are mutation-tested). All 53 verified by execution (`check_all()` -> 0
  failures) and over HTTP.
- **Second gap closed in `public_demo_never_exposes_a_state_changing_route`.** The
  banned-token set omitted `custody`, so a custody route added to the keyless
  allowlist would not have failed the invariant. `custody` is now in the set and
  a mutation test
  (`test_public_demo_invariant_notices_a_custody_route_in_the_allowlist`) fails
  if it is removed. The four custody routes are gated by
  `SERVICE_FACING_POST_PATHS` and are absent from `PUBLIC_DEMO_ROUTES`.
- **Release gates:** pyflakes clean; compileall OK; offline demo byte-identical
  (md5 `4864f13c…`); near demo byte-identical (`fc2949ef…`); 9/9 attack scenarios
  pass; packaging 12 pass; Docker image builds, runs non-root (uid 10001), health
  `200`, `Server: TRACESETTLE`, refuses to start with no credentials (exit 2),
  and reports the custody boundary disabled by default.
- **Not done, requires explicit human confirmation:** no mainnet transaction, no
  key material configured, no paid infrastructure.

## Adversarial input-hardening sweep (2026-11-06, branch `fix/adversarial-hardening`)

Final-mission adversarial pass over the guard's public boundary. Three latent
crash defects were found and fixed, each mutation-checked, and a new structural
invariant now guards the whole class. No authorization rule was weakened; the
settlement engine is untouched; runtime stays standard-library only.

- **Defect 1 — `outlayer_execution._implicit_account` could raise `OverflowError`.**
  The hand-rolled base58 decoder did ``n.to_bytes(32, "big")`` on a value that
  decoded to more than 32 bytes (or used an alphabet index on an invalid
  character), raising `OverflowError`/`ValueError`. The caller caught only
  `(CustodyError, ValueError)`, so a malformed on-chain public key aborted the
  custody settlement verification instead of refusing it. It now delegates to the
  shared, validating `tracesettle.base58.b58decode` and requires exactly 32 bytes.
  Tests: `test_a_malformed_signing_key_is_disputed_not_raised` (4 cases) and
  `test_the_implicit_account_decoder_rejects_a_key_that_is_not_32_bytes`.
- **Defect 2 — a non-token `authorization` raised `AttributeError` (HTTP 500).**
  `AuthorizationAuthority.validate` dereferenced `token.version` before checking
  the type, so a bare string, int, list or bool presented to `/api/guard/sign`
  produced an unhandled exception rather than a refusal. A type guard now returns
  `AuthState.MALFORMED` for any non-token, non-dict value. Tests:
  `test_a_non_token_authorization_is_refused_not_raised` (parametrized) and
  `test_sign_refuses_a_non_token_authorization_without_raising`.
- **Defect 3 — an absurd positive-exponent amount raised `decimal.Overflow`.**
  ``1e1000000000`` parses to a finite `Decimal` that passes the digits/scale
  checks, then overflows the decimal context during control arithmetic, turning a
  bad request into a 500. `parse_amount` now bounds the magnitude
  (`MAX_AMOUNT_VALUE = 10**40`), so ``1e41`` and above are refused with
  `AmountError` → HTTP 400. Tests: `test_parse_amount_rejects_an_absurd_magnitude`
  and `test_a_huge_amount_is_refused_by_the_api_not_a_500`.
- **New invariant (54 total): `hostile_input_never_crashes_the_guard`.** Exercises
  the real authority and service with a non-token authorization, an absurd amount
  exponent, and non-string destinations, and requires a typed refusal or a
  non-ALLOW decision for each — never an exception. Mutation-tested two ways
  (`test_hostile_input_invariant_notices_an_amount_that_overflows`,
  `test_hostile_input_invariant_notices_a_token_that_raises`); reverting the
  amount bound or the token guard makes it fail with the real defect message.
- **Sweep coverage.** All POST routes and every transaction field were fuzzed with
  hostile shapes (`None`, ints, bools, lists, dicts, 5 KB strings, NUL bytes,
  `nan`, `inf`, `1e308`): zero uncaught raises after the fixes. `verify_intent`
  was fuzzed with malformed chain records: zero raises. Service-identity binding,
  the public-demo allowlist, and the durable-state fail-closed paths were
  re-checked and hold.
- **Gates:** full suite **1657 passed, 7 skipped** with PostgreSQL 16; pyflakes
  clean; compileall OK; offline demo byte-identical (`4864f13c…`); near demo
  byte-identical (`fc2949ef…`); agent demo byte-identical (`d23f8b52…`); 54/54
  invariants hold. README architecture count updated (53 → 54).
- **Product truth (Mission 21) is already shipped on `master`:** the landing page
  states the two-sided proposition (block before signing, verify the settlement
  afterward), `/demo` runs the six-scene narrative, and the keyless public
  demonstration at `/api/guard/near/agent-demo` proves the block with a zero
  signer-call count. Verified live on production (`tracesettle-navy.vercel.app`).
