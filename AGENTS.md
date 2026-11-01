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
- **Tests:** `python3 -m pytest tests/ -q` (540 passed, 185 new). New files:
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
