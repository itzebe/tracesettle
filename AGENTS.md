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

`CONFIRMED` (authoritative on-chain source) · `REPORTED` (upstream service, not independently checked) ·
`MISSING` · `CONTRADICTORY` · `UNAVAILABLE` · `SIMULATED`. Reconciliation returns an explicit **unknown**
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
- **Tests:** `python3 -m pytest tests/ -q` (136 tests). `tests/conftest.py` provides
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
  plain unverified report.
- **Tests:** `python3 -m pytest tests/ -q` (136 tests).

## Independent verification (pre-submission)

- **Verified (2026-10-20):** full suite `136 passed`; `pyflakes` clean over
  `tracesettle/ tests/ demo/`; `compileall` OK; no non-stdlib runtime imports.
- **Live reproduction confirmed** through the HTTP interface: deposit address
  `0xb741c00f6d63b6ded0ccada1a82bcbadc38a572b` -> `SETTLED_VERIFIED`, all four stages
  `CONFIRMED`, REFUND `MISSING`, 17 evidence items, 9 safety invariants all PASS.
  Note 1Click nests the hash arrays under `swapDetails` in `/v0/status`.
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
  ran from that venv: 136 collected, 136 passed, pyflakes clean, compileall OK, no
  external runtime imports, 15 modules imported.
- **Live reproduction re-confirmed (this run):** via `POST /api/investigate` ->
  `SETTLED_VERIFIED`, 17 evidence items, 9/9 safety invariants PASS.
- **New regression test:** `test_bridge_credit_origin_hash_match_is_case_insensitive`
  guards the hex case-insensitivity requirement. Mutation-checked: it fails if
  `.lower()` normalization is removed from `_names_expected_origin_tx`.
- **Docs corrected:** `reconcile.py` module docstring now lists all 9 invariants;
  README carries the current count (136), a runtime-dependencies section, and the
  "no real refunded transaction independently verified yet" limitation.

## Judge-ready demonstration pass

- **Second and third live cases verified (2026-10-20).** Both were taken from the
  public NEAR Intents explorer's embedded recent-transactions feed (a traceable
  source), then re-checked against 1Click status and NEAR RPC directly:
  - `bc1qjrkwt3v42j4am6csmkaelmpwd9shufl4laxkxm` — a real **refunded** BTC→TRON
    swap. Outcome `REFUND_REPORTED_UNVERIFIED`; refund is `UNAVAILABLE`
    (`UNSUPPORTED_CHAIN`, Bitcoin has no configured RPC), deposit credit
    `REPORTED`, destination `MISSING`, NEAR settlement `CONFIRMED`. This is now
    demo Case 3 and a README reproduction step.
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

