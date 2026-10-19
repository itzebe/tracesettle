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

- **Runtime:** Python 3.13 standard library only at runtime. `pytest` and `pyflakes`
  are dev-only. Do not add runtime dependencies (free infra, no DB).
- **Tests:** `python3 -m pytest tests/ -q` (115 tests). `tests/conftest.py` provides
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

