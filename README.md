# TRACESETTLE

A read-only cross-chain settlement investigator for NEAR Intents.

TRACESETTLE takes one identifier, gathers what public sources actually say about
a NEAR Intents (1Click) swap, separates what is **independently verified** from
what is **merely reported**, flags contradictions and gaps, and prints an
evidence-backed investigation report.

It never signs, submits, holds, or moves anything. It never asks for a private
key or seed phrase. It never claims funds were recovered.

## The problem

When a cross-chain swap goes wrong, the evidence is scattered: a 1Click status
record, an origin-chain receipt, a NEAR transaction, a destination-chain
receipt. Each source speaks a different vocabulary (`SUCCESS`, `SETTLED`,
`FINAL`, `0x1`). A user is left guessing which of those statements is actually
proof.

The common failure mode is treating an upstream service's word as ground truth.
A status of `FAILED` is not proof funds were lost. A `refundedAmount` of `0` is
not proof no refund can occur. A transaction hash is not proof the event it
describes happened. TRACESETTLE is built to keep those distinctions explicit.

## What it does

For each transaction stage it records evidence, then classifies it:

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

Stages: `SOURCE_CHAIN_DEPOSIT`, `BRIDGE_DEPOSIT_CREDIT`, `NEAR_SETTLEMENT`,
`DESTINATION_CHAIN_DELIVERY`, and `REFUND`.

A stage is confirmed **only** by its decisive evidence, never by a neighbouring
signal:

- source deposit: the origin-chain transaction executed;
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
python -m pytest tests/ --collect-only -q   # 233 tests collected
python -m pytest tests/ -q                  # 233 passed
```
→ `233 passed`.

**2. Investigate a real, known-good swap from the command line.**

```sh
python3 -m tracesettle investigate 0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B
```
→ a Markdown report whose outcome is `SETTLED_VERIFIED`, with the source
deposit, bridge deposit credit, NEAR settlement, and destination delivery each
marked `CONFIRMED` and each linking to its real explorer page.

**3. See conservative handling of an unknown address.**

```sh
python3 -m tracesettle investigate 0x000000000000000000000000000000000000dEaD
```
→ outcome `NOT_FOUND`, and the report says plainly that not found is not proof
the swap failed.

**4. See that a reported-only settlement is not called verified.**

```sh
python3 -m tracesettle investigate 7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG --json
```
→ outcome `SETTLED_REPORTED_ONLY`: the intent hash path can read a service
statement but cannot reach the whole path, and the report says so.

**5. See how a real reported Bitcoin refund is handled.**

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

**6. Run the web interface.**

```sh
python3 -m tracesettle serve --host 127.0.0.1 --port 8000
```
→ open `http://127.0.0.1:8000`, enter a deposit address, press **Investigate**,
and read the evidence in chronological order with links to every source record.
Copy or download the report as JSON or Markdown.

**7. Or run all three cases at once.**

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

**7b. If a public endpoint is down, replay the captured evidence.**

```sh
python3 demo/demonstrate.py --offline
```
→ runs the same analysis over the **real captures** in `evidence/raw/`, with no
network access. It substitutes only the network transport, so the adapter,
engine, and report code is the real code. The run is labelled `OFFLINE REPLAY`
and states the capture date; it does not show that an endpoint is answering now.

## Supported input and honest limits

| Identifier | What it can do |
| --- | --- |
| 1Click deposit address | Full path: source, settlement, destination, refund. |
| Intent hash | Settlement status only (solver relay). No reverse lookup exists. |
| Origin-chain transaction hash | Not supported. The 1Click status endpoint is keyed on the deposit address; there is no documented reverse lookup. |

Other limits, stated in every report:

- 1Click status is a service statement, reported and not independently verified.
- Only chains with a configured public RPC can be independently verified.
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

```
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
reconcile.py ── deterministic engine, 11 safety invariants
   │
   ▼
report.py ── JSON + Markdown investigation report
   │
   ▼
ui.py / __main__.py ── web interface + CLI
```

The engine is deterministic: identical evidence produces an identical result.
No LLM decides whether a transaction is confirmed.

## Files

| Path | Role |
| --- | --- |
| `tracesettle/identifiers.py` | Identifier classification and validation. |
| `tracesettle/model.py` | Evidence model: stages, states, outcomes, safety invariants. |
| `tracesettle/assets.py` | `nep141:` asset id parsing to chain/contract. |
| `tracesettle/config.py` | Public chain RPC map and explorer URL builders. |
| `tracesettle/httpclient.py` | Timeouts, bounded retries, error classification. |
| `tracesettle/adapters/` | One adapter per data source (1Click, solver relay, NEAR, EVM, Bitcoin). |
| `tracesettle/reconcile.py` | Deterministic reconciliation engine. |
| `tracesettle/investigation.py` | Orchestrator. |
| `tracesettle/report.py` | Report generation. |
| `tracesettle/ui.py` | Standard-library web interface. |
| `tracesettle/__main__.py` | CLI. |
| `demo/demonstrate.py` | Read-only walkthrough (live, or `--offline` replay of captures). |
| `demo/replay_opener.py` | Offline transport that replays `evidence/raw/` through the real code. |
| `tests/` | 233 tests. `evidence/raw/` fixtures are real captures; `tests/fixtures/synthetic/` are clearly labelled synthetic. |
| `PHASE1_FEASIBILITY.md` | Phase 1 feasibility and API verification. |
| `submission/` | Hackathon artifacts: API payload shape, technical summary, demo post draft, publication checklist. |
| `docs/official/` | NEAR documentation captured during Phase 1. |
| `requirements-dev.txt` | Development-only tool pins (`pytest`, `pyflakes`). Not needed at runtime. |

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

## Tests

```sh
python3 -m pytest tests/ -q          # all 233
python3 -m pytest tests/test_safety_invariants.py -q
python3 -m pytest tests/test_ui.py -q
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

## Read-only guarantee

TRACESETTLE cannot recover, reverse, freeze, or move funds. It cannot report a
refund or a delivery without verifiable on-chain evidence. When the evidence is
insufficient it says so and returns an explicit unknown.
