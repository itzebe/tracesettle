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
| `CONTRADICTORY` | Two pieces of evidence materially disagree. |
| `SIMULATED` | Clearly-labelled test evidence, never a live finding. |

Stages: `SOURCE_CHAIN_DEPOSIT`, `BRIDGE_DEPOSIT_CREDIT`, `NEAR_SETTLEMENT`,
`DESTINATION_CHAIN_DELIVERY`, and `REFUND`.

A stage is confirmed **only** by its decisive evidence, never by a neighbouring
signal:

- source deposit: the origin-chain transaction executed;
- bridge deposit credit: an on-chain bridge transfer to `intents.near` carries a
  `BRIDGED_FROM` memo naming **this** deposit's origin transaction hash;
- settlement: the investigated intent hash appears in on-chain intent-execution
  event logs (a NEAR transaction merely being included or final is not enough);
- destination delivery: the expected asset transfer to the expected recipient
  appears in the destination receipt logs;
- refund: a matching on-chain transfer to the refund address exists.

Correlation uses explicit identifiers only (intent hash, deposit address,
recipient address, transaction hash). Amount and timestamp similarity are never
used to link stages.

## Try it: do X → see Y

No API keys, no paid services, no database. Python 3.11+ standard library only.

**1. Run the tests.**

```sh
python3 -m pytest tests/ -q
```
→ `135 passed`.

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

**5. Run the web interface.**

```sh
python3 -m tracesettle serve --host 127.0.0.1 --port 8000
```
→ open `http://127.0.0.1:8000`, enter a deposit address, press **Investigate**,
and read the evidence in chronological order with links to every source record.
Copy or download the report as JSON or Markdown.

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
   └── adapters/evm_rpc.py       EVM receipts       (authoritative)
   │
   ▼
model.py ── normalized EvidenceItem stream
   │
   ▼
reconcile.py ── deterministic engine, 9 safety invariants
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
| `tracesettle/adapters/` | One adapter per data source. |
| `tracesettle/reconcile.py` | Deterministic reconciliation engine. |
| `tracesettle/investigation.py` | Orchestrator. |
| `tracesettle/report.py` | Report generation. |
| `tracesettle/ui.py` | Standard-library web interface. |
| `tracesettle/__main__.py` | CLI. |
| `tests/` | 135 tests. `evidence/raw/` fixtures are real captures. |
| `PHASE1_FEASIBILITY.md` | Phase 1 feasibility and API verification. |
| `docs/official/` | NEAR documentation captured during Phase 1. |

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
python3 -m pytest tests/ -q          # all 135
python3 -m pytest tests/test_safety_invariants.py -q
python3 -m pytest tests/test_ui.py -q
```

Test coverage includes successful settlement, a failed intent with a verified
refund, a failed intent without a verified refund, a confirmed source with
incomplete downstream evidence, conflicting or unavailable status information,
invalid identifiers, malformed responses, API timeouts, missing fields, and
unreliable correlation. `tests/test_safety_invariants.py` fails the build if the
engine ever claims a refund or a destination delivery without the required
evidence.

Tests exercise the real adapter and engine code. Only the network transport is
substituted, and real Phase 1 captures are loaded from `evidence/raw/` rather
than recreated. Synthetic fixtures live in `tests/fixtures/synthetic/` and are
labelled as such.

## Read-only guarantee

TRACESETTLE cannot recover, reverse, freeze, or move funds. It cannot report a
refund or a delivery without verifiable on-chain evidence. When the evidence is
insufficient it says so and returns an explicit unknown.
