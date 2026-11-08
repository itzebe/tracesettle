# TRACESETTLE — Judge guide

An independent evaluation path. You do not need a wallet, an API key, a private key, or any paid
service to verify the core claim in this guide.

## The claim in one paragraph

An AI agent's *intention* is not payment authorization. TRACESETTLE sits between the agent and the
signer: it reads the **actual transaction parameters**, evaluates them against the operator's policy
and its own independent controls, and issues a transaction-bound authorization only for a decision it
is willing to stand behind. Anything else — an unapproved receiver, a manipulated amount, a tampered
payload, an expired or replayed token, an unknown identity — is refused **before a signer is reached**.
After execution, TRACESETTLE verifies the settlement independently rather than trusting a provider's
word.

The single most important property: **an unsafe payment is stopped before the wallet signs it.**

## Two minutes, three ways

### 1. Offline, no network, no key (recommended first step)

```bash
git clone https://github.com/itzebe/tracesettle
cd tracesettle
python3 -m tracesettle judge
```

This runs the real authorization boundary, the reference signer, the replay store, the approval
authority and the settlement verifier against ten scenarios and prints each result. Nine are
controlled simulations; the tenth reads a real NEAR **testnet** transaction. When this host has no
outbound network the tenth is printed `[SKIP]` and reported `UNAVAILABLE` — an honest environmental
limitation, never a failure and never a verdict about the transaction. The command exits non-zero
only for a real defect (an enforcement scenario that misbehaved, or a live contradiction).

Add `--json` for the machine-readable report.

### 2. In the browser, on the running site

Open `/evaluate` on the deployed site. Press **Run the ten scenarios**. Each card shows the input, the
expected result, what actually happened, whether the signer was reached, and the supporting evidence.
The raw JSON is at `/api/guard/judge/scenarios`. The full HTTP surface is documented in
`docs/API.md` in the repository.

### 3. Connect your own agent

The deployed site exposes a scoped, keyless **sandbox integration** so an agent
you already operate can have a proposed payment independently evaluated:

```bash
# 1. Issue a short-lived credential. No key, no account, no wallet.
curl -sS -X POST https://<deployment>/api/agent/connect \
  -H 'Content-Type: application/json' -d '{"label":"my-agent"}'
# -> { "service_id": "sandbox-my-agent", "api_credential": "...",
#      "approval_secret": "...", "ttl_seconds": 3600, ... }

# 2. Submit a payment intent. The decision is the real boundary's.
curl -sS -X POST https://<deployment>/api/agent/evaluate \
  -H 'X-Sandbox-Credential: <api_credential>' -H 'Content-Type: application/json' \
  -d '{"transaction":{"operation":"WITHDRAWAL","chain":"base","asset":"USDC",
       "amount":"50","destination":"0x1111111111111111111111111111111111111111"}}'
# -> { "decision": "ALLOW", "authorizes_signing": true, "authorization": {...} }
```

The credential is scoped to a **fixed sandbox policy**: an approved destination is
`ALLOW`, an unapproved one is `BLOCK` (with no authorization, so the signer is
never reached), and an amount over the threshold is `REQUIRE_APPROVAL`. The
credential cannot name an operator service, cannot sign a real transaction and
cannot broadcast; execution is the simulated executor and says so. The
machine-readable contract is at `/api/agent/openapi.json` and the scope at
`/api/agent/config`. On the public site, the **Connect your own agent** button on
`/evaluate` runs this same sequence in the browser.

### 4. Read the code

| Concern | File |
| --- | --- |
| Independent scenario matrix | `tracesettle/judge.py` |
| The boundary (five outcomes) | `tracesettle/near/agent_wrapper.py` |
| Guard controls, decision, counters | `tracesettle/guard/service.py` |
| Transaction-bound authorization | `tracesettle/guard/authorization.py` |
| The signer that refuses before executing | `tracesettle/guard/signer.py` |
| NEAR settlement verification | `tracesettle/near/verify.py` |
| TEE signing boundary (OutLayer Signing Keys) | `tracesettle/near/tee_signing/` |
| Reproducible-build identity + verifier | `tracesettle/near/tee_signing/build_verify.py` |
| Independent attestation verifier | `tracesettle/near/tee_signing/outlayer_attestation.py` |
| Authorization→settlement evidence chain | `tracesettle/near/tee_signing/evidence_chain.py` |
| The reviewer CLI | `tracesettle/tee_verify_cli.py` |
| Structural invariants (62) | `tracesettle/guard/invariants.py` |

## What the ten scenarios prove

| # | Scenario | Threat | Expected result |
| --- | --- | --- | --- |
| 1 | Unauthorized receiver | A manipulated agent pays an unapproved address | BLOCK, signer never reached |
| 2 | Manipulated amount | The amount moves outside the spending policy | BLOCK, signer never reached |
| 3 | Altered transaction | The payload is changed after authorization | Refused: `WRONG_PARAMETERS` |
| 4 | Expired authorization | A stale token is presented late | Refused: `EXPIRED` |
| 5 | Replayed authorization | A captured token is used twice | First succeeds, replay refused, one execution |
| 6 | Malformed input | Hostile or absurd input probes for a crash | Every case rejected with a typed error |
| 7 | Unknown service identity | A caller claims an unregistered identity | BLOCK, cannot sign |
| 8 | Approval required | An above-threshold payment skips human approval | `REQUIRE_APPROVAL`; signed only after a bound approval |
| 9 | Legitimate payment | A valid in-policy payment | ALLOW, signer executes once |
| 10 | Settlement verification | A provider claims success without proof | `VERIFIED` only if the on-chain record matches |

Scenario 9 is as important as the others: a boundary that blocks everything is not a security product.
The tool must let the authorized path through, and it does.

## How to tell real from simulated

- **Real, running code in every scenario:** the authorization boundary, the guard controls, the
  reference signer, the replay store, the approval authority, the NEAR policy analysis and the
  settlement verifier.
- **Simulated:** the executor. It records what it was asked to do and never touches a chain. Every
  simulated result says so, and `broadcast` is always `false`.
- **Real evidence:** scenario 10 reads an already-final NEAR **testnet** transaction from a public RPC
  and checks its signer, receiver, operation and amount. It never signs, builds or broadcasts.
- **Not exercised here, and not claimed:** a live wallet signature in a real browser extension, and any
  mainnet settlement. See "Limitations" below.

## Verify the safety invariants yourself

```bash
python3 -m tracesettle serve --host 127.0.0.1 --port 8000 &
curl -s localhost:8000/api/guard/invariants | python3 -m json.tool | tail -5
```

62 structural invariants are asserted by execution, not by prose. Each one is mutation-tested: a
checker that cannot fail is treated as a defect. You can also read the statements next to the results.

## Verify the enclave trust chain yourself (no key, no network)

The TEE signing claim is inspectable with the shipped captures and the reviewer CLI. Every command
below runs offline and exits non-zero on any failure.

```bash
# 1. The build identity. The pinned rustc must reproduce the approved bytes.
python3 -m tracesettle guest verify

# 2. The attestation. Verifies the TDX quote to the pinned Intel root, the
#    report_data Task-Hash commitment, the worker measurement, the on-chain
#    worker approval, and the input/output payload hashes.
python3 -m tracesettle attestation verify \
    --record tracesettle/near/fixtures/onchain_tee_attestation.json

# 3. The signature. Recomputes sha256(unsigned_bytes) and verifies ed25519 over
#    it, and reports the on-chain transaction hash the signature produces.
python3 -c "import json;print(json.dumps(json.load(open('tracesettle/near/fixtures/onchain_tee_run.json'))['sign_transaction']['output']))" > /tmp/signing.json
python3 -m tracesettle signature verify /tmp/signing.json

# 4. The evidence chain. Re-checks that authorization, the exact signed bytes,
#    the attestation, the broadcast hash and the settlement all name one
#    transaction.
python3 -m tracesettle chain verify <evidence-chain.json>
```

To rebuild the guest bytes yourself you need Rust; the pinned toolchain is in
`rust-toolchain.toml` and the full procedure is in
`evidence/mission26/reproducible_build.md`. Without Rust, step 1 still checks the
recorded identity, the toolchain pin, and — because the approved bytes are
committed — the artifact hash.

The evidence chain is also on the running site: `GET /api/guard/near/execution/chain/<tx_hash>`
returns a stored chain with its binding verdict, and `GET /api/guard/near/execution/chains` lists them.
The build, attestation and signature commands are offline reviewer tools; they are not HTTP routes.

## Run the full test suite

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

The suite covers authorization, blocking, amount manipulation, prompt injection, transaction-digest
binding, replay prevention, signer preconditions, BLOCK and REQUIRE_APPROVAL enforcement, service
authentication and settlement verification. The runtime itself is standard-library only; `pytest` and
`pyflakes` are development tools.

## Limitations, stated plainly

- The demonstration's settlement evidence is a NEAR **testnet** transaction. Mainnet is refused by
  design and no real funds are involved.
- The public site does not hold a signing key and never requests one. The wallet-mediated path is
  opt-in and off by default; the site's public pages only evaluate and verify.
- A live signature from a third-party browser-extension wallet depends on that extension's own network
  support. TRACESETTLE's boundary is correct regardless of which wallet is used.
- `UNAVAILABLE` on the live check means the public RPC could not be reached from this host. It is never
  upgraded into a verdict about the transaction. The free testnet nodes prune recent history, so the
  client also tries a public testnet **archive** node; a pruned transaction is a definitive miss and is
  looked up again on the archive, while an outage never fans out.

## What TRACESETTLE is not

- Not a transaction explorer, a payment dashboard, or a generic blockchain security tool.
- Not a custodian: it holds no funds and no private keys.
- Not an oracle for "is this transaction safe" in the abstract. It enforces a specific operator policy
  and reports its evidence, including when the evidence is insufficient.
