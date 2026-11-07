# Free on-chain TEE signing (real Intel TDX enclave, NEAR testnet)

TRACESETTLE can ask a **real Intel TDX enclave** to sign the exact NEAR
transaction it authorized, and this document records how the free path works and
what it does and does not prove.

## 1. Why an on-chain route exists

OutLayer runs the TEE. It exposes two ways to reach it:

| Route | Payment | Free? |
| --- | --- | --- |
| `POST https://testnet-api.outlayer.ai/call/{owner}/{project}` | prepaid USD balance (minimum $1, `docs/payment-keys`) | no |
| `outlayer.testnet.request_execution` (a NEAR contract call) | the caller's NEAR balance | **yes on testnet** |

On NEAR **testnet**, NEAR is free — the official faucet funds a fresh `.testnet`
account with 10 000 NEAR and no signup. So the on-chain route runs the same real
enclave for a fraction of a cent of free testnet NEAR, and it is the route this
project uses. No money is spent and no paid service is introduced.

## 2. The flow

```
TraceSettle                     NEAR testnet                 Intel TDX enclave
    │                                │                              │
    │  build transaction             │                              │
    │  compute digest (sha256)       │                              │
    │  build canonical request ──────┼──────────────────────────────│
    │  sign request_execution        │                              │
    │  ──────────────────────────────▶ outlayer.testnet            │
    │                                │  request_execution ─────────▶
    │                                │                     fetch wasm,
    │                                │                     check sha256,
    │                                │                     run guest in TEE
    │                                │◀───── signed tx + key ────────
    │◀── execution_completed event ──│                              │
    │  parse answer                  │                              │
    │  verify digest matches         │                              │
    │  broadcast signed bytes ──────▶│                              │
    │  re-read settlement ──────────▶│                              │
```

The provider (`tracesettle/near/tee_signing/onchain.py`) does three things the
host cannot fake:

1. it publishes the guest WASM to a public HTTPS URL and pins its `sha256`;
2. it submits the **canonical signing request** — a structured description of the
   authorized transaction, never raw caller bytes;
3. it refuses an answer whose recorded `transaction_digest` differs from the one
   the product computed, so a genuine signature cannot ride a swapped
   transaction.

The guest recomputes the digest inside the enclave from the same canonical
structure, so a hostile host cannot smuggle a different transaction past the
enclave either.

## 3. What the live run proved (2026-11-07)

| Fact | Value |
| --- | --- |
| Enclave key (derived inside the TEE) | `ed25519:H3dd94sk1df1t2PVyQWjD9cyzDAKh2WceAFmP3tWdC2a` |
| Implicit account | `ee678ff2b2243fa83e63582f7e017027470be84c55f8deaef87f72244f1a6fb7` |
| Transaction the enclave signed | `F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj` |
| Amount | 0.1 NEAR (`100000000000000000000000` yocto) |
| Settlement | recipient balance rose by exactly the amount; `FINAL` |
| Cost | ~0.00105 NEAR charged, the rest refunded — free testnet NEAR |

Raw RPC responses: [`evidence/mission25/transactions.json`](../evidence/mission25/transactions.json).
The narrative: [`evidence/mission25/tee_signing_live_run.md`](../evidence/mission25/tee_signing_live_run.md).

## 4. Reproduce it

Offline (no network, deterministic, replays the real capture):

```
python3 demo/near_onchain_tee_demo.py        # 5/5 checks
python3 demo/near_onchain_tee_demo.py --json
```

The strongest check needs no trust in the capture: the product's own transaction
builder is fed the parameters the enclave recorded and must reproduce the **exact**
live digest and transaction hash. A one-byte serialization drift fails it.

Live (opt-in, spends free testnet NEAR):

```
export TRACESETTLE_TEST_ONCHAIN_TEE=1
export TRACESETTLE_TEST_TEE_WASM_URL=https://…/tracesettle-signing-module-wasm.wasm
export TRACESETTLE_TEST_TEE_WASM_SHA256=<sha256 of that file>
python3 -m pytest tests/test_near_live_onchain_tee.py -q
```

The live test creates its own faucet-funded account, funds the enclave's implicit
account, and asserts the recipient's balance actually rose.

## 5. The guest

`tracesettle/near/tee_signing/guest/signing-module/` is a Rust crate built to
`wasm32-wasip2` by `build.sh` (OutLayer refuses a WASI P1 module that declares
signing keys). Its manifest declares one ed25519 key at path `neartx` with
`bind: "wasm"` and `caller: "none"`, so the key is derived inside the enclave and
stable across runs without a caller identity.

The guest exposes two operations:

* `public_key` — return the enclave-derived public key;
* `sign_transaction` — recompute the NEAR digest from the canonical request,
  verify it matches the request's recorded digest, sign, and return the signature
  plus the assembled signed transaction bytes.

`vectors/tee_signing_vectors.json` pins the cross-language digest vectors so the
Rust encoder and the Python encoder cannot silently diverge.

## 6. Honest scope

* The enclave **signs**. It does not itself prove settlement — that is established
  by independently re-reading the chain (balance delta and receipt status).
* The enclave is reached through OutLayer's contract; this is a real Intel TDX
  enclave but the *relying party* here is OutLayer, and the guest WASM is
  identified by a pinned `sha256` rather than a reproducibly-built artifact.
* Testnet only. No mainnet transaction is made and no mainnet key exists.
* The caller's key signs only the `request_execution` call. The provider holds a
  sign callable, never a key, and the caller's key is never logged.
