# Mission 25 — live TEE signing run (real Intel TDX enclave, NEAR testnet)

Recorded 2026-11-07. Every value below was produced by a real network call
against `outlayer.testnet` and `rpc.testnet.near.org`. Nothing is simulated,
and no transaction hash, signature, key or balance is fabricated.

## The finding that unblocked it

OutLayer's **HTTPS** route (`POST /call/{owner}/{project}`) needs a prepaid USD
stablecoin balance (`docs/payment-keys`, minimum $1), so it is *paid*. Its
**on-chain** route — `outlayer.testnet.request_execution` — is paid from the
caller's **NEAR** balance, and on NEAR **testnet** NEAR is free. That route runs
a real Intel TDX enclave and is the free path this mission needed.

## Free testnet NEAR

`POST https://helper.testnet.near.org/account` with
`{"newAccountId": ..., "newAccountPublicKey": ...}` creates a funded `.testnet`
account (10 000 NEAR) with no signup and no key held by anyone else.

## What ran

The TraceSettle guest (`tracesettle/near/tee_signing/guest/signing-module`),
built for `wasm32-wasip2` and published at a public HTTPS URL
(`WasmUrl` source, `bind: "wasm"` manifest). The worker fetched the bytes,
checked their sha256 against the request, compiled them and ran them inside the
TEE.

| Step | Evidence |
| --- | --- |
| Guest `public_key` op | TEE-derived `ed25519:H3dd94sk1df1t2PVyQWjD9cyzDAKh2WceAFmP3tWdC2a` |
| Same op, second run | identical key (stable; `caller: "none"`) |
| Guest `sign_transaction` op | signature over the exact authorized digest, verified in-guest and again on the host |
| Broadcast | `F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj` |
| Settlement | recipient balance rose by exactly 0.1 NEAR (100000000000000000000000 yocto) |

## Transaction hashes (immutable, on-chain)

| Role | Hash |
| --- | --- |
| `public_key` request | `HcWqhDKCoiEXeT4R8GF5wjUo4YkQDTafsijvDAhujy7n` |
| Fund the TEE account | `83bVfGHBR4ajft926ynonaB6oQyH63dPxJbCFKNDZHhY` |
| `sign_transaction` request | `9aqdmyBq4GE7zhvnwHcgGVU9mfyUrx4KbKRG26TuierY` |
| TEE-signed settlement | `F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj` |

Raw RPC responses for each are in `transactions.json`.

## The guest wasm

| Field | Value |
| --- | --- |
| Target | `wasm32-wasip2` (OutLayer refuses WASI P1 when signing keys are declared) |
| Manifest key | `path: "neartx"`, `type: "ed25519"`, `bind: "wasm"`, `caller: "none"` |
| sha256 (wasm variant) | `eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0` |

## Cost

`execution_completed` reported `payment_charged: 1147400000000000000000`
(~0.00115 NEAR) and `payment_refunded: 998852600000000000000000` of the 1 NEAR
attached. So a run costs a fraction of a cent of *free testnet* NEAR.

## Honest scope

* This proves a **real Intel TDX enclave signed a real NEAR testnet
  transaction** with a key derived inside the enclave.
* It does **not** by itself prove the settlement — that is established
  independently by re-reading the chain (see the balance delta and the receipt
  status above).
* The guest wasm is not yet reproducibly built by CI; the pinned sha256 is what
  an operator approves. See `docs/TEE_ONCHAIN_SIGNING.md`.
* No mainnet transaction was made and no mainnet key exists.
