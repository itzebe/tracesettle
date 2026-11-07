# TRACESETTLE TEE signing guest

This directory holds the source of the WASI **Preview 2** component OutLayer runs
inside its Intel TDX enclave to sign a NEAR transaction digest. It is the module
side of the trusted signing chain; the Python side is
`tracesettle/near/tee_signing/`.

## What it does

1. Receives the structured signing request (`TeeSigningRequest.canonical()`), not
   a raw digest.
2. Refuses anything whose `domain` is not `tracesettle.tee.signing-request` or
   that carries a `raw_message`/`raw_digest` — a module that signs caller bytes is
   a signing oracle, which OutLayer's own rules forbid.
3. Recomputes the NEAR signing digest `sha256(borsh(Transaction))` from the
   parsed fields, using the V0 transaction form.
4. Asks the `outlayer:signing-keys` host interface to sign **that digest** with
   the declared `neartx` key (ed25519, `bind: project`, `caller: signer`).
5. Returns `{ public_key, signature, transaction_digest, wasm_hash }`.

The private key never reaches the module: the host returns a public key or a
signature, never the key.

## Building (operator action)

```bash
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
# publish the .wasm as a URL, then deploy it as a project version on OutLayer
```

## Why it is not compiled in this repository's CI

Compiling needs the Rust + WASI-P2 toolchain and a network fetch. The zero-budget
rule and the offline CI gate forbid both. The *logic that matters* — recomputing
the NEAR digest from the structured request — is mirrored in
`tracesettle/near/tee_signing/guest_reference.py` and tested against the
product's own Borsh serializer
(`tests/test_near_tee_signing.py::test_guest_digest_matches_the_product_digest_for_a_transfer`
and `..._for_an_ft_transfer`). If the guest and the product disagreed about the
bytes, those tests would fail.

## Honest status

- **IMPLEMENTED AND TESTED:** the request shape, the digest recomputation, the
  refusal of raw-message requests, the adapter, the attestation binding and the
  evidence ladder — all in Python, all covered by tests.
- **IMPLEMENTED BUT ACCESS-BLOCKED:** running this guest on OutLayer requires a
  funded payment key; OutLayer bills per execution. See
  `evidence/mission24/free_access_and_credentials.md`.
- **NOT CLAIMED:** that this module has signed a real transaction inside a real
  enclave. It has not, because that requires the paid route.
