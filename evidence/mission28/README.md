# Mission 28 — genuine TEE signing, independently verified

Date: 2026-11-08. Branch `feat/mission28-genuine-tee-signing-verification`,
stacked on PR #26's head. Testnet only. No paid call, no mainnet, no deploy.

## The question

Can TraceSettle durably preserve enough cryptographic evidence to independently
verify, **after a process restart**, that the exact transaction it authorized was
signed by the claimed signing identity?

Answer: **yes**, in two separately-proven halves.

## Half 1 — durability (Mission 27, re-verified here)

The exact signed bytes are persisted (`SubmissionLedger.signed_b64`) before
broadcast. A fresh process recomputes the NEAR digest from those bytes and
re-verifies the ed25519 signature under the key the bytes name
(`NearExecutionPipeline.verify_recorded_signature`). Proven across a real SQLite
close/reopen. See `../mission27/restart_verification.json`.

## Half 2 — genuine enclave provenance (new in Mission 28)

A valid signature does not prove the key was in an Intel TDX enclave running the
approved build. `near/tee_signing/signing_provenance.py::verify_attested_signing`
chains the commitments:

```
Intel-signed TDX quote
  └─ output_hash = sha256(enclave stdout)
       └─ that stdout, parsed, IS the signing output (carries signed_transaction)
            └─ sha256(borsh(unsigned)) == recorded transaction_digest
                 └─ b58(digest) == tx_hash
                      └─ ed25519(sig, digest, public_key) verifies
```

Every link is a named check. The verdict level is `TEE_SIGNING_VERIFIED` only when
all hold; a bare valid signature is capped at `SIGNATURE_VERIFIED`.

## Evidence in this directory

| File | What it is |
|---|---|
| `signing_provenance.json` | recorded-capture verdict (real Mission 25 run) |
| `live_signing_provenance.json` | **live** verdict, fetched 2026-11-08 from the free OutLayer endpoint + public NEAR RPC |
| `generate_evidence.py` | regenerates the JSON above from real code paths |

The Mission 27 evidence files (`../mission27/`) carry Mission 28 addenda covering
the data flow, the durable-evidence contract, adversarial results, the
reproducible-build regression and the honest limitations.

## What is proven, and how

* `F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj` — a real testnet transfer — was
  signed by the enclave key `ed25519:H3dd94sk1df1t2PVyQWjD9cyzDAKh2WceAFmP3tWdC2a`
  (implicit account `ee678ff2…`).
* The enclave ran the approved build `eb705a61554fc982…`.
* The Intel-attested `output_hash` `5ef45840…` equals `sha256(receipt SuccessValue)`,
  and that SuccessValue is the signing output carrying the signed transaction.
* The signature verifies over the recomputed digest of the exact signed bytes.

## What is NOT proven

* The enclave did not broadcast: a separate funded account relayed the call.
  Settlement is established by the independent on-chain read, never by the enclave.
* No live, paid enclave signature was produced this mission (the `/call` route is
  paid). The proof re-verifies the existing Mission 25 capture and makes it
  reproducible, offline and live.
* The guest pin is a sha256 of our artifact, not a verified build of the OutLayer
  host. Mainnet is never used.
