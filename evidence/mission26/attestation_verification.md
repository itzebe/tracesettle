# Mission 26 — Independent attestation verification

Recorded 2026-11-08. The capture is
`tracesettle/near/fixtures/onchain_tee_attestation.json`; it ships inside the
package so the verifier runs in the production image.

## The gap Mission 25 left

Mission 25 proved a real Intel TDX enclave signed a real NEAR testnet
transaction, but recorded the run as *provider-trusted*: the on-chain
`execution_completed` event carries no quote, so nothing in the product could
show the enclave's attestation. It set `attestation_url: ""`.

## The route that closes it

OutLayer publishes the attestation for an execution at a **free,
unauthenticated** endpoint:

```
GET https://testnet-api.outlayer.ai/attestations/by-tx/<near_transaction_hash>
```

No key, no payment. The record carries the TDX quote and the fields the worker
hashed into `report_data` before Intel signed it.

## What is verified, and against which anchor

Every claim is checked separately; the verdict is all-of.

| Claim | What is checked | Trust anchor |
| --- | --- | --- |
| `quote_authentic` | ECDSA chain, QE report, AK binding, quote signature | pinned Intel SGX Root CA |
| `task_hash_bound` | `report_data[0:32]` equals the Task Hash recomputed from the record's own fields | the signed bytes |
| `worker_measurement_matches_quote` | the record's `worker_measurement` equals the quote's `rt_mr3` | the quote |
| `worker_measurement_approved` | `rt_mr3`/`mrtd`/`rtmr0-2` approved by the on-chain register contract | `worker.outlayer.testnet` |
| `approved_build` | the attested `wasm_hash` equals the pinned approved build | the operator's pin |
| `executed_wasm_matches_named_wasm` | the executed artifact is the one the record names | the record |
| `execution_binding` | the record's `transaction_hash` is the execution asked about | the caller's question |
| `input_hash_bound` | `sha256(execution_requested.input_data)` equals the attested input hash | the on-chain tx |
| `output_hash_bound` | a receipt `SuccessValue` hashes to the attested output hash | the on-chain tx |

## The result

```
$ python3 -m tracesettle attestation verify \
    --record tracesettle/near/fixtures/onchain_tee_attestation.json
claims:
  [OK ] quote_authentic - signature chain to the pinned Intel SGX Root CA
  [OK ] task_hash_bound - report_data[0:32] = f91d8cd0e029775d719951ab7938abb545cfc8b84b1306671992e3696932d194
  [OK ] worker_measurement_matches_quote - record 70ff63a49a8e12490ea4eba7… vs quote rt_mr3 70ff63a49a8e12490ea4eba7…
  [OK ] worker_measurement_approved - worker.outlayer.testnet.is_measurements_approved -> True
  [OK ] approved_build - attested eb705a61554fc982… vs approved eb705a61554fc982…
  [OK ] executed_wasm_matches_named_wasm - the executed artifact is the one the record names
  [OK ] execution_binding - record names 9aqdmyBq4GE7zhvnwHcgGVU9mfyUrx4KbKRG26TuierY
  [OK ] input_hash_bound - sha256(input_data) equals the attested input hash
  [OK ] output_hash_bound - a receipt SuccessValue hashes to the attested output hash
RESULT: PASS
```

Level: `INDEPENDENTLY_VERIFIED` — every claim verified **and** the worker build is
approved on-chain.

## The register read: recorded vs live

The on-chain register read (`worker.outlayer.testnet.is_measurements_approved`) is
the only network call. The recorded answer ships in the fixture
(`worker_approval`) so the command is reproducible offline; `--live-worker-approval`
re-reads it from the chain:

```
$ python3 -m tracesettle attestation verify --record … --live-worker-approval
worker_approval_source: live
RESULT: PASS
```

Re-checked live in this session (2026-11-06): the command fetched the worker
approval from `worker.outlayer.testnet` and returned `RESULT: PASS` with
`worker_approval_source: live`, so the recorded answer is confirmed against the
chain, not merely trusted.

The recorded and live answers agree (both `True`). The `RecordedApprovalRpc`
answers only the one question captured and only for the measurements it names;
any other worker is `UNAVAILABLE`, never a pass. Tests assert a different worker
and a recorded disapproval are both refusals.

## Honest limits

* The attestation proves *an approved enclave ran an approved build for this
  task*. It does not, by itself, prove the signature was produced inside that
  enclave; the signing route is `outlayer:signing-keys`, whose contract is that
  the key is handed to the guest, not the host.
* A missing record is `NOT_VERIFIED`; an unreachable register is a failure, never
  a pass.
* The verifier reproduces OutLayer's documented hash rules, including the
  asymmetry between the input hash (key order preserved) and the output hash
  (keys sorted). That asymmetry is OutLayer's and is reproduced, not corrected.
