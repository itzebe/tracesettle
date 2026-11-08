# Mission 29 — fresh live TEE signing and NEAR testnet lifecycle

Date: 2026-11-08. **Testnet only. Zero cost.** No mainnet, no paid call, no
credential required.

This mission produced a **new** signing operation (not a re-verification of
Mission 25's capture). A genuine Intel TDX enclave — the OutLayer **on-chain**
route, paid in free testnet NEAR — signed a real NEAR testnet transaction.

## The route is genuinely free

- The **HTTPS** `POST /call/{owner}/{project}` route needs a prepaid USD balance
  → **paid**, not used.
- The **on-chain** `outlayer.testnet.request_execution` route is paid from the
  caller's **NEAR** balance, and on NEAR **testnet** NEAR is free from the
  faucet `https://helper.testnet.near.org/account`. Cost in USD: **0**.
- The enclave's own transaction is funded from the same free account.

## Prerequisite: the approved guest artifact is publicly served

The worker fetches the guest wasm over HTTPS and refuses a file whose bytes do
not match the configured sha256. The repository's canonical artifact
`tracesettle/near/tee_signing/guest/signing-module/dist/tracesettle-signing-module-wasm.wasm`
(sha256 `eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0`,
186462 bytes, `wasm32-wasip2`) was served from this sandbox's public runtime host
and verified byte-for-byte against the approved build before the run.

## The fresh operation (real code paths, `evidence/mission29/live_tee_signing.py`)

| Field | Value |
|---|---|
| Enclave signing key | `ed25519:H3dd94sk1df1t2PVyQWjD9cyzDAKh2WceAFmP3tWdC2a` |
| Enclave implicit account | `ee678ff2b2243fa83e63582f7e017027470be84c55f8deaef87f72244f1a6fb7` |
| enclave `request_execution` tx | `GMpwjDeTXo57PjfmNcXMq6sqFD3F8RwJxfTZ67SJ6nTQ` |
| enclave-signed transfer tx | `7dffFM6trTHVRUEBYXVnLscASersQA29RktWfSmvnMZ2` |
| transaction digest | `sha256:628abe3882566ad3746a54eda17c82d2b35aca7bdbd6a20941b1b7af6d07d529` |
| recipient | `ts-m29-dca6d7.testnet` |
| amount | 0.1 NEAR (`100000000000000000000000` yoctoNEAR) |
| worker measurements approved on-chain | `true` (`worker.outlayer.testnet.is_measurements_approved -> True`) |

Both transactions independently re-read from `https://rpc.testnet.near.org` →
`SuccessValue` (final, executed). The recipient's balance rose by exactly the
transferred amount.

## Provenance chain — all 7 links hold (level `TEE_SIGNING_VERIFIED`)

1. `signed_bytes_parse` — the enclave's `signed_transaction` is 255 bytes.
2. `digest_matches_signed_bytes` — recomputed `sha256` equals the recorded digest.
3. `tx_hash_is_b58_of_digest` — `b58(digest)` equals the transaction hash.
4. `signature_verifies_over_digest` — the ed25519 signature verifies over the
   recomputed digest under the enclave's key.
5. `enclave_output_hash_binds_the_receipt` — the Intel-attested `output_hash`
   equals `sha256` of the on-chain receipt `SuccessValue`.
6. `attested_output_is_this_signing_output` — that output, parsed, equals the
   signing output field-for-field.
7. `attestation_verified` — the Intel TDX quote, the Task-Hash commitment, the
   worker approval and the approved build all verified
   (`attestation_level: INDEPENDENTLY_VERIFIED`).

The decisive link is #5: the enclave's `output_hash`, which Intel signed into the
quote, commits to the exact bytes that carry the signed transaction, so a host
that swapped the transaction after the enclave produced it would fail the chain.

## Durable evidence + post-restart re-verification

The exact signed bytes were persisted to a SQLite `SubmissionLedger`, the store
was **closed and reopened**, and a fresh pipeline re-verified the signature:

- `signed_bytes_present`, `digest_recomputed`, `decode_round_trips`,
  `signature_verifies_over_digest`, `record_matches_signed_bytes` — all hold.
- `state: VERIFIED`, `digest_source: recomputed_from_persisted_signed_bytes`.

## Honest limitations

- The enclave did not broadcast a transaction for the *signing* call above; a
  separate funded account relayed `request_execution`. The enclave-signed NEAR
  transfer (`7dffFM6t…`) was then broadcast and independently re-read.
- The **Agent API provider-policy live read** remains access-blocked (needs a
  live key); the provider layer is implemented and fail-closed.
- No mainnet, no paid enclave call, no fabricated receipt.

Raw evidence: `live_tee_signing.json`. Driver: `live_tee_signing.py`.
