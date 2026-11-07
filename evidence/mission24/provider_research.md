# Mission 24 — Phase A: sponsor and free-infrastructure research

Research date: 2026-11-06. Every row below was checked against the live source
(HTTP status and quoted text), not against memory. Nothing here is invented.

Question the research had to answer: **is there a genuinely free or
hackathon-sponsored route that produces a real signature over the exact NEAR
transaction digest TraceSettle authorizes, inside an independently verifiable
trusted environment?**

## Sources read

| Source | Where | Status |
| --- | --- | --- |
| NEAR Hackathon rules + resources | `https://nearhackathon.com/HACKATHON.md` (HTTP 200) | read in full |
| NEAR AI Security track | `nearai/near-hackathon-prompt-examples` track 06 | referenced |
| NEAR AI Cloud docs | `https://docs.near.ai/` (HTTP 200) | read |
| NEAR Builders join / build | `https://nearbuilders.org/join`, `/build` | referenced |
| OutLayer docs (signing keys, custody, attestation, pricing, connectors, web2) | `https://app.outlayer.ai/docs/*` (HTTP 200) | read |
| OutLayer OpenAPI | `https://testnet-api.outlayer.ai/openapi.json` (HTTP 200, 470 KB, 96 paths) | parsed |
| OutLayer health | `https://testnet-api.outlayer.ai/health` → `{"status":"ok","version":"0.1.0"}` | live |
| OutLayer worker attestation portal | `https://workers.outlayer.ai` (HTTP 200) | live |

## The three OutLayer surfaces are NOT interchangeable

This is the decisive finding. OutLayer exposes three different things, and only
one of them signs a caller-computed digest.

| Surface | What it signs | Signs the exact authorized digest? | Per-operation attestation? | Free? |
| --- | --- | --- | --- | --- |
| **Agent Custody** (`/wallet/v1/*`) | NEP-413 messages and native transfers, built provider-side | **No.** `POST /wallet/v1/sign-message` with `format: raw` is *rejected* (`400 bad_request`); the field exists only to return that redirect. NEAR transfers go through `/wallet/v1/transfer`, which builds the transaction itself. | **No.** The custody OpenAPI defines no attestation endpoint/schema. | wallet registration is free, but signing is a provider action, not a caller-bound signature |
| **Signing Keys** (`outlayer:signing-keys` host interface, WASI P2) | **raw bytes** the module composes (`sign(path, vault, message)`; ed25519 = 64-byte RFC 8032 signature over the raw message, no prehash, ≤65536 bytes) | **Yes.** The module computes the NEAR signing digest itself and asks the host to sign it; the private key never leaves the enclave. | **Yes.** Every run carries an Intel TDX quote whose `report_data`/task hash commits to input, output, `wasm_hash`, caller and project. | **No.** `/call` is a paid execution (`base_fee + instructions×rate + time×rate`); *failed executions are not refunded*. |
| **Agent Connect / compute** (`/call/{owner}/{project}`) | arbitrary WASI compute output | it is the transport for Signing Keys, so yes — *if* you publish a signing module | yes | paid, as above |

So the only OutLayer route that can sign the exact NEAR transaction digest is the
**Signing Keys** path, and it costs money per execution. That is a hard blocker
under the zero-spending constraint.

## NEAR AI Cloud credits — real, but not a transaction signer

`HACKATHON.md` Q-000: *"claim $10 by joining NEAR Builders (https://nearbuilders.org/join)"*,
or buy credits at `https://cloud.near.ai`. The credits are for **private AI
inference** on NEAR AI Cloud (GLM, Qwen, etc. running in TEEs). They are an
**inference** credit, not a general-purpose transaction-signing service. NEAR AI
Cloud's own docs describe models in TEEs, not an endpoint that signs an arbitrary
caller payload. Using an inference credit to "sign a NEAR transaction" would be a
category error.

## Free resources that ARE usable

| Resource | Free? | Evidence |
| --- | --- | --- |
| NEAR **testnet** transaction execution | Yes | testnet NEAR is free (faucet); `HACKATHON.md` Q-008: *"Testnet NEAR is free (near-cli faucet, near-faucet.io)"* |
| Public NEAR RPC (read + broadcast) | Yes | `https://rpc.testnet.near.org`, `https://rpc.testnet.fastnear.com`, `https://free.rpc.fastnear.com` |
| OutLayer **worker attestation portal** (read) | Yes | `https://workers.outlayer.ai` HTTP 200 |
| OutLayer **on-chain register contract** (read) | Yes | `worker.outlayer.testnet`, verifies TDX quotes (Intel DCAP) and holds the approved 5-measurement allowlist |
| Intel PCS collateral (read) | Yes | already used by `tracesettle/near/collateral.py` |
| NEAR AI Cloud **attestation** endpoint (read) | Yes | already used by `tracesettle/near/attestation.py` (genuine TDX quote, verified locally) |

## Cost of the one route that would work

OutLayer Signing Keys runs through `/call`, which is priced per execution
(`base_fee + instructions×rate + time×rate`); *"failed executions are not
refunded"*. A connector call requires a **payment key** (`pk_…`) backed by a
funded balance, and the `/call` route's security scheme is `PaymentKeyAuth`.
There is a trial (`POST /trial-key` → *"fifty connector calls in its first week"*)
and sponsor codes (`POST /wallet/v1/sponsorship`), but the trial is scoped to a
**wallet's connector calls**, and its terms are an offer OutLayer controls — not
a documented, guaranteed, zero-cost path to a raw-digest signature, and claiming
it requires an owner wallet with funds for any overage. Acting on it without the
owner's explicit decision would risk a charge, which the mission forbids.

## Decision

**The strongest technically sound free-capable route is the OutLayer Signing
Keys (WASI P2) path**, because it is the only provider that (a) signs the exact
caller-computed digest, (b) is a real ed25519 key whose public key is a NEAR
implicit account, and (c) ships a per-run Intel TDX attestation that commits to
the input, output and build. It is therefore the provider Mission 24 integrates.

**But it is access-blocked at zero cost**: every execution is billed, and no
documented free tier covers a raw-digest signature. So Mission 24:

1. **Implements** the provider adapter, the canonical signing request, the
   attestation binding and the evidence model in full, against the documented
   interface (`tracesettle/near/tee/`).
2. **Implements** the guest module (WASI P2) source and manifest that composes
   and signs the NEAR digest, so the integration is real code, not prose.
3. **Verifies offline**: the signature path is exercised end-to-end against a
   deterministic stand-in transport that signs with a real ed25519 key, and the
   digest/binding/attestation rules are mutation-tested.
4. **Reports the exact owner-only action** required to run it live (fund an
   OutLayer payment key, or obtain a sponsor code / trial), rather than faking it.

No paid service is called, no payment method is activated, no mainnet
transaction is made.
