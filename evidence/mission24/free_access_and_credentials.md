# Mission 24 — Phase F: free access and credentials

Checked 2026-11-06 against the live sources. No account was created, no credit
claimed, no payment method activated, no transaction signed.

## Free resources discovered

| Resource | How it is free | Verified how |
| --- | --- | --- |
| NEAR testnet execution | Testnet NEAR comes from a faucet at no cost | `HACKATHON.md` Q-008 |
| Public NEAR RPC | Free public endpoints, read + broadcast | `https://docs.near.org/api/rpc/providers`; used already |
| NEAR AI Cloud **inference** credits | `$10` by joining NEAR Builders | `HACKATHON.md` Q-000 |
| Intel PCS collateral | Public, free to fetch | used already by `near/collateral.py` |
| NEAR AI Cloud attestation quote | Public, free to fetch | used already by `near/attestation.py` |
| OutLayer worker attestation portal | Public read | `https://workers.outlayer.ai` HTTP 200 |
| OutLayer register contract state | Public read on testnet | `worker.outlayer.testnet` |
| OutLayer connector **trial** | `POST /trial-key` — "fifty connector calls in its first week" | live OpenAPI summary |
| OutLayer **sponsor codes** | `POST /wallet/v1/sponsorship` — a subscription paid by a sponsor | live OpenAPI summary |

## Verified credit eligibility

- **NEAR AI Cloud credits:** eligibility is *joining NEAR Builders*
  (`https://nearbuilders.org/join`). This is an **inference** credit. It cannot
  sign a NEAR transaction — NEAR AI Cloud runs models in TEEs; it is not a
  general-purpose signing service. Keeping this distinct from signing is
  deliberate (mission §5).
- **OutLayer execution credits:** none documented as free. Pricing is per
  execution and *failed executions are not refunded*. The trial and sponsor codes
  exist but are OutLayer-controlled offers scoped to connector calls.

## Exact access restrictions

| Service | Restriction | Can be tested without payment? |
| --- | --- | --- |
| OutLayer `/call` (Signing Keys transport) | Requires a payment key (`pk_…`) with balance, or a trial/sponsor allowance; per-execution billing | **No** — any real call risks a charge |
| OutLayer `/wallet/v1/*` (Custody) | Requires a wallet API key; signing is NEP-413/transfer only, **never** a raw digest | Partially (register is free) but it cannot sign the digest, so it is not the route |
| OutLayer `/public/*` | Open read | **Yes** |
| OutLayer worker portal | Open read | **Yes** |
| NEAR testnet RPC | Open | **Yes** |
| NEAR AI Cloud models | API key + credits | Only with credits (inference, not signing) |

## Services that require payment

- Any OutLayer execution (`/call`) — the only route that produces a raw-digest
  ed25519 signature inside the enclave. **This is the single blocker.**

## Remaining owner actions (exact)

To run Mission 24's live TEE-signing path end to end, the owner would need ONE of:

1. **Fund an OutLayer payment key** on testnet:
   - create/connect a wallet at `https://app.outlayer.ai/wallet/manage`,
   - create a payment key (`POST /wallet/v1/create-payment-key` or the dashboard),
   - top it up from the NEAR testnet faucet,
   - set `TRACESETTLE_TEE_SIGNING=1` and provide the key +
     `TRACESETTLE_TEE_SIGNING_OWNER`/`_PROJECT`/`_APPROVED_BUILD` server-side
     (see `docs/NEAR_INTEGRATION.md` §10).
2. **Obtain an OutLayer sponsor code** and redeem it with
   `POST /wallet/v1/sponsorship`, then the same configuration as (1).
3. **Claim the connector trial** (`POST /trial-key`) for the wallet that will call
   the signing module — only if OutLayer confirms it covers a custom project call.

Any of these spends or risks spending, so the mission's zero-spending rule means
**the owner must decide**, not the agent. Until then the provider reports itself
unavailable (`GET /api/guard/near/tee-signing` → `available: false`) and the
boundary refuses to sign — never a silent software fallback.

## What was done offline instead

- Full provider adapter, canonical signing request, attestation binding, evidence
  model, guest module source and manifest — all implemented and unit-tested.
- The whole signing lifecycle is exercised against a deterministic stand-in
  transport that signs with a **real** ed25519 key, so every line of the adapter
  runs; only the network transport is substituted.
- The live path is exposed and refuses closed when unconfigured.
