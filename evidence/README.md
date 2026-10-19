# Evidence index

Raw artefacts captured during Phase 1 feasibility verification on **2026-10-19 (UTC)**.
Everything here was fetched live; nothing is hand-written. Reproduction commands are given so any
claim in [`../PHASE1_FEASIBILITY.md`](../PHASE1_FEASIBILITY.md) can be re-checked.

> These artefacts contain only **public** blockchain data and **public** API responses. No credentials,
> keys, or personal data are included.

## `raw/`

| File | Source | What it proves |
| --- | --- | --- |
| `oneclick_status_SUCCESS.json` | `GET https://1click.chaindefuser.com/v0/status?depositAddress=0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B` | A completed swap retrievable **with no auth header**: full `swapDetails` with `intentHashes`, `nearTxHashes`, `originChainTxHashes`, `destinationChainTxHashes`. |
| `oneclick_status_PENDING_DEPOSIT.json` | `GET /v0/status?depositAddress=<fresh quote address>` | The pre-funding shape: `status: PENDING_DEPOSIT`, null amounts, empty hash arrays, `refundedAmount: "0"`. |
| `oneclick_quote_response.json` | `POST /v0/quote` with `"dry": true` | `dry: true` returns **no `depositAddress`** (documented rule, confirmed live). |
| `oneclick_tokens.json` | `GET /v0/tokens` | Public, no-auth token/asset list with `assetId` values used for quotes. |
| `solver_relay_get_status_SETTLED.json` | `POST https://solver-relay-v2.chaindefuser.com/rpc` `get_status` | Independent settlement confirmation for the same intent hash; `data.hash` matches a 1Click `nearTxHash`. |
| `near_rpc_tx.json` | `POST https://free.rpc.fastnear.com` `tx` for `5E3Gdbhw…ypFb` | NEAR execution `FINAL`; `intents.near` receipt logs contain the intent hash in DIP-4 `EVENT_JSON`. |
| `near_rpc_tx_omft.json` | `POST https://free.rpc.fastnear.com` `tx` for `FbrSoTHb…p284` | NEAR execution `FINAL`; signer `bridge-mng.near`, receiver `omft.near`. |
| `evm_receipt_origin.json` | `POST https://ethereum-rpc.publicnode.com` `eth_getTransactionReceipt` | Origin-chain deposit tx confirmed: `status: 0x1`. |
| `evm_receipt_destination.json` | `POST https://ethereum-rpc.publicnode.com` `eth_getTransactionReceipt` | Destination-chain delivery tx confirmed: `status: 0x1`, `to` = USDC contract. |
| `oneclick_openapi.yaml` | `https://1click.chaindefuser.com/docs/v0/openapi.yaml` | Full 1Click API spec: paths, auth schemes, `GetExecutionStatusResponse` / `SwapDetails` schemas, status enum. |
| `exp_openapi.yaml` | `https://explorer.near-intents.org/api/v0/openapi.yaml` | Explorer API spec — both paths require `bearerAuth` (partner-gated, out of scope). |

## Reproduction commands

```sh
# 1) Status for a known completed swap — no auth header
curl -s "https://1click.chaindefuser.com/v0/status?depositAddress=0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"

# 2) Solver relay settlement check — no auth header
curl -s -X POST https://solver-relay-v2.chaindefuser.com/rpc -H 'Content-Type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"get_status","params":[{"intent_hash":"7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG"}]}'

# 3) Independent NEAR verification (free public RPC, no key)
curl -s -X POST https://free.rpc.fastnear.com -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tx","params":{"tx_hash":"5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb","sender_account_id":"intents.near","wait_until":"NONE"}}'

# 4) Independent origin-chain verification (free public RPC, no key)
curl -s -X POST https://ethereum-rpc.publicnode.com -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0xfca11aa01bce5fc20a6cbeb4ca30e8af994cda47de9bd5fa53a9ca4295ba01d2"]}'

# 5) Auth-boundary checks (401 on invalid key, 404 on unknown address with no key)
curl -s -o /dev/null -w '%{http_code}\n' "https://1click.chaindefuser.com/v0/status?depositAddress=deadbeef"
curl -s -o /dev/null -w '%{http_code}\n' -H "X-API-Key: totally-invalid-key-123" \
  "https://1click.chaindefuser.com/v0/status?depositAddress=deadbeef"

# 6) Rate-limit headers (unauthenticated budget)
curl -s -D - -o /dev/null "https://1click.chaindefuser.com/v0/status?depositAddress=0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B" | grep -i ratelimit
```

## Prior art

| File | Source |
| --- | --- |
| `prior_art_intent-triager_SKILL.md` | [`shreyaspadmakiran-defuse/intent-triager`](https://github.com/shreyaspadmakiran-defuse/intent-triager) — closest existing public tool; independent corroboration of the endpoint choices above. |
