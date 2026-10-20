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
| `btc_tx_deposit.json` | `GET https://mempool.space/api/tx/9a80de61…051226` | Bitcoin origin deposit tx for a real BTC→TRON swap: confirmed at height 972255, one output pays the bridge deposit address. |
| `btc_tx_refund.json` | `GET https://mempool.space/api/tx/377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f` | A confirmed Bitcoin tx paying the refund address of that swap (height 972263). Used to show *a* payout exists; it is not tied to the intent. |
| `btc_address_history.json` | `GET https://mempool.space/api/address/bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw/txs` | The refund address's full history: **four** confirmed transactions pay it. This is the evidence that the refund payout is *ambiguous* and cannot be confirmed. |
| `near_rpc_tx_btc_deposit.json` | `POST https://free.rpc.fastnear.com` `tx` for `5G5fbpGz…jgL7T` | NEAR bridge deposit credit for the BTC origin; receipt logs carry the `BRIDGED_FROM`/`utxo_added` memo naming the Bitcoin origin txid. |
| `near_rpc_tx_btc_settlement.json` | `POST https://free.rpc.fastnear.com` `tx` for `83tjFcjT…jxL1` | NEAR settlement for the same swap; `ft_withdraw` log records the withdrawal recipient `btc:bc1q77w5l5…mdrgw`. |
| `btc_tx_deposit.hex` | `GET https://mempool.space/api/tx/9a80de61…051226/hex` | The deposit transaction's raw bytes, in the non-witness serialization used to **recompute** its txid locally (`SHA256d`) and confirm the bytes hash to the requested id. |
| `btc_tx_refund.hex` | `GET https://mempool.space/api/tx/377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f/hex` | The refund-candidate transaction's raw bytes, for the same local txid recomputation. |
| `btc_outspend_deposit_vout0.json` | `GET https://mempool.space/api/tx/9a80de61…051226/outspend/0` | The deposit's output 0 is **spent** by a later transaction. Used to reason about whether a deposit output was consumed. |
| `btc_outspend_deposit_vout1.json` | `GET https://mempool.space/api/tx/9a80de61…051226/outspend/1` | The deposit's output 1 is **unspent** (`spent: false`). The pair shows the outspend lookup returns per-output state, not a single boolean. |
| `oneclick_status_btc_REFUNDED.json` | `GET https://1click.chaindefuser.com/v0/status?depositAddress=bc1qjrkwt3…kxm` | Live 1Click status for the refunded BTC→TRON swap, captured 2026-10-19. `originChainTxHashes` now names **both** the refund and the deposit transaction. |
| `btc_address_stats_refund.json` | `GET https://mempool.space/api/address/bc1q77w5l5…mdrgw` | Authoritative `tx_count` for the refund address, used to judge whether the history search was complete. |
| `solver_relay_get_status_BTC_REFUNDED.json` | `POST https://solver-relay-v2.chaindefuser.com/rpc` `get_status` for `69o3QALy…Rgrn` | The solver relay reports `SETTLED` for the same intent that 1Click reports `REFUNDED` — two conflicting upstream statements, both preserved as `REPORTED`. |

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

# 7) Bitcoin origin deposit tx (free Esplora API, no key)
curl -s "https://mempool.space/api/tx/9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226"

# 8) The refund address's full history — shows four confirmed payouts
curl -s "https://mempool.space/api/address/bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw/txs"

# 9) Raw transaction bytes, for local txid recomputation
curl -s "https://mempool.space/api/tx/9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226/hex"
curl -s "https://mempool.space/api/tx/377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f/hex"

# 10) Per-output outspend state for the deposit transaction
curl -s "https://mempool.space/api/tx/9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226/outspend/0"
curl -s "https://mempool.space/api/tx/9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226/outspend/1"
```

> The full refund txid and the deposit txid above are the real values in the captures; where a
> txid is shown truncated in the table, the `raw/` file itself carries the complete, verbatim value.

## Prior art

| File | Source |
| --- | --- |
| `prior_art_intent-triager_SKILL.md` | [`shreyaspadmakiran-defuse/intent-triager`](https://github.com/shreyaspadmakiran-defuse/intent-triager) — closest existing public tool; independent corroboration of the endpoint choices above. |
