# NEAR Mainnet archival RPC — free-access reality

Goal: a **free, permanent** NEAR Mainnet archival endpoint for historical
settlement verification. This document records what was actually tested and what
remains unsolved. **No paid provider is recommended here.**

## 1. Why this matters

TraceSettle confirms a settlement only from a **decisive on-chain event**. For an
old transaction that means a historical `tx`/receipt lookup. Free NEAR nodes prune
history, so a miss on a non-archival node is not proof of absence.

## 2. Test method

Read-only JSON-RPC `tx` calls, no accounts, no keys, **one request per endpoint**
(well within any free rate limit). A browser-like `User-Agent` is used because
some Cloudflare-fronted providers reject the default urllib agent; this is not a
rate-limit bypass. Historical reference transaction (previously verified, sender
`intents.near`):

```
5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb
```

```json
{"jsonrpc":"2.0","id":1,"method":"tx",
 "params":{"tx_hash":"5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb",
           "sender_account_id":"intents.near","wait_until":"NONE"}}
```

Probed 2026-11-01.

## 3. Results (observed, this environment)

| Provider / endpoint | Result | Meaning |
| --- | --- | --- |
| `https://archival-rpc.mainnet.near.org` | **OK, 3.60 s**, 6 receipt outcomes, 9 logs | **archival — resolves the historical tx** |
| `https://free.rpc.fastnear.com` | `UNKNOWN_TRANSACTION` | non-archival (the default primary) |
| `https://rpc.mainnet.near.org` | `UNKNOWN_TRANSACTION` | non-archival |
| `https://rpc.fastnear.com` | `UNKNOWN_TRANSACTION` | non-archival |
| `https://near.drpc.org` | `UNKNOWN_TRANSACTION` | non-archival public tier |
| `https://near-mainnet.gateway.tatum.io` | `UNKNOWN_TRANSACTION` | non-archival public gateway |
| `https://1rpc.io/near` | `the method tx does not exist/is not available` | `tx` disabled |
| `https://near.blockpi.network/v1/rpc/public` | HTTP 503 `Apikey no…` | key required |
| `https://near.lava.build` | HTTP 410 `This endpoint has been discontinued.` | discontinued |
| `https://rpc.ankr.com/near` | `Unauthorized: … API key` | key required |
| `https://near.nownodes.io` | HTTP 422 `Missing API_key` | key required |
| `https://archival-rpc.mainnet.pagoda.co`, `https://rpc.mainnet.pagoda.co` | HTTP 403 (rate-limit body) | blocked here |
| `allthatnode`, `getblock`, `chainstack`, `blastapi`, `nownodes` public hosts | DNS not resolvable / 404 | no public endpoint |

**Note on the earlier run.** A previous probe recorded HTTP 403 for dRPC, 1RPC,
BlockPI, and Lava. Re-testing with a browser `User-Agent` showed those 403s were
Cloudflare blocking the sandbox agent, not a provider policy. The corrected
results above (the method being unavailable, a key being required, or the endpoint
being discontinued) are the accurate ones.

## 4. Conclusion

The **only** endpoint that resolved the historical transaction **without an
account or key** was `archival-rpc.mainnet.near.org` — the already-default
fallback. NEAR documents it as **deprecated and hard rate-limited** (HTTP 429,
`Retry-After` can reach hundreds of seconds after a burst).

**No genuinely free, permanent, key-free archival NEAR provider was verified.**
Every other free public endpoint is non-archival, key-gated, or discontinued.
This is an **unresolved limitation** under the zero-budget constraint.

## 5. Configuration under the zero-budget constraint

```sh
TRACESETTLE_NEAR_RPC_URL=https://free.rpc.fastnear.com
TRACESETTLE_NEAR_RPC_FALLBACK_URL=https://archival-rpc.mainnet.near.org
```

- The primary handles recent transactions (free, no key, non-archival).
- The fallback is the deprecated free archive. It is the **only** free option, and
  it is rate-limited. Historical lookups may return `UNAVAILABLE` when it throttles.
- No paid archive node is used or recommended.

## 6. What historical queries may fail, and why that is safe

- **Old transactions** (beyond the free nodes' pruning window) resolve only through
  the deprecated archive; if it throttles, the settlement stage is reported
  `UNAVAILABLE`.
- **Unavailable evidence vs invalid evidence.** These are different and the engine
  keeps them apart:
  - `UNAVAILABLE` means the source could not be reached or throttled — the evidence
    is **missing**, not wrong. It never becomes a confirmation and never becomes a
    failure verdict.
  - `CONTRADICTORY` means a source answered but the evidence disagrees (for example,
    returned bytes that hash to a different txid). That is a real contradiction.
  - A miss on **every** endpoint is `NOT_FOUND`, which is **not** proof of absence.
- A settlement is never manufactured: only a decisive on-chain event confirms a
  stage. If the free archive cannot answer, the honest result is an unknown, not a
  success.

## 7. Options if a reliable archive is ever required

These are **paid** and are therefore **out of scope** under the current
constraint. Recorded only for completeness, not recommended:

- A paid archive plan from a provider such as QuickNode, Chainstack, dRPC, or
  GetBlock. None was tested (no account), so each is **UNVERIFIED**.
- This is the one capability the zero-budget architecture cannot deliver. See
  `COST_ESTIMATE.md` §4 and §6.

## 8. Not done here

No account created, no key obtained, no plan purchased, no endpoint changed in a
live deployment. No rate limit was bypassed.
