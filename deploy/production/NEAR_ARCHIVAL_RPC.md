# NEAR Mainnet archival RPC — provider evaluation

Goal: a reliable NEAR Mainnet **archival** endpoint for historical settlement
verification (`tx` and receipt lookups for old transactions).

## Test method

Read-only JSON-RPC `tx` calls, no accounts, no keys. Historical reference
transaction used (previously verified FINAL, sender `intents.near`):

```
5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb
```

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"tx",
 "params":{"tx_hash":"5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb",
           "sender_account_id":"intents.near","wait_until":"NONE"}}
```

Probed 2026-11-01. Sender id `intents.near` was the first that resolved.

## Results (observed)

| Provider / endpoint | Result | Meaning |
| --- | --- | --- |
| `https://free.rpc.fastnear.com` | `UNKNOWN_TRANSACTION` | non-archival (recent only) — this is the default primary |
| `https://rpc.mainnet.near.org` | `UNKNOWN_TRANSACTION` | non-archival |
| `https://archival-rpc.mainnet.near.org` | **OK, 3.37 s**, `status {SuccessValue:""}`, 6 receipt outcomes, 9 logs | **archival** — resolves the historical tx fully |
| `https://near.drpc.org` | HTTP 403 | blocked without an API key |
| `https://1rpc.io/near` | HTTP 403 | blocked |
| `https://near.blockpi.network/v1/rpc/public` | HTTP 403 | blocked |
| `https://near.lava.build` | HTTP 403 | blocked |
| `https://near-mainnet.gateway.tatum.io` | `UNKNOWN_TRANSACTION` | non-archival public gateway |
| `https://rpc.ankr.com/near` | `Unauthorized` (needs key) | account required |
| `near-mainnet.public.blastapi.io`, `archival.fastnear.com`, `near.nownodes.io`, `near-mainnet.core.chainstack.com` | DNS not resolvable | endpoint name wrong / account-gated |

**Conclusion:** the only endpoint that resolved the historical transaction
**without an account or key** was `archival-rpc.mainnet.near.org`, the free
endpoint already used as the default fallback. It is documented by NEAR as
**deprecated and hard rate-limited** (HTTP 429, `Retry-After` can reach hundreds
of seconds). Every other free public endpoint is non-archival or key-gated.

The code's own behaviour matches this: a `UNKNOWN_TRANSACTION` on the primary
triggers the fallback; an archive miss on **every** endpoint stays `NOT_FOUND`
(not proof of absence); an unreachable endpoint stays `UNAVAILABLE`.

## Recommended configuration

| Role | Endpoint | Notes |
| --- | --- | --- |
| Primary (recent tx) | `https://free.rpc.fastnear.com` | free, no key, non-archival |
| Archival fallback | **paid** NEAR archive node from a provider below | see pricing |
| Interim fallback | `https://archival-rpc.mainnet.near.org` | free but deprecated + rate-limited; acceptable only at low volume |

Set:

```sh
TRACESETTLE_NEAR_RPC_URL=https://free.rpc.fastnear.com
TRACESETTLE_NEAR_RPC_FALLBACK_URL=https://<your-paid-archive-endpoint>
```

## Paid archive options (pricing to confirm with the vendor at sign-up)

All of the following advertise NEAR Mainnet **archive** access. None could be
tested here without an account, so each is **UNVERIFIED** for TraceSettle's exact
`tx`+receipt usage.

| Provider | Model | Archive NEAR | Indicative entry price | Notes |
| --- | --- | --- | --- | --- |
| FastNEAR (now SVRN, Inc.) | RPC + NEARDATA | Yes (archive nodes) | contact vendor | already the primary operator; NEAR-native |
| QuickNode | API credits | Yes (paid) | ~$49/mo Build, overage ~$0.62/M | broad chains, SOC 2 |
| Chainstack | request units (archive = 2x) | Yes | ~$49/mo Growth | published dedicated-node formula |
| dRPC | flat per request | Yes | ~$6/M requests; free plan ~10M/mo public | public free tier non-archival |
| NOWNodes | API key, per request | Yes ("archive nodes") | from ~€20–50/mo | key required |
| All That Node | request units | Yes | free tier (public), paid tiers | free tier non-archival |
| GetBlock | requests | archive on paid | free 40k/day public; ~$2.98/M | dedicated node $600/mo |
| Lava | requests | Yes (paid) | free public non-archival | public endpoint blocked here |

The cheapest credible **production** path is a low-volume paid archive plan
(QuickNode Build or Chainstack Growth at ~$49/month, or a metered dRPC/GetBlock
pay-as-you-go at a few dollars if lookup volume is tiny). Verify with the vendor
that the plan includes NEAR Mainnet archive and the `tx` method.

## Expected monthly cost

Historical lookups are rare (one per investigated old transaction). At, say,
5,000 archive lookups/month, a metered provider costs well under $1/month; the
practical floor is the plan minimum (~$49/month) for the flat-plan providers, or
$0 if the deprecated free archive is acceptable at very low volume.

## Failure behaviour and monitoring

- Primary miss → fallback tried automatically.
- All endpoints miss → `NOT_FOUND` (never treated as "failed").
- Endpoint unreachable/429 → `UNAVAILABLE` for the affected stage only; the rest
  of the investigation proceeds. This is the intended honest-uncertainty result.
- Monitor: HTTP 429 rate on the archive endpoint, `UNAVAILABLE` stage counts, and
  p95 latency of the archive call. Alert if archive lookups are `UNAVAILABLE`
  for more than a short window.

## Not done here

No account was created, no plan purchased, no endpoint changed. Pointing the
fallback at a paid archive node is a post-authorization deployment step.
