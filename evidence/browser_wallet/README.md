# Browser-wallet journey evidence (NEAR testnet)

Captured by `demo/browser_wallet/run_demo.py` against real NEAR testnet
transactions. Each `*.json` is the harness's own record for one scenario; each
`*.png` is the console at that moment. Only **public** testnet data is here: no
key, seed, or private material is present (the key lived only in the harness
process and was never written to disk).

Reproduce:

```bash
cd demo/browser_wallet && npm install
export TSW_SEED=<64-hex-ed25519-secret> TSW_ACCOUNT=<acct.testnet> TSW_RECEIVER=<rcpt.testnet>
python demo/browser_wallet/run_demo.py --outdir evidence/browser_wallet
```

| Scenario | Authorization | Wallet asked | Settlement | On-chain tx |
| --- | --- | --- | --- | --- |
| `happy` | `ALLOW` | yes | `VERIFIED` | `EvNeH37s95oSRJKiso5xuxgrgpgrdsMf3q2tDp3ntep4` |
| `blocked` | `BLOCK` | no | — | none (never signed) |
| `tamper` | `ALLOW` | yes | `DISPUTED` | `BHgNvQ2AUBLknEWMo13dueR1yWc84puLaahu8dYhhRTR` |
| `reject` | `ALLOW` | no | — | none (user rejected) |

Both on-chain transactions were independently re-read from `rpc.testnet.near.org`
(`method: tx`, `wait_until: FINAL`) and report `FINAL` / `SuccessValue` with
receiver `tsr0c0e96c307.testnet`. In the `tamper` case the transfer **succeeded**
on-chain (0.5 NEAR sent) while the authorized amount was 0.02 NEAR, so settlement
is `DISPUTED`, not `VERIFIED` — provider/wallet success is never treated as proof.

Accounts used here are throwaway `*.testnet` accounts funded by the free NEAR
testnet helper. They hold no real value and no mainnet key is involved anywhere.
