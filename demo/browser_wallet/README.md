# Browser-wallet journey on NEAR testnet

This demonstrates the **real** journey through the TraceSettle console in a
**real** Chromium browser, with a wallet that actually holds the key and signs:

```
connect  ->  authorize (the real guard)  ->  the wallet signs and sends  ->
independent settlement verification
```

The server never holds a key. The web page never sees a private key. The wallet
emulator plays the role of a wallet *extension*: it keeps the key in the Node
process, builds the NEAR transaction with the same Borsh layout as
`tracesettle/near/borsh.py`, signs ed25519, and broadcasts to NEAR testnet. The
page receives only a signed-and-broadcast transaction hash, exactly as a real
wallet returns.

## What it proves

Four scenarios run against real testnet transactions:

| Scenario  | Authorization | Wallet asked to sign | Settlement  | Why |
|-----------|---------------|----------------------|-------------|-----|
| `happy`   | `ALLOW`       | yes                  | `VERIFIED`  | every required check passes on the on-chain record |
| `blocked` | `BLOCK`       | **no**               | —           | a non-approved recipient never reaches the wallet |
| `tamper`  | `ALLOW`       | yes                  | `DISPUTED`  | the wallet signed a different amount than was authorized; the on-chain record contradicts the intent |
| `reject`  | `ALLOW`       | **no**               | —           | the user rejected the signature; nothing is broadcast |

The `tamper` case is the point of independent settlement assurance: the transfer
**succeeded on-chain** (the provider/wallet says success), but the on-chain record
does not match the authorized amount, so the state is `DISPUTED`, not `VERIFIED`.

## Prerequisites (all free)

- A Chromium or Chrome binary. On Debian/Ubuntu: `apt-get install -y chromium`
  (or set `PUPPETEER_EXECUTABLE_PATH` to any Chrome/Chromium you have).
- Node.js (any recent LTS).
- A funded `*.testnet` account key. NEAR testnet accounts are free.
- The recipient must be an existing `*.testnet` account (a transfer to a
  non-existent account fails on-chain).

Install the pinned browser driver:

```bash
cd demo/browser_wallet
npm install        # installs puppeteer-core (pinned); no browser is downloaded
```

## Run it

```bash
export TSW_SEED=<64-hex-ed25519-secret>     # a funded *.testnet account key
export TSW_ACCOUNT=<your-account.testnet>
export TSW_RECEIVER=<recipient.testnet>     # an existing *.testnet account
python demo/browser_wallet/run_demo.py --outdir /tmp/ts-wallet
```

`run_demo.py` starts the console with the NEAR execution boundary enabled and an
operator policy that approves only `TSW_RECEIVER`, then runs all four scenarios
and prints the observed outcome for each. It **refuses to run** without the
prerequisites and **never points at mainnet**. The key is used only to sign the
demonstration transactions; it is never written to disk or logged.

Evidence (a screenshot and a JSON result per scenario) is written to `--outdir`.

## Verify the emulator's transaction layout

The emulator must produce the exact bytes a real wallet would sign. That is
checked against a fixed vector from the repository's own serializer:

```bash
node --test demo/browser_wallet/borsh.test.mjs
```

`tests/test_browser_wallet_borsh.py` runs the same check from the Python suite
(and skips when Node is not installed).

## Scope and honesty

- This is a **simulated** wallet extension, not a real browser-extension
  wallet (e.g. MyNearWallet). It speaks the connector's injected-wallet protocol
  faithfully and signs real testnet transactions with a real ed25519 key.
- It signs and broadcasts **testnet** transactions only. It is a demonstration,
  not a production path; the production boundary never holds a key.
- The provider/wallet "success" is never treated as proof. Settlement is
  verified field by field against the authorized intent.
