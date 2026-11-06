# Vendored browser assets

## `near-connect.js`

A bundled copy of [`@hot-labs/near-connect`](https://github.com/hot-dao/near-connect)
v0.12.0 (MIT licence), the wallet connector the NEAR Foundation recommends as the
successor to `near-wallet-selector`.

It is vendored so the security console can connect a user's NEAR wallet without a
third-party `<script>` origin at runtime: the console's Content-Security-Policy
keeps `script-src 'self'`, so no external script is ever loaded.

Rebuild with:

```
npm install @hot-labs/near-connect@0.12.0
npx esbuild entry.mjs --bundle --format=iife --minify \
    --outfile=tracesettle/static/near-connect.js
```

where `entry.mjs` is:

```js
import { NearConnector } from "@hot-labs/near-connect";
window.TraceSettleWallet = { NearConnector };
```

The connector resolves the wallet manifest and runs wallet code from
`cdn.jsdelivr.net` and `raw.githubusercontent.com`, which the console CSP allows
in `connect-src`/`frame-src`. No wallet key material reaches this server: the
connector runs entirely in the browser and the server never sees a private key.
