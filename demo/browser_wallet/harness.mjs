// Drives the REAL TraceSettle console in a REAL Chromium browser with a
// browser-wallet emulator that holds the key and signs. The page never sees a
// private key: it receives only signIn/getAccounts results and a signed-and-
// broadcast transaction hash, exactly as a real wallet extension returns.
//
// This is a DEMONSTRATION harness. It signs and broadcasts real *testnet*
// transactions. The account key is supplied through the environment by
// run_demo.py and is never written to disk or logged here.
//
// Scenarios (argv[2]):
//   happy   - an approved transfer: authorization ALLOW, wallet signs, VERIFIED
//   blocked - a non-approved recipient: authorization BLOCK, wallet never asked
//   tamper  - the wallet signs a different amount: settlement DISPUTED
//   reject  - the user rejects the signature: nothing is broadcast
import puppeteer from "puppeteer-core";
import fs from "node:fs";
import { EmulatedWallet } from "./wallet.mjs";

const env = process.env;
const info = {
  seed_hex: env.TSW_SEED,
  account: env.TSW_ACCOUNT,
  public_key: env.TSW_PUBKEY,
  receiver: env.TSW_RECEIVER,
};
const API_KEY = env.TSW_API_KEY;
const CONSOLE = env.TSW_CONSOLE || "http://127.0.0.1:8000/console";
const CHROMIUM = env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium";
const scenario = process.argv[2] || "happy";
const outDir = env.TS_OUTDIR || "/tmp/tracesettle-browser-wallet";
fs.mkdirSync(outDir, { recursive: true });

const wallet = new EmulatedWallet({
  seedHex: info.seed_hex,
  accountId: info.account,
  publicKey: info.public_key,
});
const state = { rejectNextSign: false, tamperAmount: null };
const results = { scenario, events: [] };

const browser = await puppeteer.launch({
  executablePath: CHROMIUM,
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const page = await browser.newPage();
await page.setViewport({ width: 1280, height: 1600 });
page.on("pageerror", (e) => results.events.push("pageerror: " + e.message));
page.on("dialog", async (d) => {
  results.events.push("dialog: " + d.type() + " " + (d.message() || "").split("\n")[0]);
  await d.accept();
});

// The wallet bridge: the page calls this; the real key stays in Node.
await page.exposeFunction("__tsWalletRequest", async (method, params) => {
  results.events.push("wallet:" + method);
  if (method === "near:signIn" || method === "near:getAccounts") {
    return [{ accountId: info.account, publicKey: info.public_key }];
  }
  if (method === "near:signOut") return true;
  if (method === "near:signAndSendTransaction") {
    if (state.rejectNextSign) {
      state.rejectNextSign = false;
      throw new Error("User rejected the signature request");
    }
    let req = params;
    if (state.tamperAmount) {
      req = {
        ...params,
        actions: params.actions.map((a) =>
          a.type === "Transfer"
            ? { ...a, params: { ...a.params, deposit: state.tamperAmount } }
            : a
        ),
      };
      results.events.push("wallet:tampered deposit -> " + state.tamperAmount);
    }
    let r;
    try {
      r = await wallet.signAndSendTransaction(req);
    } catch (err) {
      results.broadcastError = String((err && err.message) || err);
      throw err;
    }
    results.broadcast = {
      expectedHash: r._expectedHash,
      onchainHash: r._onchainHash,
      status: r._status,
    };
    return {
      transaction: { hash: r._onchainHash },
      transaction_outcome: { id: r._onchainHash },
      status: r._status,
    };
  }
  throw new Error("unsupported method " + method);
});

// Inject the "wallet extension" into the page: it answers the connector's
// injected-wallet protocol by delegating to the Node-side wallet bridge.
await page.evaluateOnNewDocument(() => {
  window.__WALLET_LOG__ = [];
  function reply(id, result, error) {
    window.postMessage(
      { type: "near-wallet-injected-response", id, success: !error, result: result ?? null, error: error ?? null },
      "*"
    );
  }
  window.addEventListener("message", async (e) => {
    const d = e.data;
    if (!d || d.type !== "near-wallet-injected-request") return;
    window.__WALLET_LOG__.push({ method: d.method });
    try {
      const result = await window.__tsWalletRequest(d.method, d.params);
      reply(d.id, result);
    } catch (err) {
      reply(d.id, null, String((err && err.message) || err));
    }
  });
  function register() {
    window.postMessage(
      {
        type: "near-wallet-injected",
        manifest: {
          id: "tracesettle-demo-wallet",
          name: "TraceSettle Demo Wallet (testnet)",
          features: { testnet: true, mainnet: true, signIn: true, signAndSendTransaction: true },
        },
      },
      "*"
    );
  }
  window.addEventListener("near-selector-ready", register);
  setTimeout(register, 1000);
  setTimeout(register, 2500);
});

await page.goto(CONSOLE, { waitUntil: "networkidle2", timeout: 45000 });
await page.type("#apikey", API_KEY);
await page.click("#tab-near");
await page.waitForFunction(() => document.getElementById("w-connect"), { timeout: 20000 });

// Select our injected wallet directly (no selector popup).
await page.evaluate(() => {
  const Orig = window.TraceSettleWallet.NearConnector;
  window.TraceSettleWallet.NearConnector = class extends Orig {
    async connect(opts = {}) {
      return super.connect({ ...opts, walletId: opts.walletId || "tracesettle-demo-wallet" });
    }
  };
});

await page.click("#w-connect");
await page.waitForFunction(
  (acct) => document.getElementById("w-account").textContent.trim() === acct,
  { timeout: 20000 },
  info.account
);
results.connectedAccount = await page.$eval("#w-account", (el) => el.textContent.trim());

const receiver = scenario === "blocked" ? "not-approved-" + Date.now() + ".testnet" : info.receiver;
if (scenario === "tamper") state.tamperAmount = "500000000000000000000000"; // 0.5 NEAR, not the authorized 0.02
if (scenario === "reject") state.rejectNextSign = true;

await page.$eval("#w-receiver", (el, v) => (el.value = v), receiver);
await page.$eval("#w-amount", (el) => (el.value = "0.02"));
await page.$eval("#w-receiver", (el) => el.dispatchEvent(new Event("input", { bubbles: true })));
await page.$eval("#w-amount", (el) => el.dispatchEvent(new Event("input", { bubbles: true })));

const beforeCalls = wallet.calls.length;
await page.click("#w-send");
await new Promise((r) => setTimeout(r, 22000));

results.outputText = await page.$eval("#wallet-output", (el) => el.innerText);
results.walletAsked = wallet.calls.length - beforeCalls;
results.lastWalletRequest = wallet.calls.length ? wallet.calls[wallet.calls.length - 1] : null;

await page.screenshot({ path: outDir + "/" + scenario + ".png", fullPage: false });
fs.writeFileSync(outDir + "/" + scenario + ".json", JSON.stringify(results, null, 2));
console.log(
  JSON.stringify(
    {
      scenario,
      connected: results.connectedAccount,
      walletAsked: results.walletAsked,
      broadcast: results.broadcast || null,
      output: results.outputText,
    },
    null,
    2
  )
);
await browser.close();
