// A browser-wallet emulator for the real TraceSettle console.
//
// It plays the role of a NEAR browser wallet EXTENSION: it holds the account
// key material in this Node process and the web page (the dapp) never sees it.
// The page only ever receives a signed-and-broadcast result (the transaction
// hash), exactly as a real extension would return.
//
// It builds the NEAR transaction with the SAME Borsh layout the repository
// uses (tracesettle/near/borsh.py), fetches the access-key nonce and the latest
// block hash from NEAR testnet RPC, signs ed25519, broadcasts, and returns the
// on-chain transaction hash.
import crypto from "node:crypto";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error("bad base58 char: " + ch);
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const body = hex === "00" ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  const pad = s.length - s.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(pad), body]);
}
export function b58encode(buf) {
  let n = BigInt("0x" + (buf.toString("hex") || "0"));
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  const pad = buf.length - buf.length; // leading zero handling below
  let zeros = 0;
  for (const b of buf) {
    if (b === 0) zeros++;
    else break;
  }
  return "1".repeat(zeros) + (out || "");
}

const u8 = (v) => Buffer.from([v & 0xff]);
const u32 = (v) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0);
  return b;
};
const u64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return b;
};
const u128 = (v) => {
  let n = BigInt(v);
  const b = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return b;
};
const str = (s) => {
  const raw = Buffer.from(s, "utf8");
  return Buffer.concat([u32(raw.length), raw]);
};

function sha256(b) {
  return crypto.createHash("sha256").update(b).digest();
}

// Borsh `Transaction` V0 (signer_id, public_key, nonce, receiver_id, block_hash,
// actions) with one Transfer action - the same layout as
// tracesettle/near/borsh.py::transaction. Exported so it can be unit-tested
// against the repository's own serializer.
export function buildTransferBytes({ signerId, receiverId, publicKey, nonce, blockHashB58, deposit }) {
  const pubRaw = b58decode(String(publicKey).replace(/^ed25519:/, ""));
  const action = Buffer.concat([u8(3), u128(deposit)]);
  return Buffer.concat([
    str(signerId),
    u8(0),
    pubRaw,
    u64(nonce),
    str(receiverId),
    b58decode(blockHashB58),
    u32(1),
    action,
  ]);
}

export class EmulatedWallet {
  constructor({ seedHex, accountId, publicKey, rpcUrl = "https://rpc.testnet.near.org" }) {
    this.seed = Buffer.from(seedHex, "hex");
    this.accountId = accountId;
    this.publicKey = publicKey; // ed25519:<base58>
    this.pubRaw = b58decode(publicKey.replace(/^ed25519:/, ""));
    this.rpcUrl = rpcUrl;
    this.calls = [];
    this.rejectNext = false;
  }

  async rpc(method, params) {
    const res = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "ts", method, params }),
    });
    const body = await res.json();
    if (body.error) throw new Error(method + ": " + JSON.stringify(body.error));
    return body.result;
  }

  async nextNonce() {
    const r = await this.rpc("query", {
      request_type: "view_access_key",
      finality: "final",
      account_id: this.accountId,
      public_key: this.publicKey,
    });
    return BigInt(r.nonce) + 1n;
  }

  async latestBlockHash() {
    const r = await this.rpc("block", { finality: "final" });
    return r.header.hash;
  }

  buildUnsigned(request, nonce, blockHashB58) {
    return buildTransferBytes({
      signerId: request.signerId,
      receiverId: request.receiverId,
      publicKey: this.publicKey,
      nonce,
      blockHashB58,
      deposit: request.actions[0].params.deposit,
    });
  }

  sign(txBytes) {
    const pkcs8 = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      this.seed,
    ]);
    const key = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    // NEAR signs sha256(borsh(Transaction)) - the transaction hash, not the raw bytes.
    const sig = crypto.sign(null, sha256(txBytes), key);
    return sig; // 64 bytes
  }

  // The extension's signAndSendTransaction: build, sign, broadcast.
  async signAndSendTransaction(request) {
    this.calls.push(request);
    if (this.rejectNext) {
      this.rejectNext = false;
      throw new Error("User rejected the signature request");
    }
    const nonce = await this.nextNonce();
    const blockHash = await this.latestBlockHash();
    const unsigned = this.buildUnsigned(request, nonce, blockHash);
    const expectedHash = b58encode(sha256(unsigned));
    const sig = this.sign(unsigned);
    const signed = Buffer.concat([unsigned, u8(0), sig]);
    const b64 = signed.toString("base64");
    const result = await this.rpc("broadcast_tx_commit", [b64]);
    const onchainHash =
      (result.transaction && result.transaction.hash) ||
      (result.transaction_outcome && result.transaction_outcome.id);
    return {
      _expectedHash: expectedHash,
      _onchainHash: onchainHash,
      _status: result.status,
      transaction: { hash: onchainHash },
      transaction_outcome: { id: onchainHash },
      status: result.status,
    };
  }
}
