// Cross-checks the emulator's Borsh `Transaction` layout against a fixed vector
// produced by the repository's own serializer (tracesettle/near/borsh.py), so
// the two can never drift silently.
//
//   node --test borsh.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { buildTransferBytes, b58encode } from "./wallet.mjs";

// Produced by: tracesettle.near.txbuild.build_transfer(...) for
//   signer alice.testnet, receiver bob.testnet, nonce 42, amount 1 NEAR,
//   block 9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9
//   public key ed25519:FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF
const VECTOR = {
  signerId: "alice.testnet",
  receiverId: "bob.testnet",
  publicKey: "ed25519:FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF",
  nonce: 42,
  blockHashB58: "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9",
  deposit: "1000000000000000000000000",
  unsigned_b64:
    "DQAAAGFsaWNlLnRlc3RuZXQAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbgqAAAAAAAAAAsAAABib2IudGVzdG5ldHrrphgV1yxGnBA16BosfwHX3D4ciy7Rx+OuElE9Syr6AQAAAAMAAACh7czOG8LTAAAAAAAA",
  tx_hash: "EZSyLnj4MLQ5ejxSKq8GSfNauXRg2U1JYQiFjUExVth8",
};

test("emulator Borsh layout matches the repository serializer", () => {
  const tx = buildTransferBytes(VECTOR);
  assert.equal(tx.toString("base64"), VECTOR.unsigned_b64);
});

test("emulator transaction hash matches the repository serializer", () => {
  const tx = buildTransferBytes(VECTOR);
  const hash = b58encode(crypto.createHash("sha256").update(tx).digest());
  assert.equal(hash, VECTOR.tx_hash);
});

test("a changed amount changes the transaction bytes and hash", () => {
  const a = buildTransferBytes(VECTOR);
  const b = buildTransferBytes({ ...VECTOR, deposit: "2000000000000000000000000" });
  assert.notEqual(a.toString("base64"), b.toString("base64"));
  assert.notEqual(
    b58encode(crypto.createHash("sha256").update(a).digest()),
    b58encode(crypto.createHash("sha256").update(b).digest())
  );
});
