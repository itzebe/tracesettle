//! TRACESETTLE TEE signing guest (WASI Preview 2 command component).
//!
//! This is the module OutLayer runs inside an Intel TDX enclave. It is the only
//! place the NEAR transaction digest is composed and signed, and the private key
//! never reaches it: the `outlayer:signing-keys` host interface hands back a
//! public key or a signature, never the key.
//!
//! Why the digest is composed *here* and not passed in: OutLayer's own security
//! rule is "never sign caller-supplied bytes or digests verbatim". A module that
//! signs whatever it is handed is a signing oracle for any EVM/NEP-413 message.
//! So this module receives the *structured* signing request, recomputes the NEAR
//! `sha256(borsh(Transaction))` from the fields it parsed and checked, and only
//! then asks the host to sign that digest. The caller cannot make it sign an
//! arbitrary blob.
//!
//! It also refuses anything outside its fixed structure: a request whose
//! `domain` is not `tracesettle.tee.signing-request`, whose `v` is not `1`, or
//! that asks for a raw message, is an error — never a signature.
//!
//! The digest rule is mirrored, and unit-tested against the product's own
//! serializer, by `tracesettle/near/tee_signing/guest_reference.py`; the byte
//! layout is pinned there against `tracesettle/near/borsh.py` and a real
//! on-chain transaction.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ── the outlayer:signing-keys host interface ────────────────────────────────
// Bindings generated from `wit/signing-keys.wit`, a copy of OutLayer's own
// `sdk/outlayer/wit/deps/signing-keys.wit`. `build.sh` diffs the two so a drift
// is reported rather than silently compiled against a stale interface.
//
// The interface is a wasm import, so it is compiled only for the wasm target.
// On the host (`cargo test`) a stub stands in, which lets the digest logic — the
// part that must agree with `tracesettle/near/borsh.py` — be unit-tested natively.
#[cfg(target_arch = "wasm32")]
mod signing_keys_host {
    wit_bindgen::generate!({
        world: "signing-keys-host",
        path: "wit",
    });
}
#[cfg(target_arch = "wasm32")]
use signing_keys_host::outlayer::signing_keys::api as signing_keys;

#[cfg(not(target_arch = "wasm32"))]
mod signing_keys {
    pub fn public_key(_path: &str, _vault: Option<&str>) -> Result<Vec<u8>, String> {
        Err("the signing-keys host is only available inside the enclave".into())
    }
    pub fn sign(_path: &str, _vault: Option<&str>, _message: &[u8]) -> Result<Vec<u8>, String> {
        Err("the signing-keys host is only available inside the enclave".into())
    }
}

// ── the approved build identity, embedded in the manifest custom section ────
// The `outlayer.manifest` section is covered by the wasm's sha256, so the key
// path the enclave derives is tied to *these* bytes. It declares one ed25519
// key, `neartx`, bound to the project and derived for the run's caller.
macro_rules! manifest {
    ($file:literal) => {
        #[cfg(target_arch = "wasm32")]
        #[used]
        #[link_section = "outlayer.manifest"]
        static OUTLAYER_MANIFEST: [u8; include_bytes!($file).len()] = *include_bytes!($file);

        const MANIFEST: &[u8] = include_bytes!($file);
    };
}
#[cfg(feature = "project")]
manifest!("../manifest.json");
#[cfg(feature = "wasm")]
manifest!("../manifest-wasm.json");
#[cfg(not(any(feature = "project", feature = "wasm")))]
compile_error!("choose a manifest: --features project (default) or wasm");

/// The key path this module signs with. It must match `manifest.json`.
const KEY_PATH: &str = "neartx";

/// The only request domain this module signs for.
const EXPECTED_DOMAIN: &str = "tracesettle.tee.signing-request";
const EXPECTED_VERSION: &str = "1";

// ── input ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct Action {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    method_name: Option<String>,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    args: Option<Value>,
    #[serde(default)]
    gas: Option<u64>,
    #[serde(default)]
    deposit: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Authorization {
    /// The guard authorization id this run is bound to, reported back so the
    /// evidence can name the decision that permitted the signature. The digest
    /// and expiry are bound by the product's own request digest, not here.
    #[serde(default)]
    id: String,
}

#[derive(Debug, Deserialize, Default)]
struct Input {
    /// The guest operation. `public_key` returns the derived key without signing
    /// anything; anything else (including the absent value the product's signing
    /// request carries) composes and signs the transaction. Named `guest_op`
    /// because the product's request already uses `operation` for the on-chain
    /// operation (`TRANSFER`/`FT_TRANSFER`), which must not be confused with this.
    #[serde(default)]
    guest_op: String,
    #[serde(default)]
    v: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    signer_account: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    receiver_account: String,
    #[serde(default)]
    nonce: u64,
    #[serde(default)]
    block_hash: String,
    #[serde(default)]
    actions: Vec<Action>,
    #[serde(default)]
    transfer_amount_yocto: String,
    #[serde(default)]
    transaction_digest: String,
    #[serde(default)]
    authorization: Option<Authorization>,
    #[serde(default)]
    approved_build: String,
}

// ── borsh: exactly the subset a NEAR V0 transaction needs ───────────────────

fn push_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// A u128 as 16 little-endian bytes, from a decimal string. Refuses a value
/// that does not fit, rather than truncating it.
fn u128_le(s: &str) -> Result<[u8; 16], String> {
    let v = u128::from_str_radix(s.trim(), 10)
        .map_err(|_| format!("amount {s:?} is not a decimal integer"))?;
    Ok(v.to_le_bytes())
}

/// The ed25519 public key, `ed25519:<base58>`, decoded to its 32 raw bytes.
fn public_key_raw(s: &str) -> Result<[u8; 32], String> {
    let key = s.split(':').next_back().unwrap_or(s);
    let raw = bs58::decode(key)
        .into_vec()
        .map_err(|e| format!("the public key is not base58: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "the public key is not 32 bytes".to_string())?;
    Ok(arr)
}

/// The block hash, base58, decoded to its 32 raw bytes.
fn hash_raw(s: &str) -> Result<[u8; 32], String> {
    let raw = bs58::decode(s.trim())
        .into_vec()
        .map_err(|e| format!("the block hash is not base58: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "the block hash is not 32 bytes".to_string())?;
    Ok(arr)
}

/// One ordered action, encoded exactly as `tracesettle/near/borsh.py` does.
///
/// * `Transfer` — tag 3, then the deposit as a u128.
/// * `FunctionCall` — tag 2, then `method_name` (string), `args` (Vec<u8>),
///   `gas` (u64), `deposit` (u128), in that struct order.
fn encode_action(out: &mut Vec<u8>, a: &Action) -> Result<(), String> {
    match a.kind.as_str() {
        "Transfer" => {
            out.push(3u8);
            let deposit = a
                .deposit
                .clone()
                .or_else(|| a.amount.clone())
                .ok_or("a Transfer action carries no deposit")?;
            out.extend_from_slice(&u128_le(&deposit)?);
        }
        "FunctionCall" => {
            out.push(2u8);
            push_string(out, a.method_name.as_deref().unwrap_or(""));
            let args = a
                .args
                .as_ref()
                .ok_or("a FunctionCall action carries no args")?;
            // The product writes `json.dumps(args)`; the request's `args` value
            // is the same object, so `serde_json::to_string` reproduces the
            // bytes for the receiver_id/amount keys the product emits.
            push_bytes(out, serde_json::to_string(args).map_err(|e| e.to_string())?.as_bytes());
            out.extend_from_slice(&a.gas.unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&u128_le(a.deposit.as_deref().unwrap_or("1"))?);
        }
        other => return Err(format!("unsupported action type {other:?}; refusing")),
    }
    Ok(())
}

/// The exact Borsh `Transaction` bytes (the V0 wire form), recomposed here.
fn unsigned_bytes(req: &Input) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    push_string(&mut out, &req.signer_account);
    // PublicKey::ED25519 = tag 0 then the 32 key bytes.
    out.push(0u8);
    out.extend_from_slice(&public_key_raw(&req.public_key)?);
    out.extend_from_slice(&req.nonce.to_le_bytes());
    push_string(&mut out, &req.receiver_account);
    out.extend_from_slice(&hash_raw(&req.block_hash)?);
    out.extend_from_slice(&(req.actions.len() as u32).to_le_bytes());
    for a in &req.actions {
        encode_action(&mut out, a)?;
    }
    Ok(out)
}

// ── the operation ───────────────────────────────────────────────────────────

fn main() {
    let raw = read_stdin();
    let answer = match serde_json::from_str::<Input>(if raw.trim().is_empty() { "{}" } else { &raw }) {
        Ok(input) => match input.guest_op.as_str() {
            // The derived key, without signing anything. Lets a driver learn the
            // TEE-held public key before it builds the transaction that key signs.
            "public_key" => match signing_keys::public_key(KEY_PATH, None) {
                Ok(key) => json!({
                    "status": "ok",
                    "operation": "public_key",
                    "public_key": format!("ed25519:{}", bs58::encode(&key).into_string()),
                }),
                Err(e) => err(format!("the signing key is unavailable: {e}")),
            },
            _ => match sign_transaction(&input) {
                Ok(v) => v,
                Err(message) => err(message),
            },
        },
        Err(e) => err(format!("input is not the signing request this module reads: {e}")),
    };
    emit(answer);
}

fn sign_transaction(req: &Input) -> Result<Value, String> {
    // The fixed structure. Anything else is refused before a digest is composed.
    if req.domain != EXPECTED_DOMAIN {
        return Err(format!("unexpected request domain {:?}; refusing", req.domain));
    }
    if req.v != EXPECTED_VERSION {
        return Err(format!("unsupported request version {:?}; refusing", req.v));
    }

    let bytes = unsigned_bytes(req)?;
    let digest = Sha256::digest(&bytes);

    // The recomputed digest must equal the one the request commits to. If it
    // does not, the request describes a different transaction than the bytes.
    let claimed = req.transaction_digest.split(':').next_back().unwrap_or("");
    if !claimed.is_empty() && !claimed.eq_ignore_ascii_case(&hex::encode(digest)) {
        return Err("the recomposed transaction digest does not match the request; refusing".into());
    }

    // Ask the enclave to sign the digest this module composed. The key never
    // reaches the guest; a refusal is an `err`, never a trap.
    let public_key = signing_keys::public_key(KEY_PATH, None)
        .map_err(|e| format!("the signing key is unavailable: {e}"))?;
    let signature = signing_keys::sign(KEY_PATH, None, &digest)
        .map_err(|e| format!("the enclave refused to sign: {e}"))?;

    // Verify the signature over the digest, in the guest, with the key we asked
    // for. A signature that does not verify is refused, not returned.
    if !verify_ed25519(&public_key, &digest, &signature) {
        return Err("the returned signature does not verify over the digest; refusing".into());
    }

    // SignedTransaction = the transaction bytes then Signature::ED25519 (tag 0,
    // then the 64 signature bytes).
    let mut signed = bytes;
    signed.push(0u8);
    signed.extend_from_slice(&signature);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(json!({
        "status": "ok",
        "operation": "sign_transaction",
        "network": req.network,
        "signer_id": req.signer_account,
        "receiver_id": req.receiver_account,
        "amount_base": req.transfer_amount_yocto,
        "transaction_digest": format!("sha256:{}", hex::encode(digest)),
        "tx_hash": bs58::encode(&digest).into_string(),
        "public_key": format!("ed25519:{}", bs58::encode(&public_key).into_string()),
        "signature": b64.encode(&signature),
        "signed_transaction": b64.encode(&signed),
        "signature_verified_in_guest": true,
        "approved_build": req.approved_build,
        "authorization_id": req.authorization.as_ref().map(|a| a.id.clone()).unwrap_or_default(),
        "manifest_len": MANIFEST.len(),
    }))
}

fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key: [u8; 32] = match public_key.try_into() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig: [u8; 64] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    match VerifyingKey::from_bytes(&key) {
        Ok(vk) => vk.verify(message, &Signature::from_bytes(&sig)).is_ok(),
        Err(_) => false,
    }
}

fn ok_manifest_len() -> usize {
    MANIFEST.len()
}

// ── io ──────────────────────────────────────────────────────────────────────

fn read_stdin() -> String {
    use std::io::Read;
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

fn err(message: impl Into<String>) -> Value {
    json!({"status": "err", "message": message.into(), "operation": "sign_transaction"})
}

fn emit(answer: Value) {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(answer.to_string().as_bytes());
    let _ = stdout.flush();
}

#[allow(dead_code)]
fn manifest_is_present() -> bool {
    ok_manifest_len() > 2
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// The digest rule is the part that must agree with the product's own
// serializer. `vectors/tee_signing_vectors.json` is generated by
// `tracesettle` (`scripts/`-free: see the module's README); each vector carries
// the canonical signing request and the digest the product computes for it. The
// guest recomposes the same digest from the structured fields, so a drift in
// either the Borsh layout or the `args` JSON encoding fails here rather than
// producing a signature over bytes the network rejects.
#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../vectors/tee_signing_vectors.json");

    fn vectors() -> Vec<serde_json::Value> {
        serde_json::from_str(VECTORS).expect("the vector file is JSON")
    }

    fn input_of(v: &serde_json::Value) -> Input {
        serde_json::from_value(v["input"].clone()).expect("the input is a signing request")
    }

    #[test]
    fn the_guest_recomposes_the_products_digest() {
        for v in vectors() {
            let req = input_of(&v);
            let bytes = unsigned_bytes(&req).expect("the request composes");
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            assert_eq!(
                digest, v["expected_transaction_digest"],
                "guest digest for {} differs from the product's",
                v["name"]
            );
        }
    }

    #[test]
    fn the_ft_transfer_args_are_the_compact_ordered_form() {
        for v in vectors() {
            let req = input_of(&v);
            if let Some(a) = req.actions.iter().find(|a| a.kind == "FunctionCall") {
                let args = a.args.as_ref().expect("a FunctionCall carries args");
                let encoded = serde_json::to_string(args).unwrap();
                assert_eq!(encoded, r#"{"receiver_id":"merchant.testnet","amount":"1500000"}"#);
            }
        }
    }

    #[test]
    fn a_wrong_domain_is_refused() {
        let mut v = vectors();
        let mut req = input_of(&v.remove(0));
        req.domain = "evil".into();
        assert!(sign_transaction(&req).is_err());
    }

    #[test]
    fn a_tampered_amount_is_refused_by_the_digest_check() {
        let v = vectors();
        let mut req = input_of(&v[0]);
        // Change the amount without changing the committed digest: the guest
        // recomposes the bytes, so the digest no longer matches and it refuses.
        req.transfer_amount_yocto = "1".into();
        if let Some(a) = req.actions.get_mut(0) {
            a.deposit = Some("1".into());
        }
        let err = sign_transaction(&req).expect_err("a changed amount must be refused");
        assert!(err.contains("does not match"), "unexpected error: {err}");
    }
}
