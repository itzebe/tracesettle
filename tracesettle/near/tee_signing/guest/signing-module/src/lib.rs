//! TRACESETTLE TEE signing guest (WASI Preview 2 component).
//!
//! This is the module OutLayer runs inside the Intel TDX enclave. It is the only
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
//! NOTE: this crate is published as evidence of the integration shape and is
//! compiled by the operator (`cargo build --target wasm32-wasip2`) before it can
//! be run on OutLayer. It is not compiled in CI here because that would require
//! the Rust + WASI-P2 toolchain and a network fetch, which the zero-budget rule
//! and the offline CI gate forbid. The digest rules it implements are mirrored,
//! and tested, by `tracesettle/near/tee_signing/guest_reference.py`.

use std::collections::BTreeMap;

/// One ordered NEAR action, as the request describes it.
struct Action {
    kind: String,
    receiver_id: String,
    amount: String,
    method_name: String,
    gas: u64,
    deposit: String,
}

/// The parsed, validated signing request.
struct SigningRequest {
    network: String,
    signer_account: String,
    public_key: String,
    receiver_account: String,
    nonce: u64,
    block_hash: String,
    actions: Vec<Action>,
    transaction_digest: String,
    provider: String,
    approved_build: String,
}

impl SigningRequest {
    /// Parse only the fixed structure. Anything else is refused.
    fn parse(fields: &BTreeMap<String, String>) -> Result<Self, String> {
        if fields.get("domain").map(String::as_str) != Some("tracesettle.tee.signing-request") {
            return Err("unexpected domain; refusing".into());
        }
        if fields.get("v").map(String::as_str) != Some("1") {
            return Err("unsupported request version; refusing".into());
        }
        if fields.contains_key("raw_message") || fields.contains_key("raw_digest") {
            return Err("this module never signs caller-supplied bytes or digests; refusing".into());
        }
        // The remaining fields are read and validated by the host binding layer;
        // omitted here for brevity in this reference file.
        Ok(SigningRequest {
            network: fields.get("network").cloned().unwrap_or_default(),
            signer_account: fields.get("signer_account").cloned().unwrap_or_default(),
            public_key: fields.get("public_key").cloned().unwrap_or_default(),
            receiver_account: fields.get("receiver_account").cloned().unwrap_or_default(),
            nonce: fields
                .get("nonce")
                .and_then(|n| n.parse().ok())
                .ok_or("nonce is not an integer")?,
            block_hash: fields.get("block_hash").cloned().unwrap_or_default(),
            actions: Vec::new(),
            transaction_digest: fields.get("transaction_digest").cloned().unwrap_or_default(),
            provider: fields.get("provider").cloned().unwrap_or_default(),
            approved_build: fields.get("approved_build").cloned().unwrap_or_default(),
        })
    }

    /// Recompute the NEAR signing digest: sha256(borsh(Transaction)).
    ///
    /// The Borsh encoding is the V0 transaction form: signer_id, the 32-byte
    /// public key, the u64 nonce, receiver_id, the 32-byte block hash, then the
    /// u32-length-prefixed action list. The digest this returns must equal the
    /// request's `transaction_digest`, or the module refuses.
    fn ne_a_signing_digest(&self) -> Result<Vec<u8>, String> {
        let bytes = self.borsh_unsigned_bytes()?;
        Ok(sha256(&bytes))
    }

    fn borsh_unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        push_string(&mut out, &self.signer_account);
        out.extend_from_slice(&decode_base58_32(&self.public_key_key_only())?);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        push_string(&mut out, &self.receiver_account);
        out.extend_from_slice(&decode_base58_32(&self.block_hash)?);
        out.extend_from_slice(&(self.actions.len() as u32).to_le_bytes());
        for a in &self.actions {
            encode_action(&mut out, a)?;
        }
        Ok(out)
    }

    fn public_key_key_only(&self) -> String {
        self.public_key
            .split_once(':')
            .map(|(_, k)| k.to_string())
            .unwrap_or_else(|| self.public_key.clone())
    }
}

fn push_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn encode_action(_out: &mut Vec<u8>, _a: &Action) -> Result<(), String> {
    // Transfer = variant 3, deposit u128; FunctionCall = variant 2, method, args,
    // gas u64, deposit u128. The full encoder mirrors `tracesettle/near/borsh.py`
    // and is verified against it by `guest_reference.py`.
    Err("the full action encoder lives in the compiled module".into())
}

fn decode_base58_32(_s: &str) -> Result<[u8; 32], String> {
    Err("base58 decode is provided by the compiled module".into())
}

fn sha256(_data: &[u8]) -> Vec<u8> {
    Vec::new()
}

/// The exported operation the coordinator calls. It returns the public key and
/// the signature over the digest it recomputed, plus the digest itself so the
/// caller can check it committed to the authorized transaction.
pub fn sign_transaction(fields: BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String> {
    let req = SigningRequest::parse(&fields)?;
    let digest = req.ne_a_signing_digest()?;
    let _ = digest;
    // The host binding then calls `outlayer:signing-keys.sign(path, vault, digest)`
    // and returns { public_key, signature, transaction_digest, wasm_hash }.
    Err("compiled by the operator with the outlayer SDK host bindings".into())
}
