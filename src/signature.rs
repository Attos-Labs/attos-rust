//! Signed artifacts (mirrors the Go SDK's signature.go).
//!
//! The control plane can sign every dataset file with an Ed25519 key. The signature travels in the
//! `X-Attos-Signature` response header, detached from the file:
//!
//! ```text
//! X-Attos-Signature: alg=ed25519; kid=<key id>; sig=<base64 of 64 bytes>
//! ```
//!
//! The signed message is `"attos-artifact-v1\0" + datasetID + "\0" + SHA-256(file)`, which binds the signature
//! to one dataset. Configure trusted public keys with `SyncConfig::signature_keys`; from then on the SDK
//! refuses any downloaded or cached file without a valid signature (fail closed), keeps serving the file it
//! has, and counts the failure.

use crate::error::AttosError;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

/// Response header carrying the detached signature.
pub const SIGNATURE_HEADER: &str = "X-Attos-Signature";

/// Decodes a base64 (standard or URL-safe, padded or not) Ed25519 public key.
pub fn parse_public_key(b64: &str) -> Result<[u8; 32], AttosError> {
    let t = b64.trim().trim_end_matches('=');
    for e in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(b) = e.decode(t) {
            if let Ok(k) = <[u8; 32]>::try_from(b.as_slice()) {
                return Ok(k);
            }
        }
    }
    Err(AttosError::Config("public key must be 32 bytes, base64 encoded".into()))
}

pub(crate) fn signed_message(dataset_id: &str, digest: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(18 + dataset_id.len() + 1 + digest.len());
    m.extend_from_slice(b"attos-artifact-v1\0");
    m.extend_from_slice(dataset_id.as_bytes());
    m.push(0);
    m.extend_from_slice(digest);
    m
}

/// Checks `header` against `digest` for this dataset: [`AttosError::SignatureMissing`] without a header,
/// [`AttosError::SignatureInvalid`] for a malformed header, unknown key id, other algorithm or a signature
/// that does not verify.
pub(crate) fn verify(
    keys: &HashMap<String, [u8; 32]>,
    dataset_id: &str,
    header: Option<&str>,
    digest: &[u8],
) -> Result<(), AttosError> {
    let header = match header {
        Some(h) if !h.is_empty() => h,
        _ => return Err(AttosError::SignatureMissing),
    };
    let invalid = |m: String| AttosError::SignatureInvalid(m);
    let (mut alg, mut kid, mut sig) = ("", "", "");
    for part in header.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            match k {
                "alg" => alg = v,
                "kid" => kid = v,
                "sig" => sig = v,
                _ => {}
            }
        }
    }
    if alg != "ed25519" {
        return Err(invalid(format!("unsupported algorithm {:?}", alg)));
    }
    let pk = keys.get(kid).ok_or_else(|| invalid(format!("unknown key id {:?}", kid)))?;
    let raw = STANDARD.decode(sig).ok().filter(|r| r.len() == 64).ok_or_else(|| invalid("malformed signature".into()))?;
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| invalid("malformed public key".into()))?;
    let sg = Signature::from_slice(&raw).map_err(|_| invalid("malformed signature".into()))?;
    vk.verify(&signed_message(dataset_id, digest), &sg)
        .map_err(|_| invalid("does not match the file".into()))
}

/// Signs a file digest the way the control plane does (for tests and tooling).
pub fn sign_artifact(seed: &[u8; 32], kid: &str, dataset_id: &str, digest: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let sig = sk.sign(&signed_message(dataset_id, digest));
    format!("alg=ed25519; kid={}; sig={}", kid, STANDARD.encode(sig.to_bytes()))
}

/// The public key matching a signing seed (for tests and tooling).
pub fn public_key_for(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// SHA-256 of `data` (the digest that is signed).
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut h = crate::sha256::Sha256::new();
    h.update(data);
    h.finish()
}

/// Lower-case hex SHA-256 of `data`.
pub fn sha256_digest_hex(data: &[u8]) -> String {
    crate::sha256::hex(&sha256_digest(data))
}
