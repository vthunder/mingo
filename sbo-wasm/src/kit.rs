//! Phase 7.4 — the `sbo-wasm` serialization kit (pure Rust).
//!
//! Builds canonical SBO envelopes and produces the exact bytes the signer must
//! sign, so a browser client gets **signing-byte parity** with the native
//! daemon for free (this is the carved `sbo-core` wire/message subset). The
//! signature itself is produced **outside** this kit — by the browserid agent
//! holding the cert-bound key — and folded back in via [`assemble_wire`]. The
//! kit never sees a private key.
//!
//! Flow: [`signing_bytes`] (build → canonical signing content) → agent signs →
//! [`assemble_wire`] (build → set signature → wire bytes) → POST to the daemon.
//! [`object_hash`] is the SHA-256 of the assembled wire (the content-layer
//! `object_hash` / merkle leaf). These functions are plain Rust and unit-tested
//! natively; [`crate::bindings`] is the thin `wasm_bindgen` layer over them.

use serde::{Deserialize, Serialize};

use crate::crypto::{ContentHash, PublicKey, Signature};
use crate::message::{Action, Id, Message, ObjectType, Path};
use crate::wire;

/// Errors building or assembling an envelope.
#[derive(Debug, thiserror::Error)]
pub enum KitError {
    #[error("invalid action: {0}")]
    Action(String),
    #[error("invalid path: {0}")]
    Path(String),
    #[error("invalid id: {0}")]
    Id(String),
    #[error("invalid owner: {0}")]
    Owner(String),
    #[error("invalid public key: {0}")]
    PublicKey(String),
    #[error("invalid signature: {0}")]
    Signature(String),
    #[error("payload serialization: {0}")]
    Payload(String),
}

/// A complete description of an envelope to build. Mirrors the SBO headers the
/// content layer uses; ordering/conflict fields (`hlc`, `prev`) are optional and
/// stamped by the caller (the browser supplies wall-clock ms for `hlc`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSpec {
    /// Wire action name (`post`, `delete`). Defaults to `post` when empty.
    #[serde(default)]
    pub action: String,
    /// Prefix path with a trailing slash, e.g. `/communities/cooks/spaces/general/`.
    pub path: String,
    /// Object id, e.g. `p1`.
    pub id: String,
    /// The signer's public key as `ed25519:<hex>` — the browserid agent's
    /// cert-bound key (the `Public-Key` header).
    pub public_key: String,
    /// Content type; defaults to `application/json`.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Content schema, e.g. `post.v1`.
    #[serde(default)]
    pub content_schema: Option<String>,
    /// Owner header (the controller: an email or local name).
    #[serde(default)]
    pub owner: Option<String>,
    /// The raw payload bytes (e.g. the JSON from a [`payloads`] helper).
    #[serde(with = "serde_bytes_vec", default)]
    pub payload: Vec<u8>,
    /// HLC wire form `<physical_ms>.<counter>` (content-layer ordering).
    #[serde(default)]
    pub hlc: Option<String>,
    /// Prev: the `object_hash` (hex) this write is based on.
    #[serde(default)]
    pub prev: Option<String>,
    /// Auth-Cert (browserid certificate) for email-rooted writes.
    #[serde(default)]
    pub auth_cert: Option<String>,
    /// Auth-Evidence (DNSSEC chain) for email-rooted writes.
    #[serde(default)]
    pub auth_evidence: Option<String>,
}

/// Serde helper so `payload` round-trips as a JSON array of bytes (and as a
/// `Uint8Array` through serde-wasm-bindgen) rather than a string.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().copied())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

/// Build a `Message` from a spec, with a **placeholder signature** (all-zero).
/// The headers — and therefore the canonical signing content — are fully
/// determined here; only the signature is filled in later.
pub fn build_message(spec: &EnvelopeSpec) -> Result<Message, KitError> {
    let action = if spec.action.is_empty() {
        Action::Post
    } else {
        Action::parse(&spec.action).map_err(|e| KitError::Action(e.to_string()))?
    };
    let path = Path::parse(&spec.path).map_err(|e| KitError::Path(e.to_string()))?;
    let id = Id::new(&spec.id).map_err(|e| KitError::Id(e.to_string()))?;
    let public_key = PublicKey::parse(&spec.public_key).map_err(|e| KitError::PublicKey(e.to_string()))?;
    let owner = match &spec.owner {
        Some(o) => Some(Id::new(o).map_err(|e| KitError::Owner(e.to_string()))?),
        None => None,
    };
    let content_type = spec
        .content_type
        .clone()
        .unwrap_or_else(|| "application/json".to_string());
    let content_hash = ContentHash::sha256(&spec.payload);

    Ok(Message {
        action,
        path,
        id,
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: Signature([0u8; 64]),
        content_type: Some(content_type),
        content_hash: Some(content_hash),
        payload: Some(spec.payload.clone()),
        owner,
        creator: None,
        content_encoding: None,
        content_schema: spec.content_schema.clone(),
        policy_ref: None,
        related: None,
        hlc: spec.hlc.clone(),
        prev: spec.prev.clone(),
        auth_cert: spec.auth_cert.clone(),
        auth_evidence: spec.auth_evidence.clone(),
    })
}

/// The exact bytes the signer must sign for this envelope (the canonical signing
/// content — every header except `Signature`). Byte-identical to what the native
/// `sbo-core` verifier recomputes.
pub fn signing_bytes(spec: &EnvelopeSpec) -> Result<Vec<u8>, KitError> {
    Ok(build_message(spec)?.canonical_signing_content())
}

/// Fold a detached signature (`hex`, 64 bytes) into the envelope and return the
/// canonical wire bytes ready for `POST /v1/submit`.
pub fn assemble_wire(spec: &EnvelopeSpec, signature_hex: &str) -> Result<Vec<u8>, KitError> {
    let mut msg = build_message(spec)?;
    msg.signature = Signature::parse(signature_hex).map_err(|e| KitError::Signature(e.to_string()))?;
    Ok(wire::serialize(&msg))
}

/// SHA-256 of the assembled wire bytes — the content-layer `object_hash` (the
/// value a later write puts in its `Prev`, and the merkle leaf).
pub fn object_hash(wire_bytes: &[u8]) -> [u8; 32] {
    crate::crypto::sha256(wire_bytes)
}

/// JSON payload builders for the content/attestation schemas the demo writes.
/// Each returns canonical `serde_json` bytes for [`EnvelopeSpec::payload`].
pub mod payloads {
    use super::KitError;

    fn to_vec(v: serde_json::Value) -> Result<Vec<u8>, KitError> {
        serde_json::to_vec(&v).map_err(|e| KitError::Payload(e.to_string()))
    }

    /// `post.v1` — `body` required; `parent`/`created_at` optional.
    pub fn post(body: &str, parent: Option<&str>, created_at: Option<i64>) -> Result<Vec<u8>, KitError> {
        to_vec(serde_json::json!({ "body": body, "parent": parent, "created_at": created_at }))
    }

    /// `comment.v1` — `body` and `parent` required.
    pub fn comment(body: &str, parent: &str, created_at: Option<i64>) -> Result<Vec<u8>, KitError> {
        to_vec(serde_json::json!({ "body": body, "parent": parent, "created_at": created_at }))
    }

    /// `reaction.v1` — `target`/`kind` required; `state` toggles (false = remove).
    pub fn reaction(target: &str, kind: &str, state: bool) -> Result<Vec<u8>, KitError> {
        to_vec(serde_json::json!({ "target": target, "kind": kind, "state": state }))
    }

    /// `attestation.v1` for a self-issued `membership` (open communities). The
    /// `issuer`/Owner binding and storage path are set on the envelope, not here.
    pub fn membership(subject: &str, issuer: &str, issued_at: i64, expires: Option<i64>) -> Result<Vec<u8>, KitError> {
        to_vec(serde_json::json!({
            "subject": subject,
            "type": "membership",
            "value": true,
            "issued_at": issued_at,
            "expires": expires,
            "issuer": issuer,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    fn spec_for(key: &SigningKey, payload: Vec<u8>) -> EnvelopeSpec {
        EnvelopeSpec {
            action: String::new(),
            path: "/communities/cooks/spaces/general/".to_string(),
            id: "p1".to_string(),
            public_key: key.public_key().to_string(),
            content_type: None,
            content_schema: Some("post.v1".to_string()),
            owner: Some("alice@mingo.place".to_string()),
            payload,
            hlc: Some("1703001234567.0".to_string()),
            prev: None,
            auth_cert: None,
            auth_evidence: None,
        }
    }

    #[test]
    fn signing_bytes_then_external_sign_then_assemble_verifies() {
        let key = SigningKey::generate();
        let payload = payloads::post("hello from the kit", None, None).unwrap();
        let spec = spec_for(&key, payload);

        // 1. Kit produces the bytes to sign.
        let to_sign = signing_bytes(&spec).unwrap();
        // 2. The "agent" (here, a local key) signs them out-of-band.
        let sig = key.sign(&to_sign);
        // 3. Kit folds the detached signature into the wire.
        let wire_bytes = assemble_wire(&spec, &sig.to_hex()).unwrap();

        // The assembled envelope parses and its signature verifies natively.
        let parsed = wire::parse(&wire_bytes).expect("wire parses");
        assert!(crate::message::verify_message(&parsed).is_ok(), "signature verifies");
        assert_eq!(parsed.content_schema.as_deref(), Some("post.v1"));
        assert_eq!(parsed.hlc.as_deref(), Some("1703001234567.0"));
        assert_eq!(parsed.owner.as_ref().map(|o| o.as_str()), Some("alice@mingo.place"));
    }

    #[test]
    fn signing_bytes_are_independent_of_signature() {
        // The bytes to sign must not depend on the placeholder signature: the
        // detached-sign flow is only sound if signing content excludes Signature.
        let key = SigningKey::generate();
        let spec = spec_for(&key, payloads::post("x", None, None).unwrap());
        let bytes = signing_bytes(&spec).unwrap();
        let sig = key.sign(&bytes);
        let wire_bytes = assemble_wire(&spec, &sig.to_hex()).unwrap();
        let reparsed = wire::parse(&wire_bytes).unwrap();
        assert_eq!(bytes, reparsed.canonical_signing_content());
    }

    #[test]
    fn object_hash_matches_sha256_of_wire() {
        let key = SigningKey::generate();
        let spec = spec_for(&key, payloads::post("x", None, None).unwrap());
        let sig = key.sign(&signing_bytes(&spec).unwrap());
        let wire_bytes = assemble_wire(&spec, &sig.to_hex()).unwrap();
        assert_eq!(object_hash(&wire_bytes), crate::crypto::sha256(&wire_bytes));
    }

    #[test]
    fn prev_chains_object_hash() {
        // A second write can reference the first's object_hash via `prev`.
        let key = SigningKey::generate();
        let s1 = spec_for(&key, payloads::post("first", None, None).unwrap());
        let w1 = assemble_wire(&s1, &key.sign(&signing_bytes(&s1).unwrap()).to_hex()).unwrap();
        let h1 = hex::encode(object_hash(&w1));

        let mut s2 = spec_for(&key, payloads::post("second", None, None).unwrap());
        s2.id = "p2".to_string();
        s2.prev = Some(h1.clone());
        let w2 = assemble_wire(&s2, &key.sign(&signing_bytes(&s2).unwrap()).to_hex()).unwrap();
        let parsed2 = wire::parse(&w2).unwrap();
        assert_eq!(parsed2.prev.as_deref(), Some(h1.as_str()));
        assert!(crate::message::verify_message(&parsed2).is_ok());
    }

    #[test]
    fn payload_helpers_shape() {
        let p = payloads::post("b", Some("/x"), Some(1)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["body"], "b");
        assert_eq!(v["parent"], "/x");

        let c = payloads::comment("b", "/parent", None).unwrap();
        let cv: serde_json::Value = serde_json::from_slice(&c).unwrap();
        assert_eq!(cv["parent"], "/parent");

        let r = payloads::reaction("/t", "upvote", true).unwrap();
        let rv: serde_json::Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(rv["kind"], "upvote");
        assert_eq!(rv["state"], true);

        let m = payloads::membership("alice@mingo.place", "cooks@mingo.place", 100, None).unwrap();
        let mv: serde_json::Value = serde_json::from_slice(&m).unwrap();
        assert_eq!(mv["type"], "membership");
    }

    #[test]
    fn bad_public_key_is_an_error() {
        let spec = EnvelopeSpec {
            action: String::new(),
            path: "/x/".to_string(),
            id: "y".to_string(),
            public_key: "not-a-key".to_string(),
            content_type: None,
            content_schema: None,
            owner: None,
            payload: b"{}".to_vec(),
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
        };
        assert!(matches!(signing_bytes(&spec), Err(KitError::PublicKey(_))));
    }
}
