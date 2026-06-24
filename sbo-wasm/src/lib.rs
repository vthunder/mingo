//! Phase 7.0 spike — `sbo-wasm`.
//!
//! Proves the SBO **wire + message + crypto + error** subset is wasm-clean and
//! produces the exact same canonical signing bytes as the native daemon. The
//! modules are `#[path]`-included verbatim from `sbo-core` (same source compiled
//! for two targets), so parity is by construction; this crate just isolates the
//! subset from `sbo-core`'s native-only deps (rocksdb/reqwest/dnssec) so it can
//! target `wasm32-unknown-unknown`.
//!
//! If this builds for wasm32 and the round-trip test passes, the client signing
//! path is viable: `sbo-wasm` builds canonical bytes in the browser, the
//! browserid agent signs them, and `sbo-core` (native, in the daemon/replayers)
//! verifies — see `docs/plans/2026-06-24-phase7-mingo-client-plan.md` §7.0.

#[path = "../../sbo-core/src/error.rs"]
pub mod error;

#[path = "../../sbo-core/src/crypto/mod.rs"]
pub mod crypto;

#[path = "../../sbo-core/src/message/mod.rs"]
pub mod message;

#[path = "../../sbo-core/src/wire/mod.rs"]
pub mod wire;

/// The Phase 7.4 serialization kit (pure Rust; natively unit-tested).
pub mod kit;

/// The Phase 7.4 `wasm_bindgen` layer over [`kit`] (JS-facing exports).
pub mod bindings;

#[cfg(test)]
mod spike_tests {
    use crate::crypto::{ContentHash, SigningKey};
    use crate::message::{Action, Id, Message, ObjectType, Path};

    /// Build a representative content write, sign it with the carved subset, and
    /// verify the signature — exercising build → canonical-bytes → sign → verify
    /// entirely through `sbo-wasm` (no `sbo-core`).
    #[test]
    fn build_sign_serialize_verify_roundtrip() {
        let key = SigningKey::generate();
        let payload = br#"{"body":"hello from the spike","created_at":1703001234}"#.to_vec();

        let placeholder = crate::crypto::Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/spaces/general/").unwrap(),
            id: Id::new("p1").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: placeholder,
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: Some(Id::new("alice@mingo.place").unwrap()),
            creator: None,
            content_encoding: None,
            content_schema: Some("post.v1".to_string()),
            policy_ref: None,
            related: None,
            hlc: Some("1703001234567.0".to_string()),
            prev: None,
            auth_cert: None,
            auth_evidence: None,
        };
        msg.sign(&key);

        // Wire round-trips, and the signature the subset produced verifies.
        let wire = crate::wire::serialize(&msg);
        assert!(!wire.is_empty(), "serialized wire is non-empty");
        let parsed = crate::wire::parse(&wire).expect("wire parses back");
        assert!(
            crate::message::verify_message(&parsed).is_ok(),
            "signature produced via sbo-wasm must verify via sbo-wasm"
        );
    }
}
