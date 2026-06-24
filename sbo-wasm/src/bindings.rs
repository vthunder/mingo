//! Phase 7.4 — the `wasm_bindgen` layer over [`crate::kit`].
//!
//! Thin JS-facing wrappers: they (de)serialize across the boundary and delegate
//! to the pure, natively-tested kit. `Uint8Array` ⇄ `Vec<u8>`; envelope specs
//! cross as a plain JS object via serde-wasm-bindgen. No private key ever enters
//! this layer — the browser obtains `signing_bytes`, has the browserid agent
//! sign them, then calls `assemble_wire` with the detached signature.

use wasm_bindgen::prelude::*;

use crate::kit::{self, EnvelopeSpec};

fn spec_from_js(opts: JsValue) -> Result<EnvelopeSpec, JsError> {
    serde_wasm_bindgen::from_value(opts).map_err(|e| JsError::new(&e.to_string()))
}

fn kit_err(e: kit::KitError) -> JsError {
    JsError::new(&e.to_string())
}

/// `signingBytes(spec)` → the bytes the browserid agent must sign.
#[wasm_bindgen(js_name = signingBytes)]
pub fn signing_bytes(opts: JsValue) -> Result<Vec<u8>, JsError> {
    kit::signing_bytes(&spec_from_js(opts)?).map_err(kit_err)
}

/// `assembleWire(spec, signatureHex)` → canonical wire bytes for `/v1/submit`.
#[wasm_bindgen(js_name = assembleWire)]
pub fn assemble_wire(opts: JsValue, signature_hex: &str) -> Result<Vec<u8>, JsError> {
    kit::assemble_wire(&spec_from_js(opts)?, signature_hex).map_err(kit_err)
}

/// `objectHash(wire)` → SHA-256 of the assembled wire (the content `object_hash`).
#[wasm_bindgen(js_name = objectHash)]
pub fn object_hash(wire: &[u8]) -> Vec<u8> {
    kit::object_hash(wire).to_vec()
}

/// `payloadPost(body, parent?, createdAt?)` → `post.v1` JSON bytes.
#[wasm_bindgen(js_name = payloadPost)]
pub fn payload_post(body: &str, parent: Option<String>, created_at: Option<i64>) -> Result<Vec<u8>, JsError> {
    kit::payloads::post(body, parent.as_deref(), created_at).map_err(kit_err)
}

/// `payloadComment(body, parent, createdAt?)` → `comment.v1` JSON bytes.
#[wasm_bindgen(js_name = payloadComment)]
pub fn payload_comment(body: &str, parent: &str, created_at: Option<i64>) -> Result<Vec<u8>, JsError> {
    kit::payloads::comment(body, parent, created_at).map_err(kit_err)
}

/// `payloadReaction(target, kind, state)` → `reaction.v1` JSON bytes.
#[wasm_bindgen(js_name = payloadReaction)]
pub fn payload_reaction(target: &str, kind: &str, state: bool) -> Result<Vec<u8>, JsError> {
    kit::payloads::reaction(target, kind, state).map_err(kit_err)
}

/// `payloadMembership(subject, issuer, issuedAt, expires?)` → `attestation.v1`
/// JSON bytes for a self-issued membership.
#[wasm_bindgen(js_name = payloadMembership)]
pub fn payload_membership(subject: &str, issuer: &str, issued_at: i64, expires: Option<i64>) -> Result<Vec<u8>, JsError> {
    kit::payloads::membership(subject, issuer, issued_at, expires).map_err(kit_err)
}
