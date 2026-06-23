//! `attestation.v1` schema — a signed on-chain claim by an issuer about a
//! subject (see the SBO Attestation Specification).
//!
//! The **issuer is the `Owner` header**, authorized at the L2 attribution
//! layer like any other write; this module validates only the envelope-level
//! schema fields (Validation rules 2–5). Storage location (`/<issuer>/
//! attestations/<subject>/<type>`) is a convention, not a validity rule, so it
//! is not enforced here. The [`Attestation::is_in_force`] helper (effective and
//! unexpired at a reference time) is consumed by policy evaluation.

use serde::Deserialize;

use super::{SchemaError, SchemaResult};
use crate::message::Message;

/// A parsed `attestation.v1` payload.
#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    /// Identity reference the claim is about (email, name, or cross-repo ref).
    pub subject: String,
    /// Namespaced claim type, e.g. `membership`, `role:moderator`, `vouch`.
    #[serde(rename = "type")]
    pub type_: String,
    /// Claim content; opaque to validators (off-chain convention per `type`).
    pub value: serde_json::Value,
    /// Unix seconds when the issuer asserts the claim takes effect.
    pub issued_at: i64,
    /// Unix seconds after which the claim is stale. Absent = no self-expiry.
    #[serde(default)]
    pub expires: Option<i64>,
    /// Advisory pointer to supporting material; not protocol-verified.
    #[serde(default)]
    pub evidence: Option<String>,
    /// Advisory issuer field; if present MUST equal the `Owner` header.
    #[serde(default)]
    pub issuer: Option<String>,
}

impl Attestation {
    /// Whether the attestation is **in force** at reference time `t`: effective
    /// (`issued_at ≤ t`) and not expired (`t < expires`, when `expires` is set).
    /// An attestation with no `expires` never self-expires. This is the
    /// freshness predicate policy evaluation uses to resolve attestation-defined
    /// roles at the message's inclusion time.
    pub fn is_in_force(&self, t: i64) -> bool {
        self.issued_at <= t && self.expires.map_or(true, |exp| t < exp)
    }
}

/// Parse an `attestation.v1` payload into an [`Attestation`].
pub fn parse_attestation(payload: &[u8]) -> SchemaResult<Attestation> {
    Ok(serde_json::from_slice(payload)?)
}

/// The conventional storage **path** for an attestation in the issuer's
/// namespace: `/<issuer>/attestations/<subject>/` (the object's `ID` is the
/// `<type>`). Storing under the issuer — not the subject — is what stops a
/// subject from deleting unfavorable claims about themselves (Attestation Spec
/// §Storage). The `(issuer, subject, type)` triple is the attestation's primary
/// key, so re-issuing supersedes by last-writer-wins.
pub fn storage_path(issuer: &str, subject: &str) -> String {
    format!("/{issuer}/attestations/{subject}/")
}

/// Validate an `attestation.v1` message's payload (Attestation Spec §Validation,
/// rules 2–5). Authorization for `Owner` (the issuer) is enforced separately at
/// the attribution layer.
pub fn validate_attestation(msg: &Message) -> SchemaResult<()> {
    let payload = msg.payload.as_ref().ok_or(SchemaError::EmptyPayload)?;
    // Rule 3 (presence of subject/type/value/issued_at) is enforced by the
    // required fields here; a missing one yields a deserialize error.
    let att = parse_attestation(payload)?;

    if att.subject.is_empty() {
        return Err(SchemaError::MissingField("subject".into()));
    }

    // Rule 3: type matches [a-z0-9]+(:[a-z0-9-]+)* (lowercase, ':'-separated).
    if !valid_type(&att.type_) {
        return Err(SchemaError::InvalidField {
            field: "type".into(),
            reason: format!(
                "'{}' must match [a-z0-9]+(:[a-z0-9-]+)* (lowercase, ':'-separated, no '/' or whitespace)",
                att.type_
            ),
        });
    }

    // Rule 5: if expires is present it must be a number >= issued_at.
    if let Some(exp) = att.expires {
        if exp < att.issued_at {
            return Err(SchemaError::InvalidField {
                field: "expires".into(),
                reason: format!("expires ({}) must be >= issued_at ({})", exp, att.issued_at),
            });
        }
    }

    // Rule 4: a payload issuer field, if present, equals the Owner header.
    if let Some(issuer) = &att.issuer {
        let owner = msg.owner.as_ref().map(|o| o.as_str());
        if owner != Some(issuer.as_str()) {
            return Err(SchemaError::InvalidField {
                field: "issuer".into(),
                reason: format!(
                    "payload issuer '{}' must equal Owner {}",
                    issuer,
                    owner.unwrap_or("(absent)")
                ),
            });
        }
    }

    Ok(())
}

/// `[a-z0-9]+(:[a-z0-9-]+)*` — the first segment is lowercase alphanumeric; each
/// subsequent `:`-separated segment may also contain `-`. No empty segments,
/// `/`, or whitespace.
fn valid_type(type_: &str) -> bool {
    let mut segments = type_.split(':');
    match segments.next() {
        Some(first)
            if !first.is_empty()
                && first
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) => {}
        _ => return false,
    }
    segments.all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_regex_accepts_valid_forms() {
        for t in ["membership", "role:moderator", "badge:early-adopter", "credential:kyc", "a1:b2-c3"] {
            assert!(valid_type(t), "{t} should be valid");
        }
    }

    #[test]
    fn type_regex_rejects_invalid_forms() {
        for t in ["", "Role", "role:", ":x", "role/moderator", "role moderator", "role::x"] {
            assert!(!valid_type(t), "{t} should be invalid");
        }
        // The spec regex's later segments are [a-z0-9-]+, so a hyphen-only
        // segment like "badge:-" technically matches — we mirror the spec.
        assert!(valid_type("badge:-"));
    }

    #[test]
    fn in_force_window() {
        let att = Attestation {
            subject: "alice".into(),
            type_: "role:moderator".into(),
            value: serde_json::json!(true),
            issued_at: 100,
            expires: Some(200),
            evidence: None,
            issuer: None,
        };
        assert!(!att.is_in_force(99), "before issued_at: not yet effective");
        assert!(att.is_in_force(100), "at issued_at: effective");
        assert!(att.is_in_force(199), "within window");
        assert!(!att.is_in_force(200), "at expires: no longer in force (half-open)");
        assert!(!att.is_in_force(201), "after expires");
    }

    #[test]
    fn in_force_without_expires_never_self_expires() {
        let att = Attestation {
            subject: "alice".into(),
            type_: "badge:founder".into(),
            value: serde_json::json!(true),
            issued_at: 100,
            expires: None,
            evidence: None,
            issuer: None,
        };
        assert!(!att.is_in_force(99));
        assert!(att.is_in_force(100));
        assert!(att.is_in_force(i64::MAX));
    }

    #[test]
    fn storage_path_uses_issuer_namespace() {
        assert_eq!(
            storage_path("moderators@community.org", "alice"),
            "/moderators@community.org/attestations/alice/"
        );
    }

    #[test]
    fn parse_rejects_missing_required_fields() {
        // missing issued_at
        let payload = br#"{"subject":"alice","type":"vouch","value":true}"#;
        assert!(parse_attestation(payload).is_err());
    }
}
