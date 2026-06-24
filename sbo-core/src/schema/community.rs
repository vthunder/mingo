//! `community.v1` schema — a thin descriptor naming a self-owned community's
//! authoritative issuer and pointing at its policy and namespace (see the SBO
//! Community Specification).
//!
//! The descriptor **carries no logic**: membership, roles, and bans are
//! [attestations](super::attestation) and access control is
//! [policy](crate::policy) — a community adds almost no new machinery. This
//! module validates only field presence and types; it does **not** check that
//! the `issuer` or `policy` objects exist (those resolve at read time), and the
//! storage location (`/sys/community` repo-per-community, or `/communities/<id>`
//! aggregated) is a convention, not a validity rule. Authorization of a
//! `community.v1` write is the existing L2 gate (the writer must speak for the
//! `Owner`, conventionally `sys`); no new auth code lives here.

use serde::Deserialize;

use super::{SchemaError, SchemaResult};
use crate::message::Message;

/// Default path prefix under which membership is recorded.
pub const DEFAULT_MEMBERS_PREFIX: &str = "/members/";
/// Default path prefix for spaces (channels, subforums).
pub const DEFAULT_SPACES_PREFIX: &str = "/spaces/";

/// A parsed `community.v1` payload (Community Spec §The `community.v1` Object).
#[derive(Debug, Clone, Deserialize)]
pub struct Community {
    /// Human-readable community name.
    pub name: String,
    /// The **authoritative issuer**: the identity whose `membership`/`role:*`/
    /// `ban` attestations this community treats as canonical.
    pub issuer: String,
    /// Path or URI to the community's root policy.
    pub policy: String,
    /// Short description.
    #[serde(default)]
    pub description: Option<String>,
    /// Path prefix under which membership is recorded (default `/members/`).
    #[serde(default)]
    pub members: Option<String>,
    /// Path prefix for spaces (default `/spaces/`).
    #[serde(default)]
    pub spaces: Option<String>,
    /// Advisory hint that membership is self-service; the **actual** gate is the
    /// policy, not this flag.
    #[serde(default)]
    pub open: Option<bool>,
    /// Unix seconds the community was created.
    #[serde(default)]
    pub created_at: Option<i64>,
}

impl Community {
    /// The effective members path prefix, applying the `/members/` default.
    pub fn members_prefix(&self) -> &str {
        self.members.as_deref().unwrap_or(DEFAULT_MEMBERS_PREFIX)
    }

    /// The effective spaces path prefix, applying the `/spaces/` default.
    pub fn spaces_prefix(&self) -> &str {
        self.spaces.as_deref().unwrap_or(DEFAULT_SPACES_PREFIX)
    }
}

/// Parse a `community.v1` payload into a [`Community`].
pub fn parse_community(payload: &[u8]) -> SchemaResult<Community> {
    Ok(serde_json::from_slice(payload)?)
}

/// Validate a `community.v1` message's payload (Community Spec §Payload). Checks
/// field presence and types only — the required string fields are enforced by
/// deserialization (a missing one yields a deserialize error); here we reject
/// empty required strings. The descriptor's pointers (`issuer`, `policy`) are
/// **not** dereferenced — they resolve at read time.
pub fn validate_community(msg: &Message) -> SchemaResult<()> {
    let payload = msg.payload.as_ref().ok_or(SchemaError::EmptyPayload)?;
    let community = parse_community(payload)?;

    for (field, value) in [
        ("name", &community.name),
        ("issuer", &community.issuer),
        ("policy", &community.policy),
    ] {
        if value.is_empty() {
            return Err(SchemaError::MissingField(field.into()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_descriptor() {
        let payload = br#"{
            "name": "Cooks",
            "description": "A community for home cooks.",
            "issuer": "cooks@example.org",
            "policy": "/sys/policies/root",
            "members": "/members/",
            "spaces": "/spaces/",
            "open": true,
            "created_at": 1703001234
        }"#;
        let c = parse_community(payload).unwrap();
        assert_eq!(c.name, "Cooks");
        assert_eq!(c.issuer, "cooks@example.org");
        assert_eq!(c.policy, "/sys/policies/root");
        assert_eq!(c.open, Some(true));
        assert_eq!(c.created_at, Some(1703001234));
    }

    #[test]
    fn defaults_apply_when_paths_omitted() {
        let payload = br#"{"name":"Cooks","issuer":"cooks@example.org","policy":"/sys/policies/root"}"#;
        let c = parse_community(payload).unwrap();
        assert_eq!(c.members_prefix(), "/members/");
        assert_eq!(c.spaces_prefix(), "/spaces/");
        assert_eq!(c.open, None);
    }

    #[test]
    fn parse_rejects_missing_required_fields() {
        // missing policy
        let payload = br#"{"name":"Cooks","issuer":"cooks@example.org"}"#;
        assert!(parse_community(payload).is_err());
    }

    #[test]
    fn parse_rejects_wrong_types() {
        // open must be a boolean, not a string
        let payload = br#"{"name":"Cooks","issuer":"x","policy":"/p","open":"yes"}"#;
        assert!(parse_community(payload).is_err());
    }
}
