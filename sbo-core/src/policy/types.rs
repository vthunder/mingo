//! Policy types

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::path::PathPattern;

/// Policy document (policy.v2 schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub roles: HashMap<String, Vec<Identity>>,

    #[serde(default)]
    pub deny: Vec<PathPattern>,

    #[serde(default)]
    pub grants: Vec<Grant>,

    #[serde(default)]
    pub restrictions: Vec<Restriction>,
}

/// Grant: who can do what on which paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub to: Identity,
    pub can: Vec<ActionType>,
    pub on: PathPattern,
}

/// Restriction: conditions on allowed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restriction {
    pub on: PathPattern,
    pub require: Requirements,
}

/// Identity reference in grants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Identity {
    /// Special values: "owner", "*", or a name
    Name(String),
    /// Public key reference
    Key { key: String },
    /// Role reference
    Role { role: String },
    /// Any of these identities
    Any { any: Vec<Identity> },
}

/// Action types for grants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    Create,
    Update,
    Post,
    Delete,
    Transfer,
    Import,
    #[serde(rename = "*")]
    All,
}

/// Requirements for restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirements {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaRequirement>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Require the payload to be signed by an object at the specified path pattern
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_payload_signed_by: Option<RequirePayloadSignedBy>,
}

/// Requirement that an object's payload (JWT) must be signed by another object
///
/// The payload's JWT issuer (e.g., "domain:example.com") is mapped to an object path
/// (e.g., "/sys/domains/example.com"), and the signature is verified against that object's
/// public key. The issuer path must match the specified pattern.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequirePayloadSignedBy {
    /// Path pattern where the signing object must exist
    /// e.g., "/sys/domains/*" means the issuer must be a domain object
    pub path: String,
}

/// Schema requirement (single or multiple allowed)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaRequirement {
    Single(String),
    Any { any: Vec<String> },
}
