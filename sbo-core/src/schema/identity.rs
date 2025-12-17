//! Identity schema validation (identity.v1)
//!
//! Schema for user identity objects per SBO Identity Specification v0.1.
//!
//! Required fields:
//! - `public_key`: Public key in `algorithm:hex` format (e.g., `ed25519:abc123...`)
//!
//! Optional fields:
//! - `display_name`: Human-readable name
//! - `description`: Text description
//! - `avatar`: Relative SBO path or absolute URL
//! - `links`: Key-value pairs of named links
//! - `binding`: SBO URI for cross-chain identity binding

use super::{SchemaError, SchemaResult};
use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identity object (identity.v1 schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Public key in algorithm:hex format (required)
    pub public_key: String,

    /// Human-readable display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Text description of the identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Avatar image path (relative SBO path or URL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,

    /// Named links (website, github, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,

    /// Cross-chain identity binding (SBO URI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

impl Identity {
    /// Create a new identity with just a public key
    pub fn new(public_key: String) -> Self {
        Self {
            public_key,
            display_name: None,
            description: None,
            avatar: None,
            links: None,
            binding: None,
        }
    }

    /// Create an identity with display name
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Create an identity with avatar
    pub fn with_avatar(mut self, avatar: impl Into<String>) -> Self {
        self.avatar = Some(avatar.into());
        self
    }

    /// Serialize to JSON bytes
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Serialize to pretty JSON string
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Parse identity from JSON bytes
pub fn parse_identity(payload: &[u8]) -> SchemaResult<Identity> {
    serde_json::from_slice(payload).map_err(SchemaError::from)
}

/// Validate identity fields
pub fn validate_identity_fields(identity: &Identity) -> SchemaResult<()> {
    // Validate public_key format
    validate_public_key_format(&identity.public_key)?;

    // Validate optional fields
    if let Some(ref name) = identity.display_name {
        if name.is_empty() {
            return Err(SchemaError::InvalidField {
                field: "display_name".to_string(),
                reason: "cannot be empty string".to_string(),
            });
        }
        if name.len() > 256 {
            return Err(SchemaError::InvalidField {
                field: "display_name".to_string(),
                reason: format!("too long ({} > 256 chars)", name.len()),
            });
        }
    }

    if let Some(ref desc) = identity.description {
        if desc.len() > 4096 {
            return Err(SchemaError::InvalidField {
                field: "description".to_string(),
                reason: format!("too long ({} > 4096 chars)", desc.len()),
            });
        }
    }

    if let Some(ref avatar) = identity.avatar {
        if avatar.is_empty() {
            return Err(SchemaError::InvalidField {
                field: "avatar".to_string(),
                reason: "cannot be empty string".to_string(),
            });
        }
        // Avatar must be a path (starts with /) or URL (starts with http)
        if !avatar.starts_with('/') && !avatar.starts_with("http://") && !avatar.starts_with("https://") {
            return Err(SchemaError::InvalidField {
                field: "avatar".to_string(),
                reason: "must be an SBO path (starts with /) or URL (starts with http)".to_string(),
            });
        }
    }

    if let Some(ref binding) = identity.binding {
        // Binding must be an SBO URI
        if !binding.starts_with("sbo://") && !binding.starts_with("sbo+raw://") {
            return Err(SchemaError::InvalidField {
                field: "binding".to_string(),
                reason: "must be an SBO URI (starts with sbo:// or sbo+raw://)".to_string(),
            });
        }
    }

    Ok(())
}

/// Validate that the public_key in the payload matches the Public-Key header
pub fn validate_identity_key_match(identity: &Identity, header_key: &PublicKey) -> SchemaResult<()> {
    let header_key_str = header_key.to_string();

    if identity.public_key != header_key_str {
        return Err(SchemaError::KeyMismatch {
            payload_key: identity.public_key.clone(),
            header_key: header_key_str,
        });
    }

    Ok(())
}

/// Validate public key format (algorithm:hex)
fn validate_public_key_format(key: &str) -> SchemaResult<()> {
    // Must have algorithm prefix
    let (algo, hex_part) = key.split_once(':')
        .ok_or_else(|| SchemaError::InvalidField {
            field: "public_key".to_string(),
            reason: "must be in algorithm:hex format (e.g., ed25519:abc123...)".to_string(),
        })?;

    // Validate algorithm
    match algo {
        "ed25519" => {
            // ed25519 public key is 32 bytes = 64 hex chars
            if hex_part.len() != 64 {
                return Err(SchemaError::InvalidField {
                    field: "public_key".to_string(),
                    reason: format!("ed25519 key must be 64 hex chars, got {}", hex_part.len()),
                });
            }
        }
        "bls12-381" => {
            // BLS public key is 48 bytes = 96 hex chars
            if hex_part.len() != 96 {
                return Err(SchemaError::InvalidField {
                    field: "public_key".to_string(),
                    reason: format!("bls12-381 key must be 96 hex chars, got {}", hex_part.len()),
                });
            }
        }
        _ => {
            return Err(SchemaError::InvalidField {
                field: "public_key".to_string(),
                reason: format!("unknown algorithm '{}', supported: ed25519, bls12-381", algo),
            });
        }
    }

    // Validate hex
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SchemaError::InvalidField {
            field: "public_key".to_string(),
            reason: "key material must be valid hex".to_string(),
        });
    }

    Ok(())
}

/// Convenience function to validate an identity message
pub fn validate_identity(identity: &Identity, header_key: &PublicKey) -> SchemaResult<()> {
    validate_identity_fields(identity)?;
    validate_identity_key_match(identity, header_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    #[test]
    fn test_parse_minimal_identity() {
        let json = r#"{"public_key":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;
        let identity = parse_identity(json.as_bytes()).unwrap();
        assert!(identity.display_name.is_none());
    }

    #[test]
    fn test_parse_full_identity() {
        let json = r#"{
            "public_key": "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "display_name": "Alice",
            "description": "Test identity",
            "avatar": "/alice/avatar.png",
            "links": {"website": "https://alice.example.com"},
            "binding": "sbo+raw://avail:mainnet:42/sys/names/alice"
        }"#;
        let identity = parse_identity(json.as_bytes()).unwrap();
        assert_eq!(identity.display_name, Some("Alice".to_string()));
        assert_eq!(identity.avatar, Some("/alice/avatar.png".to_string()));
    }

    #[test]
    fn test_validate_public_key_format() {
        // Valid ed25519
        assert!(validate_public_key_format(
            "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ).is_ok());

        // Missing algorithm
        assert!(validate_public_key_format("0123456789abcdef").is_err());

        // Wrong length
        assert!(validate_public_key_format("ed25519:0123").is_err());

        // Invalid hex
        assert!(validate_public_key_format("ed25519:gggg").is_err());
    }

    #[test]
    fn test_key_match_validation() {
        let key = SigningKey::generate();
        let public_key = key.public_key();
        let key_str = public_key.to_string();

        let identity = Identity::new(key_str.clone());
        assert!(validate_identity_key_match(&identity, &public_key).is_ok());

        // Wrong key
        let other_key = SigningKey::generate();
        let err = validate_identity_key_match(&identity, &other_key.public_key()).unwrap_err();
        assert!(matches!(err, SchemaError::KeyMismatch { .. }));
    }

    #[test]
    fn test_avatar_validation() {
        // Valid paths
        let mut id = Identity::new("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        id.avatar = Some("/alice/avatar.png".to_string());
        assert!(validate_identity_fields(&id).is_ok());

        // Valid URLs
        id.avatar = Some("https://example.com/avatar.png".to_string());
        assert!(validate_identity_fields(&id).is_ok());

        // Invalid - neither path nor URL
        id.avatar = Some("avatar.png".to_string());
        assert!(validate_identity_fields(&id).is_err());
    }

    #[test]
    fn test_binding_validation() {
        let mut id = Identity::new("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

        // Valid binding
        id.binding = Some("sbo+raw://avail:mainnet:42/sys/names/alice".to_string());
        assert!(validate_identity_fields(&id).is_ok());

        // Invalid - not SBO URI
        id.binding = Some("https://example.com".to_string());
        assert!(validate_identity_fields(&id).is_err());
    }

    #[test]
    fn test_identity_builder() {
        let id = Identity::new("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
            .with_display_name("Alice")
            .with_avatar("/alice/avatar.png");

        assert_eq!(id.display_name, Some("Alice".to_string()));
        assert_eq!(id.avatar, Some("/alice/avatar.png".to_string()));
    }

    #[test]
    fn test_identity_serialization() {
        let id = Identity::new("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
            .with_display_name("Alice");

        let json = id.to_json().unwrap();
        let parsed: Identity = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.public_key, id.public_key);
        assert_eq!(parsed.display_name, id.display_name);
    }
}
