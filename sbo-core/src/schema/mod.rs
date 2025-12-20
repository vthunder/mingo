//! Schema validation for SBO objects
//!
//! Validates payloads against Content-Schema specifications.
//!
//! Supported schemas:
//! - `identity.v1` - User identity objects (JWT format)
//! - `domain.v1` - Domain objects (JWT format, always self-signed)
//! - `profile.v1` - Profile data (JSON format)

mod identity;

use crate::message::Message;
use thiserror::Error;

pub use identity::{Identity, validate_identity, parse_identity};
pub use crate::jwt::{Profile, IdentityClaims, DomainClaims};

/// Schema validation errors
#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("Unknown schema: {0}")]
    UnknownSchema(String),

    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field value: {field}: {reason}")]
    InvalidField {
        field: String,
        reason: String,
    },

    #[error("Key mismatch: public_key in payload ({payload_key}) does not match Public-Key header ({header_key})")]
    KeyMismatch {
        payload_key: String,
        header_key: String,
    },

    #[error("Payload is empty")]
    EmptyPayload,
}

/// Result type for schema validation
pub type SchemaResult<T> = Result<T, SchemaError>;

/// Validate a message's payload against its Content-Schema
///
/// Returns Ok(()) if:
/// - No Content-Schema is specified (no validation required)
/// - Content-Schema is unknown (let higher layers enforce)
/// - Content-Schema is known and payload validates
///
/// Returns Err only if:
/// - A known schema is specified and validation fails
///
/// Note: Unknown schemas pass through - schema enforcement can be done
/// at higher layers (e.g., application-specific validators).
pub fn validate_schema(msg: &Message) -> SchemaResult<()> {
    let schema = match &msg.content_schema {
        Some(s) => s.as_str(),
        None => return Ok(()), // No schema, no validation
    };

    let payload = msg.payload.as_ref()
        .ok_or(SchemaError::EmptyPayload)?;

    match schema {
        "identity.v1" => {
            // JWT-based identity
            let token = std::str::from_utf8(payload)
                .map_err(|_| SchemaError::InvalidField {
                    field: "payload".into(),
                    reason: "JWT must be valid UTF-8".into(),
                })?;

            // Decode claims without verification first
            let claims = crate::jwt::decode_identity_claims(token)
                .map_err(|e| SchemaError::InvalidField {
                    field: "jwt".into(),
                    reason: e.to_string(),
                })?;

            // Verify public_key in JWT matches Public-Key header
            let header_key = msg.signing_key.to_string();
            if claims.public_key != header_key {
                return Err(SchemaError::KeyMismatch {
                    payload_key: claims.public_key,
                    header_key,
                });
            }

            // For self-signed, verify JWT signature matches public_key in payload
            if claims.iss == "self" {
                crate::jwt::verify_self_signed_identity(token)
                    .map_err(|e| SchemaError::InvalidField {
                        field: "signature".into(),
                        reason: e.to_string(),
                    })?;
            }
            // For domain-certified, caller must verify against domain key

            Ok(())
        }
        "domain.v1" => {
            // JWT-based domain (always self-signed)
            let token = std::str::from_utf8(payload)
                .map_err(|_| SchemaError::InvalidField {
                    field: "payload".into(),
                    reason: "JWT must be valid UTF-8".into(),
                })?;

            let claims = crate::jwt::verify_domain(token)
                .map_err(|e| SchemaError::InvalidField {
                    field: "jwt".into(),
                    reason: e.to_string(),
                })?;

            // Verify public_key matches header
            let header_key = msg.signing_key.to_string();
            if claims.public_key != header_key {
                return Err(SchemaError::KeyMismatch {
                    payload_key: claims.public_key,
                    header_key,
                });
            }

            Ok(())
        }
        "profile.v1" => {
            // Profile is plain JSON, not JWT
            let _profile: crate::jwt::Profile = serde_json::from_slice(payload)?;
            Ok(())
        }
        _ => {
            // Unknown schemas pass through - enforcement can happen at higher layers
            tracing::debug!("Unknown schema '{}', skipping validation", schema);
            Ok(())
        }
    }
}

/// Parse and validate an identity from raw payload bytes
pub fn parse_and_validate_identity(payload: &[u8], header_signing_key: &crate::crypto::PublicKey) -> SchemaResult<Identity> {
    let identity = identity::parse_identity(payload)?;
    identity::validate_identity_fields(&identity)?;
    identity::validate_identity_key_match(&identity, header_signing_key)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_message(schema: Option<&str>, payload: &[u8]) -> Message {
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{SigningKey, ContentHash, Signature};

        let key = SigningKey::generate();

        // Create a placeholder signature, will be replaced by sign()
        let placeholder_sig = Signature::parse(
            &"0".repeat(128)
        ).unwrap();

        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/test/").unwrap(),
            id: Id::new("test").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: placeholder_sig,
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(payload)),
            payload: Some(payload.to_vec()),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: schema.map(|s| s.to_string()),
            policy_ref: None,
            related: None,
        };
        msg.sign(&key);
        msg
    }

    #[test]
    fn test_no_schema_passes() {
        let msg = make_test_message(None, b"{}");
        assert!(validate_schema(&msg).is_ok());
    }

    #[test]
    fn test_unknown_schema_passes() {
        // Unknown schemas pass through - enforcement happens at higher layers
        let msg = make_test_message(Some("unknown.v99"), b"{}");
        assert!(validate_schema(&msg).is_ok());
    }

    #[test]
    fn test_identity_v1_jwt_valid() {
        use crate::crypto::SigningKey;
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{ContentHash, Signature};

        // Generate a key and create JWT identity
        let key = SigningKey::generate();
        let jwt = crate::jwt::create_self_signed_identity(&key, "alice", None).unwrap();
        let payload = jwt.as_bytes();

        let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/names/").unwrap(),
            id: Id::new("alice").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: placeholder_sig,
            content_type: Some("application/jwt".to_string()),
            content_hash: Some(ContentHash::sha256(payload)),
            payload: Some(payload.to_vec()),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("identity.v1".to_string()),
            policy_ref: None,
            related: None,
        };
        msg.sign(&key);

        assert!(validate_schema(&msg).is_ok());
    }

    #[test]
    fn test_identity_v1_jwt_key_mismatch() {
        use crate::crypto::SigningKey;
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{ContentHash, Signature};

        // Generate two different keys
        let signing_key = SigningKey::generate();
        let jwt_key = SigningKey::generate();

        // Create JWT with jwt_key but sign message with signing_key
        let jwt = crate::jwt::create_self_signed_identity(&jwt_key, "alice", None).unwrap();
        let payload = jwt.as_bytes();

        let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/names/").unwrap(),
            id: Id::new("alice").unwrap(),
            object_type: ObjectType::Object,
            signing_key: signing_key.public_key(), // Different key!
            signature: placeholder_sig,
            content_type: Some("application/jwt".to_string()),
            content_hash: Some(ContentHash::sha256(payload)),
            payload: Some(payload.to_vec()),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("identity.v1".to_string()),
            policy_ref: None,
            related: None,
        };
        msg.sign(&signing_key);

        let err = validate_schema(&msg).unwrap_err();
        assert!(matches!(err, SchemaError::KeyMismatch { .. }));
    }

    #[test]
    fn test_domain_v1_jwt_valid() {
        use crate::crypto::SigningKey;
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{ContentHash, Signature};

        let key = SigningKey::generate();
        let jwt = crate::jwt::create_domain(&key, "example.com").unwrap();
        let payload = jwt.as_bytes();

        let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/domains/").unwrap(),
            id: Id::new("example.com").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: placeholder_sig,
            content_type: Some("application/jwt".to_string()),
            content_hash: Some(ContentHash::sha256(payload)),
            payload: Some(payload.to_vec()),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("domain.v1".to_string()),
            policy_ref: None,
            related: None,
        };
        msg.sign(&key);

        assert!(validate_schema(&msg).is_ok());
    }

    #[test]
    fn test_profile_v1_json_valid() {
        use crate::crypto::SigningKey;
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{ContentHash, Signature};

        let key = SigningKey::generate();
        let profile = crate::jwt::Profile {
            display_name: Some("Alice".to_string()),
            bio: Some("Hello world".to_string()),
            ..Default::default()
        };
        let payload = serde_json::to_vec(&profile).unwrap();

        let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/alice/").unwrap(),
            id: Id::new("profile").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: placeholder_sig,
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("profile.v1".to_string()),
            policy_ref: None,
            related: None,
        };
        msg.sign(&key);

        assert!(validate_schema(&msg).is_ok());
    }

}
