//! Schema validation for SBO objects
//!
//! Validates JSON payloads against Content-Schema specifications.
//!
//! Supported schemas:
//! - `identity.v1` - User identity objects

mod identity;

use crate::message::Message;
use thiserror::Error;

pub use identity::{Identity, validate_identity};

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

    #[error("Key mismatch: signing_key in payload ({payload_key}) does not match Signing-Key header ({header_key})")]
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
            let identity = identity::parse_identity(payload)?;
            identity::validate_identity_fields(&identity)?;
            identity::validate_identity_key_match(&identity, &msg.signing_key)?;
            Ok(())
        }
        "domain.v1" => {
            // Domain identity schema - similar to identity.v1
            let identity = identity::parse_identity(payload)?;
            identity::validate_identity_fields(&identity)?;
            identity::validate_identity_key_match(&identity, &msg.signing_key)?;
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
    fn test_identity_schema_valid() {
        use crate::crypto::SigningKey;

        // Generate a key and create identity with matching signing_key
        let key = SigningKey::generate();
        let key_str = key.public_key().to_string();
        let payload = format!(r#"{{"signing_key":"{}","display_name":"Alice"}}"#, key_str);

        // Need to create message with the same key
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{ContentHash, Signature};

        let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/alice/").unwrap(),
            id: Id::new("identity").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: placeholder_sig,
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(payload.as_bytes())),
            payload: Some(payload.into_bytes()),
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
    fn test_identity_schema_key_mismatch() {
        use crate::crypto::SigningKey;
        use crate::message::{Message, Action, ObjectType, Id, Path};
        use crate::crypto::{ContentHash, Signature};

        // Generate two different keys
        let signing_key = SigningKey::generate();
        let other_key = SigningKey::generate();

        // Create identity with a DIFFERENT key than what signs the message
        let other_key_str = other_key.public_key().to_string();
        let payload = format!(r#"{{"signing_key":"{}"}}"#, other_key_str);

        let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/alice/").unwrap(),
            id: Id::new("identity").unwrap(),
            object_type: ObjectType::Object,
            signing_key: signing_key.public_key(), // Signs with this key
            signature: placeholder_sig,
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(payload.as_bytes())),
            payload: Some(payload.into_bytes()),
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
}
