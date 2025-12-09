use sbo_core::crypto::SigningKey;
use sbo_core::message::{Message, Action, ObjectType, Id, Path};

#[test]
fn test_sign_and_verify_message() {
    let signing_key = SigningKey::generate();
    let public_key = signing_key.public_key();

    let payload = b"{\"test\":true}";
    let content_hash = sbo_core::crypto::ContentHash::sha256(payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: sbo_core::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
    };

    // Sign the message
    msg.sign(&signing_key);

    // Verify should pass
    assert!(sbo_core::message::verify_message(&msg).is_ok());
}

#[test]
fn test_verify_fails_with_wrong_key() {
    let signing_key = SigningKey::generate();
    let wrong_key = SigningKey::generate();

    let payload = b"{\"test\":true}";
    let content_hash = sbo_core::crypto::ContentHash::sha256(payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        object_type: ObjectType::Object,
        signing_key: wrong_key.public_key(), // Wrong key!
        signature: sbo_core::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
    };

    msg.sign(&signing_key);

    // Verify should fail - signed with different key than signing_key field
    assert!(sbo_core::message::verify_message(&msg).is_err());
}
