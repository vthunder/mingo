//! Test preset message generation

use crate::crypto::{SigningKey, ContentHash};
use crate::message::{Message, Action, ObjectType, Id, Path};
use crate::wire;

/// Generate genesis batch (sys identity + root policy concatenated)
/// Returns a single batch suitable for atomic DA submission
pub fn genesis(signing_key: &SigningKey) -> Vec<u8> {
    let public_key = signing_key.public_key();

    // 1. System identity claim
    let sys_payload = serde_json::json!({
        "public_key": public_key.to_string(),
        "display_name": "System"
    });
    let sys_bytes = serde_json::to_vec(&sys_payload).unwrap();
    let sys_hash = ContentHash::sha256(&sys_bytes);

    let mut sys_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("sys").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(sys_hash),
        payload: Some(sys_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.claim".to_string()),
        policy_ref: None,
        related: None,
    };
    sys_msg.sign(signing_key);

    // 2. Root policy
    let policy_payload = serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["update", "delete"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["*"], "on": "/$owner/**"}
        ]
    });
    let policy_bytes = serde_json::to_vec(&policy_payload).unwrap();
    let policy_hash = ContentHash::sha256(&policy_bytes);

    let mut policy_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(policy_hash),
        payload: Some(policy_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("policy.v2".to_string()),
        policy_ref: None,
        related: None,
    };
    policy_msg.sign(signing_key);

    // Concatenate messages directly for atomic batch submission
    let mut batch = wire::serialize(&sys_msg);
    batch.extend(wire::serialize(&policy_msg));
    batch
}

/// Generate a simple post message
pub fn post(signing_key: &SigningKey, path: &str, id: &str, payload: &[u8]) -> Vec<u8> {
    let public_key = signing_key.public_key();
    let content_hash = ContentHash::sha256(payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
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
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Claim a name at /sys/names/<name>
/// This should succeed with root policy's {"to": "*", "can": ["create"], "on": "/sys/names/*"}
pub fn claim_name(signing_key: &SigningKey, name: &str) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let payload = serde_json::json!({
        "public_key": public_key.to_string(),
        "display_name": name
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let content_hash = ContentHash::sha256(&payload_bytes);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.claim".to_string()),
        policy_ref: None,
        related: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Post to own namespace after claiming a name
/// Path format: /<name>/...
/// This should succeed with root policy's {"to": "owner", "can": ["*"], "on": "/$owner/**"}
pub fn post_to_own_namespace(signing_key: &SigningKey, name: &str, subpath: &str, id: &str, payload: &[u8]) -> Vec<u8> {
    let public_key = signing_key.public_key();
    let content_hash = ContentHash::sha256(payload);

    // Build path: /<name>/<subpath>/
    let path_str = format!("/{}/{}/", name, subpath.trim_matches('/'));

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(&path_str).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
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
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Post to another user's namespace (should be DENIED by policy)
/// This tests that unauthorized access is blocked
pub fn post_unauthorized(signing_key: &SigningKey, target_namespace: &str, id: &str, payload: &[u8]) -> Vec<u8> {
    let public_key = signing_key.public_key();
    let content_hash = ContentHash::sha256(payload);

    // Try to write to someone else's namespace
    let path_str = format!("/{}/nfts/", target_namespace);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(&path_str).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
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
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Post a policy with restrictions (max_size, content_type)
pub fn policy_with_restrictions(signing_key: &SigningKey, target_path: &str, max_size: usize) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let policy_payload = serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create", "update"], "on": format!("{}**", target_path)}
        ],
        "restrictions": [
            {
                "on": format!("{}**", target_path),
                "require": {
                    "max_size": max_size,
                    "content_type": "application/json"
                }
            }
        ]
    });
    let policy_bytes = serde_json::to_vec(&policy_payload).unwrap();
    let policy_hash = ContentHash::sha256(&policy_bytes);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(target_path).unwrap(),
        id: Id::new("_policy").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(policy_hash),
        payload: Some(policy_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("policy.v2".to_string()),
        policy_ref: None,
        related: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}
