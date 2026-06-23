//! Test preset message generation

use crate::crypto::{SigningKey, ContentHash};
use crate::message::{Message, Action, ObjectType, Id, Path};
use crate::wire;

/// Generate genesis batch (sys identity + root policy concatenated)
/// Returns a single batch suitable for atomic DA submission
///
/// This creates a Mode A (self-signed sys) genesis per the Genesis Specification.
pub fn genesis(signing_key: &SigningKey) -> Vec<u8> {
    let public_key = signing_key.public_key();

    // 1. System identity (JWT, self-signed)
    let sys_jwt = crate::jwt::create_self_signed_identity(signing_key, "sys", None)
        .expect("JWT creation should not fail");
    let sys_bytes = sys_jwt.as_bytes().to_vec();
    let sys_hash = ContentHash::sha256(&sys_bytes);

    let mut sys_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("sys").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(sys_hash),
        payload: Some(sys_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    sys_msg.sign(signing_key);

    // 2. Root policy (unchanged - still JSON)
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    policy_msg.sign(signing_key);

    // Concatenate messages directly for atomic batch submission
    let mut batch = wire::serialize(&sys_msg);
    batch.extend(wire::serialize(&policy_msg));
    batch
}

/// Generate Mode B genesis (domain-certified sys)
///
/// Creates: domain object, domain-certified sys identity, root policy
/// The domain is established first, then sys is certified by that domain.
pub fn genesis_with_domain(
    domain_signing_key: &SigningKey,
    sys_signing_key: &SigningKey,
    domain_name: &str,
) -> Vec<u8> {
    let domain_public_key = domain_signing_key.public_key();
    let sys_public_key = sys_signing_key.public_key();

    // 1. Domain object (JWT, self-signed by domain key)
    let domain_jwt = crate::jwt::create_domain(domain_signing_key, domain_name)
        .expect("JWT creation should not fail");
    let domain_bytes = domain_jwt.as_bytes().to_vec();
    let domain_hash = ContentHash::sha256(&domain_bytes);

    let mut domain_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/domains/").unwrap(),
        id: Id::new(domain_name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: domain_public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(domain_hash),
        payload: Some(domain_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("domain.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    domain_msg.sign(domain_signing_key);

    // 2. System identity (JWT, domain-certified)
    let sys_email = format!("sys@{}", domain_name);
    let sys_jwt = crate::jwt::create_domain_certified_identity(
        domain_signing_key,
        domain_name,
        &sys_email,
        &sys_public_key,
        None,
    )
    .expect("JWT creation should not fail");
    let sys_bytes = sys_jwt.as_bytes().to_vec();
    let sys_hash = ContentHash::sha256(&sys_bytes);

    let mut sys_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("sys").unwrap(),
        object_type: ObjectType::Object,
        signing_key: sys_public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(sys_hash),
        payload: Some(sys_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    sys_msg.sign(sys_signing_key);

    // 3. Root policy
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
        signing_key: sys_public_key.clone(),
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    policy_msg.sign(sys_signing_key);

    // Concatenate in order: domain, sys, policy
    let mut batch = wire::serialize(&domain_msg);
    batch.extend(wire::serialize(&sys_msg));
    batch.extend(wire::serialize(&policy_msg));
    batch
}

/// Generate Mode B genesis with domain-signing restriction
///
/// Like genesis_with_domain, but the root policy requires all identities
/// in /sys/names/* to have payloads signed by a domain object in /sys/domains/*.
///
/// Creates: domain object, domain-certified sys identity, root policy with restriction
pub fn genesis_with_domain_and_restriction(
    domain_signing_key: &SigningKey,
    sys_signing_key: &SigningKey,
    domain_name: &str,
) -> Vec<u8> {
    let domain_public_key = domain_signing_key.public_key();
    let sys_public_key = sys_signing_key.public_key();

    // 1. Domain object (JWT, self-signed by domain key)
    let domain_jwt = crate::jwt::create_domain(domain_signing_key, domain_name)
        .expect("JWT creation should not fail");
    let domain_bytes = domain_jwt.as_bytes().to_vec();
    let domain_hash = ContentHash::sha256(&domain_bytes);

    let mut domain_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/domains/").unwrap(),
        id: Id::new(domain_name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: domain_public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(domain_hash),
        payload: Some(domain_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("domain.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    domain_msg.sign(domain_signing_key);

    // 2. System identity (JWT, domain-certified)
    let sys_email = format!("sys@{}", domain_name);
    let sys_jwt = crate::jwt::create_domain_certified_identity(
        domain_signing_key,
        domain_name,
        &sys_email,
        &sys_public_key,
        None,
    )
    .expect("JWT creation should not fail");
    let sys_bytes = sys_jwt.as_bytes().to_vec();
    let sys_hash = ContentHash::sha256(&sys_bytes);

    let mut sys_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("sys").unwrap(),
        object_type: ObjectType::Object,
        signing_key: sys_public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(sys_hash),
        payload: Some(sys_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    sys_msg.sign(sys_signing_key);

    // 3. Root policy with domain-signing restriction
    let policy_payload = serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["update", "delete"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["*"], "on": "/$owner/**"}
        ],
        "restrictions": [
            {
                "on": "/sys/names/*",
                "require": {
                    "schema": "identity.v1",
                    "require_payload_signed_by": { "path": "/sys/domains/*" }
                }
            }
        ]
    });
    let policy_bytes = serde_json::to_vec(&policy_payload).unwrap();
    let policy_hash = ContentHash::sha256(&policy_bytes);

    let mut policy_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        object_type: ObjectType::Object,
        signing_key: sys_public_key.clone(),
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    policy_msg.sign(sys_signing_key);

    // Concatenate in order: domain, sys, policy
    let mut batch = wire::serialize(&domain_msg);
    batch.extend(wire::serialize(&sys_msg));
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Claim a name at /sys/names/<name> (self-signed identity)
/// This should succeed with root policy's {"to": "*", "can": ["create"], "on": "/sys/names/*"}
pub fn claim_name(signing_key: &SigningKey, name: &str) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let jwt = crate::jwt::create_self_signed_identity(signing_key, name, None)
        .expect("JWT creation should not fail");
    let payload_bytes = jwt.as_bytes().to_vec();
    let content_hash = ContentHash::sha256(&payload_bytes);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Claim a name with a profile link
pub fn claim_name_with_profile(signing_key: &SigningKey, name: &str, profile_path: &str) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let jwt = crate::jwt::create_self_signed_identity(signing_key, name, Some(profile_path))
        .expect("JWT creation should not fail");
    let payload_bytes = jwt.as_bytes().to_vec();
    let content_hash = ContentHash::sha256(&payload_bytes);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Claim an email-rooted identity (`identity.email.v1`) at
/// `/sys/names/<name>`, carrying browserid + DNSSEC attribution.
///
/// Unlike key-rooted [`claim_name`], the controller is the `Owner` header (the
/// email); the signing key is ephemeral and speaks for the email only via the
/// attached `Auth-Cert` / `Auth-Evidence` (verified at L2 against the write's
/// inclusion time). `name` is the local name to register; `email` is the
/// controller; `iat` is the issued-at timestamp (UNIX seconds).
pub fn claim_email_identity(
    signing_key: &SigningKey,
    name: &str,
    email: &str,
    auth_cert: &str,
    auth_evidence: &str,
    iat: i64,
) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let payload_bytes = serde_json::to_vec(&serde_json::json!({ "iat": iat }))
        .expect("identity.email.v1 payload serialization should not fail");
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
        owner: Some(Id::new(email).expect("email is a valid Owner Id")),
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.email.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: Some(auth_cert.to_string()),
        auth_evidence: Some(auth_evidence.to_string()),
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Create a domain object at /sys/domains/<domain_name>
///
/// Domains are self-signed authority objects that can certify identities.
/// The domain JWT contains: iss ("self"), sub (domain name), public_key, iat.
pub fn create_domain(signing_key: &SigningKey, domain_name: &str) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let jwt = crate::jwt::create_domain(signing_key, domain_name)
        .expect("JWT creation should not fail");
    let payload_bytes = jwt.as_bytes().to_vec();
    let content_hash = ContentHash::sha256(&payload_bytes);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/domains/").unwrap(),
        id: Id::new(domain_name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("domain.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
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
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    #[test]
    fn claim_email_identity_roundtrips() {
        let key = SigningKey::generate();
        let wire = claim_email_identity(
            &key,
            "alice",
            "alice@example.com",
            "CERT.JWT.SIG",
            "inline:AAAA",
            1_700_000_000,
        );
        let msg = wire::parse(&wire).expect("serialized message should parse");
        assert_eq!(msg.path.to_string(), "/sys/names/");
        assert_eq!(msg.id.as_str(), "alice");
        assert_eq!(msg.content_schema.as_deref(), Some("identity.email.v1"));
        assert_eq!(msg.owner.as_ref().map(|o| o.as_str()), Some("alice@example.com"));
        assert_eq!(msg.auth_cert.as_deref(), Some("CERT.JWT.SIG"));
        assert_eq!(msg.auth_evidence.as_deref(), Some("inline:AAAA"));
        // Signature must verify, and the schema arm must accept the payload.
        crate::message::verify_message(&msg).expect("signature should verify");
        crate::schema::validate_schema(&msg).expect("identity.email.v1 payload should validate");
    }
}
