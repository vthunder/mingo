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

/// Post the pinned authorized-broker list to `/sys/trust/brokers`.
///
/// This is the on-chain trust anchor consumed by the L2 attribution verifier:
/// a browserid certificate whose issuer differs from the email's domain is only
/// honored if the issuer is in this list. It MUST live on-chain (not in local
/// config) so every replayer converges on the same authorization decisions.
///
/// Seed it during genesis (genesis mode permits the write before the root
/// policy exists) or via an authorized key once policy governs `/sys/trust/`.
/// The payload is a JSON array of provider domains, e.g. `["id.sandmill.org"]`.
pub fn set_trust_brokers(signing_key: &SigningKey, brokers: &[&str]) -> Vec<u8> {
    let public_key = signing_key.public_key();

    let payload_bytes = serde_json::to_vec(&brokers).expect("broker list serialization");
    let content_hash = ContentHash::sha256(&payload_bytes);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/trust/").unwrap(),
        id: Id::new("brokers").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("trust.brokers.v1".to_string()),
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

/// Post an RFC 9102 DNSSEC proof of `_browserid.<domain>` to `/sys/dnssec/<domain>`.
///
/// This is the on-chain, self-authenticating evidence the L2 attribution verifier
/// consults when a write carries no inline `auth_evidence` (the conventional
/// fallback in `resolve_evidence`): to honor a browserid cert issued by `<domain>`,
/// the verifier needs `<domain>`'s `_browserid` provider key, proven via DNSSEC.
/// The payload IS the raw RFC 9102 proof chain (re-validated against the pinned
/// IANA root on every replay). The proof has an RRSIG validity window, so this
/// object must be refreshed before it expires.
///
/// Sign with an authority over `/sys/dnssec/` (the sys key at genesis, or an
/// authorized key once policy governs the path).
pub fn set_dnssec(signing_key: &SigningKey, domain: &str, proof: &[u8]) -> Vec<u8> {
    let public_key = signing_key.public_key();
    let content_hash = ContentHash::sha256(proof);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/dnssec/").unwrap(),
        id: Id::new(domain).expect("domain is a valid id"),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/octet-stream".to_string()),
        content_hash: Some(content_hash),
        payload: Some(proof.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("dnssec.v1".to_string()),
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

// ===========================================================================
// Phase 7.2 — Mingo message builders + aggregated genesis
//
// Thin wrappers that build the content/community schemas the Mingo demo writes
// (community.v1, collection.v1, attestation.v1, post/comment/reaction). They
// share the envelope scaffold via [`signed_object`] and emit canonical wire
// bytes, exactly like the builders above. None of these carry new protocol
// logic — they just shape payloads the existing schema validators accept.
// ===========================================================================

/// Build and sign a single content object, returning canonical wire bytes.
///
/// The common scaffold behind the Mingo builders: `Owner` is set when `owner`
/// is given (an email/name controller), `HLC`/`Prev` are stamped when provided
/// (content-layer ordering), and the payload's `Content-Hash` is computed here.
#[allow(clippy::too_many_arguments)]
fn signed_object(
    signing_key: &SigningKey,
    path: &str,
    id: &str,
    schema: &str,
    content_type: &str,
    payload: Vec<u8>,
    owner: Option<&str>,
    hlc: Option<&str>,
    prev: Option<&str>,
) -> Vec<u8> {
    let public_key = signing_key.public_key();
    let content_hash = ContentHash::sha256(&payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).expect("path should be well-formed"),
        id: Id::new(id).expect("id should be well-formed"),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some(content_type.to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload),
        owner: owner.map(|o| Id::new(o).expect("owner should be a valid Id")),
        creator: None,
        content_encoding: None,
        content_schema: Some(schema.to_string()),
        policy_ref: None,
        related: None,
        hlc: hlc.map(|s| s.to_string()),
        prev: prev.map(|s| s.to_string()),
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}

/// Build a `community.v1` descriptor at `/communities/<community_id>/` with
/// `ID: community` (the aggregated layout — Community Spec §Granularity). The
/// descriptor carries no logic; membership/roles/bans are attestations and
/// access control is policy. `policy` points at the community's policy object;
/// `issuer` is the authoritative attestation issuer.
#[allow(clippy::too_many_arguments)]
pub fn community(
    signing_key: &SigningKey,
    community_id: &str,
    name: &str,
    issuer: &str,
    policy: &str,
    description: Option<&str>,
    open: bool,
    created_at: Option<i64>,
) -> Vec<u8> {
    let path = format!("/communities/{community_id}/");
    let payload = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "issuer": issuer,
        "policy": policy,
        "description": description,
        "open": open,
        "created_at": created_at,
    }))
    .expect("community.v1 payload serialization");
    signed_object(
        signing_key,
        &path,
        "community",
        "community.v1",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// Build an **open-membership** `policy.v2` for a community, stored at the
/// community **root** `/communities/<community_id>/` with `ID: root`.
///
/// It lives at the community root (not a `policies/` sibling) so the daemon's
/// ancestor-walk `resolve_policy` finds it for every write under the community —
/// `spaces/**`, `members/**`, etc. — without any engine change. The descriptor
/// (`ID: community`) and this policy (`ID: root`) share the prefix but are
/// distinct `(path, id)` objects; policy indexing keys on the prefix alone.
///
/// The `member` role is anyone holding an in-force `membership` attestation from
/// `issuer`; members may post anywhere under the community's `spaces/**`; a `ban`
/// by `issuer` excludes them via `not_attested` (Policy Spec §Attestation-Defined
/// Roles, mirrored by the worked example in `l2_authorization.rs`).
pub fn community_policy(signing_key: &SigningKey, community_id: &str, issuer: &str) -> Vec<u8> {
    let path = format!("/communities/{community_id}/");
    let spaces = format!("/communities/{community_id}/spaces/**");
    let payload = serde_json::to_vec(&serde_json::json!({
        "roles": { "member": [{ "attested": { "type": "membership", "by": issuer } }] },
        "grants": [
            { "to": { "role": "member" }, "can": ["post"], "on": spaces }
        ],
        "restrictions": [
            { "on": spaces, "require": { "not_attested": { "type": "ban", "by": issuer } } }
        ],
    }))
    .expect("policy.v2 payload serialization");
    signed_object(
        signing_key,
        &path,
        "root",
        "policy.v2",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// Like [`community_policy`], but **open** and **community-scoped**: the `member`
/// role accepts a `membership:<community_id>` attestation from ANY issuer —
/// including the subject's own self-attestation (the `by` field is omitted, which
/// the policy engine treats as "any issuer"). This is the "anyone can join by
/// self-issuing a membership" model for `open: true` communities, but a
/// membership in one community does NOT authorize posting in another: the
/// attestation `type` carries the community id, and the matcher filters on `type`
/// (no engine change needed — the same mechanism `role:moderator` uses). Bans are
/// still gated on the community `issuer` so moderation stays with the authority.
pub fn community_policy_open(signing_key: &SigningKey, community_id: &str, issuer: &str) -> Vec<u8> {
    let path = format!("/communities/{community_id}/");
    let spaces = format!("/communities/{community_id}/spaces/**");
    let membership_type = format!("membership:{community_id}");
    let payload = serde_json::to_vec(&serde_json::json!({
        "roles": { "member": [{ "attested": { "type": membership_type } }] },
        "grants": [
            { "to": { "role": "member" }, "can": ["post"], "on": spaces }
        ],
        "restrictions": [
            { "on": spaces, "require": { "not_attested": { "type": "ban", "by": issuer } } }
        ],
    }))
    .expect("policy.v2 payload serialization");
    signed_object(
        signing_key,
        &path,
        "root",
        "policy.v2",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// Build a `collection.v1` descriptor at `collection_path` with `ID: _config`
/// (Content Spec §Durability Tiers). `batched` is the demo default for spaces;
/// `max_authoring_lag_s` widens the collection's back-dating bound `W`.
pub fn collection_config(
    signing_key: &SigningKey,
    collection_path: &str,
    batched: bool,
    batch_interval_s: Option<i64>,
    max_authoring_lag_s: Option<i64>,
    schema: Option<&str>,
) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "durability": if batched { "batched" } else { "on-chain" },
        "batch_interval_s": batch_interval_s,
        "max_authoring_lag_s": max_authoring_lag_s,
        "schema": schema,
    }))
    .expect("collection.v1 payload serialization");
    signed_object(
        signing_key,
        collection_path,
        crate::schema::COLLECTION_CONFIG_ID,
        "collection.v1",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// Build an `attestation.v1` in the issuer's namespace at
/// `/<issuer>/attestations/<subject>/` with `ID: <type>` (Attestation Spec
/// §Storage — stored under the issuer so a subject can't delete claims about
/// themselves). `Owner` is the issuer. `value` is opaque to validators.
#[allow(clippy::too_many_arguments)]
pub fn attestation(
    signing_key: &SigningKey,
    issuer: &str,
    subject: &str,
    type_: &str,
    value: serde_json::Value,
    issued_at: i64,
    expires: Option<i64>,
) -> Vec<u8> {
    let path = crate::schema::storage_path(issuer, subject);
    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": subject,
        "type": type_,
        "value": value,
        "issued_at": issued_at,
        "expires": expires,
        "issuer": issuer,
    }))
    .expect("attestation.v1 payload serialization");
    signed_object(
        signing_key,
        &path,
        type_,
        "attestation.v1",
        "application/json",
        payload,
        Some(issuer),
        None,
        None,
    )
}

/// Build a `post.v1` content object (Content Spec §Content Schemas). `owner` is
/// the author's controller (an email-rooted identity, conventionally), `hlc`/
/// `prev` stamp content-layer ordering when supplied.
#[allow(clippy::too_many_arguments)]
pub fn content_post(
    signing_key: &SigningKey,
    path: &str,
    id: &str,
    body: &str,
    owner: Option<&str>,
    hlc: Option<&str>,
    prev: Option<&str>,
) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({ "body": body }))
        .expect("post.v1 payload serialization");
    signed_object(
        signing_key,
        path,
        id,
        "post.v1",
        "application/json",
        payload,
        owner,
        hlc,
        prev,
    )
}

/// Build a `comment.v1` content object — a reply; `parent` (the URI of the
/// post/comment replied to) is required for threading.
#[allow(clippy::too_many_arguments)]
pub fn comment(
    signing_key: &SigningKey,
    path: &str,
    id: &str,
    body: &str,
    parent: &str,
    owner: Option<&str>,
    hlc: Option<&str>,
    prev: Option<&str>,
) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({ "body": body, "parent": parent }))
        .expect("comment.v1 payload serialization");
    signed_object(
        signing_key,
        path,
        id,
        "comment.v1",
        "application/json",
        payload,
        owner,
        hlc,
        prev,
    )
}

/// Build a `reaction.v1` content object — a toggle-able reaction keyed by
/// `(author, target, kind)`, resolved LWW by `HLC`. `state` false is a tombstone.
#[allow(clippy::too_many_arguments)]
pub fn reaction(
    signing_key: &SigningKey,
    path: &str,
    id: &str,
    target: &str,
    kind: &str,
    state: bool,
    owner: Option<&str>,
    hlc: Option<&str>,
    prev: Option<&str>,
) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "target": target,
        "kind": kind,
        "state": state,
    }))
    .expect("reaction.v1 payload serialization");
    signed_object(
        signing_key,
        path,
        id,
        "reaction.v1",
        "application/json",
        payload,
        owner,
        hlc,
        prev,
    )
}

/// A starter community in the Mingo aggregated genesis.
pub struct MingoCommunity<'a> {
    /// URL-safe community id (the `/communities/<id>/` segment), e.g. `cooks`.
    pub id: &'a str,
    /// Human-readable name, e.g. `Cooks`.
    pub name: &'a str,
    /// Short description.
    pub description: &'a str,
    /// The authoritative attestation issuer for this community (an email/name).
    pub issuer: &'a str,
}

/// Build the **Mingo aggregated genesis** as one atomic batch (Community Spec
/// §Granularity — several communities in one repository, one genesis, one root
/// policy). Emitted in dependency order so every write before the **hub root
/// policy** is admitted in genesis mode (the daemon allows posts until
/// `/sys/policies/root` exists):
///
/// 1. domain object (`/sys/domains/<domain>`, self-signed by the domain key)
/// 2. domain-certified `sys` identity (`/sys/names/sys`)
/// 3. pinned broker list (`/sys/trust/brokers`) — the on-chain attribution anchor
/// 4. per community: `community.v1`, the community's open-membership `policy.v2`,
///    and a `collection.v1` for `spaces/general/_config`
/// 5. the **hub root policy** (`/sys/policies/root`) — written last
///
/// The hub root policy is the repo-wide fallback (name claims, each user's own
/// namespace incl. self-issued membership). Each community's policy lives at its
/// **root** (`/communities/<id>/`, `ID: root`), so the daemon's ancestor-walk
/// `resolve_policy` resolves it for every write under that community — the
/// per-issuer `membership`/`ban` rules enforce without any engine change, and
/// each `community.v1`'s `policy` pointer names that same object. All signing
/// for sys-owned objects uses `sys_signing_key`.
pub fn mingo_genesis(
    domain_signing_key: &SigningKey,
    sys_signing_key: &SigningKey,
    domain_name: &str,
    broker: &str,
    communities: &[MingoCommunity<'_>],
    created_at: Option<i64>,
) -> Vec<u8> {
    let domain_public_key = domain_signing_key.public_key();
    let sys_public_key = sys_signing_key.public_key();

    let mut batch = Vec::new();

    // 1. Domain object (self-signed by the domain key).
    let domain_jwt = crate::jwt::create_domain(domain_signing_key, domain_name)
        .expect("domain JWT creation should not fail");
    let domain_bytes = domain_jwt.as_bytes().to_vec();
    let domain_hash = ContentHash::sha256(&domain_bytes);
    let mut domain_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/domains/").unwrap(),
        id: Id::new(domain_name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: domain_public_key,
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
    batch.extend(wire::serialize(&domain_msg));

    // 2. Domain-certified sys identity.
    let sys_email = format!("sys@{}", domain_name);
    let sys_jwt = crate::jwt::create_domain_certified_identity(
        domain_signing_key,
        domain_name,
        &sys_email,
        &sys_public_key,
        None,
    )
    .expect("sys JWT creation should not fail");
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
    batch.extend(wire::serialize(&sys_msg));

    // 3. Pinned broker list (on-chain attribution trust anchor).
    batch.extend(set_trust_brokers(sys_signing_key, &[broker]));

    // 4. Per-community descriptor + policy + general-space collection config.
    for c in communities {
        // The descriptor's policy pointer names the same object the daemon's
        // ancestor-walk resolves: the community-root policy (ID: root).
        let policy_path = format!("/communities/{}/", c.id);
        batch.extend(community(
            sys_signing_key,
            c.id,
            c.name,
            c.issuer,
            &policy_path,
            Some(c.description),
            true,
            created_at,
        ));
        batch.extend(community_policy_open(sys_signing_key, c.id, c.issuer));
        let general = format!("/communities/{}/spaces/general/", c.id);
        batch.extend(collection_config(
            sys_signing_key,
            &general,
            true,
            Some(5),
            Some(24 * 60 * 60),
            Some("post.v1"),
        ));
    }

    // 5. Hub root policy (written LAST so all prior writes pass in genesis mode).
    let policy_payload = serde_json::json!({
        "grants": [
            { "to": "*", "can": ["create"], "on": "/sys/names/*" },
            { "to": "owner", "can": ["update", "delete"], "on": "/sys/names/*" },
            { "to": "owner", "can": ["*"], "on": "/$owner/**" }
        ],
        "restrictions": [
            { "on": "/communities/*/spaces/**", "require": { "not_attested": { "type": "ban" } } }
        ]
    });
    let policy_bytes = serde_json::to_vec(&policy_payload).unwrap();
    let policy_hash = ContentHash::sha256(&policy_bytes);
    let mut policy_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        object_type: ObjectType::Object,
        signing_key: sys_public_key,
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
    batch.extend(wire::serialize(&policy_msg));

    batch
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

    /// Parse a builder's wire bytes, then verify signature + schema acceptance.
    fn parse_verified(wire_bytes: &[u8]) -> Message {
        let msg = wire::parse(wire_bytes).expect("serialized message should parse");
        crate::message::verify_message(&msg).expect("signature should verify");
        crate::schema::validate_schema(&msg).expect("payload should validate against its schema");
        msg
    }

    #[test]
    fn community_builder_roundtrips_and_validates() {
        let key = SigningKey::generate();
        let msg = parse_verified(&community(
            &key,
            "cooks",
            "Cooks",
            "cooks@mingo.place",
            "/communities/cooks/policies/root",
            Some("Home cooks."),
            true,
            Some(1_700_000_000),
        ));
        assert_eq!(msg.path.to_string(), "/communities/cooks/");
        assert_eq!(msg.id.as_str(), "community");
        assert_eq!(msg.content_schema.as_deref(), Some("community.v1"));
        let c = crate::schema::parse_community(msg.payload.as_ref().unwrap()).unwrap();
        assert_eq!(c.issuer, "cooks@mingo.place");
        assert_eq!(c.open, Some(true));
    }

    #[test]
    fn community_policy_builder_validates_and_parses_as_policy() {
        let key = SigningKey::generate();
        let msg = parse_verified(&community_policy(&key, "cooks", "cooks@mingo.place"));
        // Stored at the community ROOT so the ancestor-walk resolver finds it.
        assert_eq!(msg.path.to_string(), "/communities/cooks/");
        assert_eq!(msg.id.as_str(), "root");
        let _policy: crate::policy::Policy =
            serde_json::from_slice(msg.payload.as_ref().unwrap()).expect("parses as policy.v2");
    }

    #[test]
    fn collection_config_builder_validates() {
        let key = SigningKey::generate();
        let msg = parse_verified(&collection_config(
            &key,
            "/communities/cooks/spaces/general/",
            true,
            Some(5),
            Some(3600),
            Some("post.v1"),
        ));
        assert_eq!(msg.id.as_str(), "_config");
        let c = crate::schema::parse_collection(msg.payload.as_ref().unwrap()).unwrap();
        assert_eq!(c.durability, crate::schema::Durability::Batched);
        assert_eq!(c.max_authoring_lag_s, Some(3600));
    }

    #[test]
    fn attestation_builder_stores_under_issuer() {
        let key = SigningKey::generate();
        let msg = parse_verified(&attestation(
            &key,
            "cooks@mingo.place",
            "alice@mingo.place",
            "role:moderator",
            serde_json::json!(true),
            1_700_000_000,
            None,
        ));
        assert_eq!(
            msg.path.to_string(),
            "/cooks@mingo.place/attestations/alice@mingo.place/"
        );
        assert_eq!(msg.id.as_str(), "role:moderator");
        assert_eq!(msg.owner.as_ref().map(|o| o.as_str()), Some("cooks@mingo.place"));
        let a = crate::schema::parse_attestation(msg.payload.as_ref().unwrap()).unwrap();
        assert_eq!(a.subject, "alice@mingo.place");
        assert_eq!(a.type_, "role:moderator");
    }

    #[test]
    fn content_builders_carry_hlc_and_validate() {
        let key = SigningKey::generate();
        let owner = Some("alice@mingo.place");

        let post = parse_verified(&content_post(
            &key,
            "/communities/cooks/spaces/general/",
            "p1",
            "Sourdough tips",
            owner,
            Some("1700000000000.0"),
            None,
        ));
        assert_eq!(post.content_schema.as_deref(), Some("post.v1"));
        assert_eq!(post.hlc.as_deref(), Some("1700000000000.0"));

        let comment = parse_verified(&comment(
            &key,
            "/communities/cooks/spaces/general/",
            "c1",
            "Nice!",
            "/communities/cooks/spaces/general/alice@mingo.place/p1",
            owner,
            Some("1700000000001.0"),
            Some("1700000000000.0"),
        ));
        assert_eq!(comment.content_schema.as_deref(), Some("comment.v1"));
        assert_eq!(comment.prev.as_deref(), Some("1700000000000.0"));

        let reaction = parse_verified(&reaction(
            &key,
            "/communities/cooks/spaces/general/",
            "r1",
            "/communities/cooks/spaces/general/alice@mingo.place/p1",
            "upvote",
            true,
            owner,
            Some("1700000000002.0"),
            None,
        ));
        assert_eq!(reaction.content_schema.as_deref(), Some("reaction.v1"));
    }

    #[test]
    fn mingo_genesis_emits_ordered_batch_with_root_policy_last() {
        let domain_key = SigningKey::generate();
        let sys_key = SigningKey::generate();
        let communities = [
            MingoCommunity { id: "cooks", name: "Cooks", description: "Home cooks.", issuer: "cooks@mingo.place" },
            MingoCommunity { id: "woodworking", name: "Woodworking", description: "Makers.", issuer: "woodworking@mingo.place" },
            MingoCommunity { id: "homelab", name: "Homelab", description: "Self-hosters.", issuer: "homelab@mingo.place" },
        ];
        let batch = mingo_genesis(
            &domain_key,
            &sys_key,
            "mingo.place",
            "id.mingo.place",
            &communities,
            Some(1_700_000_000),
        );

        // The batch parses into a stream of well-formed, signature-valid messages.
        let msgs = wire::parse_batch(&batch).expect("batch parses");
        for msg in &msgs {
            crate::message::verify_message(msg).expect("each message verifies");
        }

        // 1 domain + 1 sys + 1 trust + 3 communities * 3 + 1 root policy = 13.
        assert_eq!(msgs.len(), 13);
        // The hub root policy is the final write (genesis-mode ordering).
        let last = msgs.last().unwrap();
        assert_eq!(last.path.to_string(), "/sys/policies/");
        assert_eq!(last.id.as_str(), "root");
        assert_eq!(last.content_schema.as_deref(), Some("policy.v2"));
        // No other root policy precedes it.
        assert!(
            !msgs[..msgs.len() - 1]
                .iter()
                .any(|m| m.path.to_string() == "/sys/policies/" && m.id.as_str() == "root"),
            "root policy must be written exactly once, last"
        );
    }
}
