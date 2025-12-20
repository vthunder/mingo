# JWT Identity Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Update identity system to use JWT format with typed `iss` field distinguishing self-signed vs domain-certified identities.

**Architecture:**
- All identities use JWT format (`Content-Type: application/jwt`)
- `iss: "self"` = self-signed (verify JWT against `public_key` in payload)
- `iss: "domain:X"` = domain-certified (verify JWT against `/sys/domains/X`)
- Profiles are separate objects linked from identity via `profile` field

**Tech Stack:** Rust, `jsonwebtoken` crate for JWT, `ed25519-dalek` for EdDSA

---

## Phase 1: Add JWT Support to sbo-core

### Task 1.1: Add jsonwebtoken dependency

**Files:**
- Modify: `sbo-core/Cargo.toml`

**Step 1: Add dependency**

```toml
# In [dependencies] section, add:
jsonwebtoken = "9"
```

**Step 2: Verify it compiles**

Run: `cargo check -p sbo-core`
Expected: Compiles without errors

**Step 3: Commit**

```bash
git add sbo-core/Cargo.toml
git commit -m "deps: add jsonwebtoken for JWT identity support"
```

---

### Task 1.2: Create JWT module in sbo-core

**Files:**
- Create: `sbo-core/src/jwt.rs`
- Modify: `sbo-core/src/lib.rs`

**Step 1: Create jwt.rs with types and encoding**

```rust
//! JWT encoding/decoding for SBO identity objects
//!
//! All identity and domain objects use JWT format with EdDSA signatures.

use crate::crypto::{PublicKey, SigningKey};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT encoding error: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid issuer format: {0}")]
    InvalidIssuer(String),

    #[error("Key mismatch: expected {expected}, got {actual}")]
    KeyMismatch { expected: String, actual: String },

    #[error("Self-signed JWT must be signed by public_key in payload")]
    SelfSignedKeyMismatch,

    #[error("Domain-certified JWT requires domain key")]
    MissingDomainKey,
}

pub type JwtResult<T> = Result<T, JwtError>;

/// Issuer type for identity JWTs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issuer {
    /// Self-signed identity (sys, sovereign users)
    SelfSigned,
    /// Domain-certified identity (email users)
    Domain(String),
}

impl Issuer {
    /// Parse issuer string: "self" or "domain:example.com"
    pub fn parse(s: &str) -> JwtResult<Self> {
        if s == "self" {
            Ok(Issuer::SelfSigned)
        } else if let Some(domain) = s.strip_prefix("domain:") {
            if domain.is_empty() {
                return Err(JwtError::InvalidIssuer("domain: prefix requires domain name".into()));
            }
            Ok(Issuer::Domain(domain.to_string()))
        } else {
            Err(JwtError::InvalidIssuer(format!("unknown issuer format: {}", s)))
        }
    }

    /// Serialize to string
    pub fn to_string(&self) -> String {
        match self {
            Issuer::SelfSigned => "self".to_string(),
            Issuer::Domain(d) => format!("domain:{}", d),
        }
    }
}

/// Identity JWT claims (identity.v1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaims {
    /// Issuer: "self" or "domain:example.com"
    pub iss: String,
    /// Subject: name (self-signed) or email (domain-certified)
    pub sub: String,
    /// Public key with algorithm prefix
    pub public_key: String,
    /// Optional profile path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Issued-at timestamp (Unix seconds)
    pub iat: i64,
}

/// Domain JWT claims (domain.v1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainClaims {
    /// Always "self" for domains
    pub iss: String,
    /// Domain name
    pub sub: String,
    /// Domain's public key
    pub public_key: String,
    /// Issued-at timestamp
    pub iat: i64,
}

/// Profile data (profile.v1) - NOT a JWT, just JSON
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Create a self-signed identity JWT
pub fn create_self_signed_identity(
    signing_key: &SigningKey,
    subject: &str,
    profile: Option<&str>,
) -> JwtResult<String> {
    let public_key = signing_key.public_key();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = IdentityClaims {
        iss: "self".to_string(),
        sub: subject.to_string(),
        public_key: public_key.to_string(),
        profile: profile.map(|s| s.to_string()),
        iat: now,
    };

    let header = Header::new(Algorithm::EdDSA);
    let key = EncodingKey::from_ed_der(signing_key.to_bytes().as_ref());

    Ok(encode(&header, &claims, &key)?)
}

/// Create a domain-certified identity JWT (signed by domain key)
pub fn create_domain_certified_identity(
    domain_signing_key: &SigningKey,
    domain: &str,
    email: &str,
    user_public_key: &PublicKey,
    profile: Option<&str>,
) -> JwtResult<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = IdentityClaims {
        iss: format!("domain:{}", domain),
        sub: email.to_string(),
        public_key: user_public_key.to_string(),
        profile: profile.map(|s| s.to_string()),
        iat: now,
    };

    let header = Header::new(Algorithm::EdDSA);
    let key = EncodingKey::from_ed_der(domain_signing_key.to_bytes().as_ref());

    Ok(encode(&header, &claims, &key)?)
}

/// Create a self-signed domain JWT
pub fn create_domain(signing_key: &SigningKey, domain_name: &str) -> JwtResult<String> {
    let public_key = signing_key.public_key();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = DomainClaims {
        iss: "self".to_string(),
        sub: domain_name.to_string(),
        public_key: public_key.to_string(),
        iat: now,
    };

    let header = Header::new(Algorithm::EdDSA);
    let key = EncodingKey::from_ed_der(signing_key.to_bytes().as_ref());

    Ok(encode(&header, &claims, &key)?)
}

/// Decode identity JWT without verification (for inspection)
pub fn decode_identity_claims(token: &str) -> JwtResult<IdentityClaims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.insecure_disable_signature_validation();
    validation.required_spec_claims.clear();

    let token_data = decode::<IdentityClaims>(token, &DecodingKey::from_secret(&[]), &validation)?;
    Ok(token_data.claims)
}

/// Decode domain JWT without verification (for inspection)
pub fn decode_domain_claims(token: &str) -> JwtResult<DomainClaims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.insecure_disable_signature_validation();
    validation.required_spec_claims.clear();

    let token_data = decode::<DomainClaims>(token, &DecodingKey::from_secret(&[]), &validation)?;
    Ok(token_data.claims)
}

/// Verify a self-signed JWT (signature matches public_key in payload)
pub fn verify_self_signed_identity(token: &str) -> JwtResult<IdentityClaims> {
    // First decode without verification to get the public key
    let claims = decode_identity_claims(token)?;

    if claims.iss != "self" {
        return Err(JwtError::InvalidIssuer(format!("expected 'self', got '{}'", claims.iss)));
    }

    // Parse the public key from claims
    let public_key = PublicKey::parse(&claims.public_key)
        .map_err(|e| JwtError::InvalidIssuer(format!("invalid public_key: {}", e)))?;

    // Now verify with that key
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims.clear();

    let key = DecodingKey::from_ed_der(public_key.to_bytes().as_ref());
    let token_data = decode::<IdentityClaims>(token, &key, &validation)?;

    Ok(token_data.claims)
}

/// Verify a domain-certified JWT (signature matches provided domain key)
pub fn verify_domain_certified_identity(token: &str, domain_key: &PublicKey) -> JwtResult<IdentityClaims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims.clear();

    let key = DecodingKey::from_ed_der(domain_key.to_bytes().as_ref());
    let token_data = decode::<IdentityClaims>(token, &key, &validation)?;

    // Verify issuer is domain type
    if !token_data.claims.iss.starts_with("domain:") {
        return Err(JwtError::InvalidIssuer(format!(
            "expected 'domain:*', got '{}'",
            token_data.claims.iss
        )));
    }

    Ok(token_data.claims)
}

/// Verify a self-signed domain JWT
pub fn verify_domain(token: &str) -> JwtResult<DomainClaims> {
    // First decode without verification to get the public key
    let claims = decode_domain_claims(token)?;

    if claims.iss != "self" {
        return Err(JwtError::InvalidIssuer(format!("domains must be self-signed, got '{}'", claims.iss)));
    }

    // Parse the public key from claims
    let public_key = PublicKey::parse(&claims.public_key)
        .map_err(|e| JwtError::InvalidIssuer(format!("invalid public_key: {}", e)))?;

    // Now verify with that key
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims.clear();

    let key = DecodingKey::from_ed_der(public_key.to_bytes().as_ref());
    let token_data = decode::<DomainClaims>(token, &key, &validation)?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_parse() {
        assert_eq!(Issuer::parse("self").unwrap(), Issuer::SelfSigned);
        assert_eq!(
            Issuer::parse("domain:example.com").unwrap(),
            Issuer::Domain("example.com".to_string())
        );
        assert!(Issuer::parse("domain:").is_err());
        assert!(Issuer::parse("invalid").is_err());
    }

    #[test]
    fn test_self_signed_identity() {
        let key = SigningKey::generate();
        let jwt = create_self_signed_identity(&key, "alice", Some("/alice/profile")).unwrap();

        let claims = verify_self_signed_identity(&jwt).unwrap();
        assert_eq!(claims.iss, "self");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.public_key, key.public_key().to_string());
        assert_eq!(claims.profile, Some("/alice/profile".to_string()));
    }

    #[test]
    fn test_domain_certified_identity() {
        let domain_key = SigningKey::generate();
        let user_key = SigningKey::generate();

        let jwt = create_domain_certified_identity(
            &domain_key,
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            None,
        ).unwrap();

        let claims = verify_domain_certified_identity(&jwt, &domain_key.public_key()).unwrap();
        assert_eq!(claims.iss, "domain:example.com");
        assert_eq!(claims.sub, "alice@example.com");
        assert_eq!(claims.public_key, user_key.public_key().to_string());
    }

    #[test]
    fn test_domain_jwt() {
        let key = SigningKey::generate();
        let jwt = create_domain(&key, "example.com").unwrap();

        let claims = verify_domain(&jwt).unwrap();
        assert_eq!(claims.iss, "self");
        assert_eq!(claims.sub, "example.com");
        assert_eq!(claims.public_key, key.public_key().to_string());
    }
}
```

**Step 2: Add module to lib.rs**

In `sbo-core/src/lib.rs`, add:
```rust
pub mod jwt;
```

**Step 3: Run tests**

Run: `cargo test -p sbo-core jwt`
Expected: All jwt tests pass

**Step 4: Commit**

```bash
git add sbo-core/src/jwt.rs sbo-core/src/lib.rs
git commit -m "feat(jwt): add JWT module for identity/domain objects"
```

---

## Phase 2: Update Schema Validation

### Task 2.1: Update schema/mod.rs for JWT validation

**Files:**
- Modify: `sbo-core/src/schema/mod.rs`

**Step 1: Add JWT schema validation**

Replace the `validate_schema` function body with:

```rust
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
                    field: "payload".to_string(),
                    reason: "JWT must be valid UTF-8".to_string(),
                })?;

            let claims = crate::jwt::decode_identity_claims(token)
                .map_err(|e| SchemaError::InvalidField {
                    field: "jwt".to_string(),
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

            // For self-signed, verify JWT signature matches public_key
            if claims.iss == "self" {
                crate::jwt::verify_self_signed_identity(token)
                    .map_err(|e| SchemaError::InvalidField {
                        field: "signature".to_string(),
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
                    field: "payload".to_string(),
                    reason: "JWT must be valid UTF-8".to_string(),
                })?;

            let claims = crate::jwt::verify_domain(token)
                .map_err(|e| SchemaError::InvalidField {
                    field: "jwt".to_string(),
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
            // Unknown schemas pass through
            tracing::debug!("Unknown schema '{}', skipping validation", schema);
            Ok(())
        }
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p sbo-core schema`
Expected: Tests pass (some may need updating)

**Step 3: Commit**

```bash
git add sbo-core/src/schema/mod.rs
git commit -m "feat(schema): update validation for JWT-based identity/domain"
```

---

## Phase 3: Update Genesis Presets

### Task 3.1: Update presets.rs for JWT genesis

**Files:**
- Modify: `sbo-core/src/presets.rs`

**Step 1: Update genesis function**

Replace the `genesis` function with:

```rust
/// Generate genesis batch (sys identity + root policy concatenated)
/// Returns a single batch suitable for atomic DA submission
///
/// This creates a Mode A (self-signed sys) genesis.
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
    };
    policy_msg.sign(signing_key);

    // Concatenate messages for atomic batch submission
    let mut batch = wire::serialize(&sys_msg);
    batch.extend(wire::serialize(&policy_msg));
    batch
}

/// Generate Mode B genesis (domain-certified sys)
///
/// Creates: domain object, domain-certified sys identity, root policy
pub fn genesis_with_domain(domain_signing_key: &SigningKey, sys_signing_key: &SigningKey, domain_name: &str) -> Vec<u8> {
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
    ).expect("JWT creation should not fail");
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
    };
    policy_msg.sign(sys_signing_key);

    // Concatenate in order
    let mut batch = wire::serialize(&domain_msg);
    batch.extend(wire::serialize(&sys_msg));
    batch.extend(wire::serialize(&policy_msg));
    batch
}
```

**Step 2: Update claim_name function**

Replace `claim_name` function:

```rust
/// Claim a name at /sys/names/<name> (self-signed identity)
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
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}
```

**Step 3: Run tests**

Run: `cargo test -p sbo-core presets`
Expected: Tests pass

**Step 4: Commit**

```bash
git add sbo-core/src/presets.rs
git commit -m "feat(genesis): update to JWT-based identity format"
```

---

## Phase 4: Update CLI Identity Commands

### Task 4.1: Update identity create command

**Files:**
- Modify: `sbo-cli/src/commands/identity.rs`

**Step 1: Update create function to use JWT**

Update the `create` function imports and payload generation:

```rust
pub async fn create(
    uri: &str,
    name: &str,
    key_alias: Option<&str>,
    display_name: Option<&str>,
    description: Option<&str>,
    avatar: Option<&str>,
    website: Option<&str>,
    binding: Option<&str>,
    dry_run: bool,
    no_wait: bool,
) -> Result<()> {
    // Open keyring and resolve signing key
    let mut keyring = Keyring::open()?;
    let alias = keyring.resolve_alias(key_alias)?;
    let signing_key = keyring.get_signing_key(&alias)?;
    let public_key = signing_key.public_key();

    // For now, create self-signed identity (domain-certified requires domain key)
    // TODO: Add --domain flag for domain-certified identities

    // Profile path (if we have profile data, we'd create it separately)
    let profile_path = if display_name.is_some() || avatar.is_some() || website.is_some() {
        Some(format!("/{}/profile", name))
    } else {
        None
    };

    // Create identity JWT
    let jwt = sbo_core::jwt::create_self_signed_identity(
        &signing_key,
        name,
        profile_path.as_deref(),
    )?;
    let payload = jwt.as_bytes().to_vec();

    // Build SBO message
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Id, Message, ObjectType, Path};

    let placeholder_sig = Signature::parse(&"0".repeat(128))?;
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/")?,
        id: Id::new(name)?,
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: placeholder_sig,
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        content_schema: Some("identity.v1".to_string()),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        policy_ref: None,
        related: None,
    };
    msg.sign(&signing_key);

    // ... rest of function unchanged (wire format, submission, etc.)
```

**Step 2: Create separate profile if needed**

Add after the identity submission success:

```rust
// If we have profile data, create profile object
if display_name.is_some() || description.is_some() || avatar.is_some() || website.is_some() {
    let mut profile = sbo_core::jwt::Profile::default();
    profile.display_name = display_name.map(|s| s.to_string());
    profile.bio = description.map(|s| s.to_string());
    profile.avatar = avatar.map(|s| s.to_string());

    if let Some(ws) = website {
        let mut links = std::collections::HashMap::new();
        links.insert("website".to_string(), ws.to_string());
        profile.links = Some(links);
    }

    let profile_payload = serde_json::to_vec(&profile)?;

    // Create profile message
    let mut profile_msg = Message {
        action: Action::Post,
        path: Path::parse(&format!("/{}/", name))?,
        id: Id::new("profile")?,
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: Signature::parse(&"0".repeat(128))?,
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&profile_payload)),
        content_schema: Some("profile.v1".to_string()),
        payload: Some(profile_payload),
        owner: None,
        creator: None,
        content_encoding: None,
        policy_ref: None,
        related: None,
    };
    profile_msg.sign(&signing_key);

    // Submit profile
    let profile_wire = sbo_core::wire::serialize(&profile_msg);
    // ... submit via daemon
}
```

**Step 3: Run and test manually**

Run: `cargo build -p sbo-cli`
Expected: Compiles

**Step 4: Commit**

```bash
git add sbo-cli/src/commands/identity.rs
git commit -m "feat(cli): update identity create to use JWT format"
```

---

## Phase 5: Add Domain Commands

### Task 5.1: Add domain subcommand to CLI

**Files:**
- Create: `sbo-cli/src/commands/domain.rs`
- Modify: `sbo-cli/src/commands/mod.rs`
- Modify: `sbo-cli/src/main.rs`

**Step 1: Create domain.rs**

```rust
//! Domain management commands

use anyhow::Result;
use sbo_core::keyring::Keyring;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};

/// Create a domain at /sys/domains/<domain>
pub async fn create(
    uri: &str,
    domain_name: &str,
    key_alias: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let mut keyring = Keyring::open()?;
    let alias = keyring.resolve_alias(key_alias)?;
    let signing_key = keyring.get_signing_key(&alias)?;
    let public_key = signing_key.public_key();

    // Create domain JWT
    let jwt = sbo_core::jwt::create_domain(&signing_key, domain_name)?;
    let payload = jwt.as_bytes().to_vec();

    // Build SBO message
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Id, Message, ObjectType, Path};

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/domains/")?,
        id: Id::new(domain_name)?,
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: Signature::parse(&"0".repeat(128))?,
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        content_schema: Some("domain.v1".to_string()),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        policy_ref: None,
        related: None,
    };
    msg.sign(&signing_key);

    let wire_bytes = sbo_core::wire::serialize(&msg);

    if dry_run {
        println!("{}", String::from_utf8_lossy(&wire_bytes));
        return Ok(());
    }

    // Submit to daemon
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    let domain_uri = format!("{}/sys/domains/{}", uri.trim_end_matches('/'), domain_name);
    println!("Creating domain '{}' at {}", domain_name, uri);
    println!("  Key: {} ({})", alias, public_key);

    match client.request(Request::Submit {
        uri: uri.to_string(),
        data: wire_bytes,
    }).await {
        Ok(Response::Ok { data }) => {
            println!("\n✓ Domain created");
            println!("  URI: {}", domain_uri);
            if let Some(id) = data.get("submission_id").and_then(|v| v.as_str()) {
                println!("  Submission ID: {}", id);
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Error connecting to daemon: {}", e);
        }
    }

    Ok(())
}

/// List domains from /sys/domains/
pub async fn list(uri_filter: Option<&str>) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    match client.request(Request::ListDomains {
        uri: uri_filter.map(|s| s.to_string()),
    }).await {
        Ok(Response::Ok { data }) => {
            if let Some(domains) = data.get("domains").and_then(|v| v.as_array()) {
                if domains.is_empty() {
                    println!("No domains found");
                } else {
                    println!("{:<40} {:<20} {}", "URI", "DOMAIN", "KEY");
                    for d in domains {
                        let uri = d.get("uri").and_then(|v| v.as_str()).unwrap_or("-");
                        let domain = d.get("domain").and_then(|v| v.as_str()).unwrap_or("-");
                        let key = d.get("public_key").and_then(|v| v.as_str()).unwrap_or("-");
                        let short_key = if key.len() > 20 {
                            format!("{}...", &key[..20])
                        } else {
                            key.to_string()
                        };
                        println!("{:<40} {:<20} {}", uri, domain, short_key);
                    }
                }
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Error connecting to daemon: {}", e);
        }
    }

    Ok(())
}
```

**Step 2: Add to mod.rs**

In `sbo-cli/src/commands/mod.rs`, add:
```rust
pub mod domain;
```

**Step 3: Add domain commands to main.rs**

Add to the `Commands` enum:
```rust
/// Domain management
Domain {
    #[command(subcommand)]
    command: DomainCommands,
},
```

Add new enum:
```rust
#[derive(Subcommand)]
enum DomainCommands {
    /// Create a domain at /sys/domains/<domain>
    Create {
        /// Repository URI (e.g., sbo://avail:turing:506/)
        uri: String,
        /// Domain name (e.g., example.com)
        domain: String,
        /// Key alias to sign with
        #[arg(short, long)]
        key: Option<String>,
        /// Output wire format instead of submitting
        #[arg(long)]
        dry_run: bool,
    },
    /// List domains
    List {
        /// Filter by repository URI
        uri: Option<String>,
    },
}
```

Add handler in match:
```rust
Commands::Domain { command } => match command {
    DomainCommands::Create { uri, domain, key, dry_run } => {
        commands::domain::create(&uri, &domain, key.as_deref(), dry_run).await?;
    }
    DomainCommands::List { uri } => {
        commands::domain::list(uri.as_deref()).await?;
    }
},
```

**Step 4: Build and test**

Run: `cargo build -p sbo-cli`
Expected: Compiles

**Step 5: Commit**

```bash
git add sbo-cli/src/commands/domain.rs sbo-cli/src/commands/mod.rs sbo-cli/src/main.rs
git commit -m "feat(cli): add domain create and list commands"
```

---

## Phase 6: Update Daemon IPC

### Task 6.1: Add domain IPC handlers

**Files:**
- Modify: `sbo-daemon/src/ipc.rs`
- Modify: `sbo-daemon/src/main.rs` (handlers)

**Step 1: Add Request variants to ipc.rs**

```rust
/// List domains from synced repos
ListDomains {
    uri: Option<String>,
},

/// Get a specific domain
GetDomain {
    uri: String,  // Full path like sbo://chain:appid/sys/domains/example.com
},
```

**Step 2: Add handlers in main.rs**

```rust
Request::ListDomains { uri } => {
    // Scan /sys/domains/ in repos
    let repos = repo_manager.list_repos();
    let mut domains = Vec::new();

    for repo in repos {
        if let Some(ref filter) = uri {
            if !repo.uri.starts_with(filter) {
                continue;
            }
        }

        let domains_path = repo.path.join("sys/domains");
        if domains_path.exists() {
            if let Ok(entries) = std::fs::read_dir(&domains_path) {
                for entry in entries.flatten() {
                    if let Ok(content) = std::fs::read(entry.path()) {
                        // Parse JWT to get domain info
                        if let Ok(token) = std::str::from_utf8(&content) {
                            if let Ok(claims) = sbo_core::jwt::decode_domain_claims(token) {
                                domains.push(serde_json::json!({
                                    "uri": format!("{}/sys/domains/{}", repo.uri, claims.sub),
                                    "domain": claims.sub,
                                    "public_key": claims.public_key,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    Response::Ok {
        data: serde_json::json!({ "domains": domains }),
    }
}
```

**Step 3: Build and test**

Run: `cargo build -p sbo-daemon`
Expected: Compiles

**Step 4: Commit**

```bash
git add sbo-daemon/src/ipc.rs sbo-daemon/src/main.rs
git commit -m "feat(daemon): add domain list IPC handler"
```

---

## Phase 7: Integration Testing

### Task 7.1: Add integration tests

**Files:**
- Create: `sbo-core/tests/jwt_identity_test.rs`

**Step 1: Create integration test**

```rust
//! Integration tests for JWT-based identity system

use sbo_core::crypto::SigningKey;
use sbo_core::jwt::{
    create_self_signed_identity, create_domain_certified_identity,
    create_domain, verify_self_signed_identity, verify_domain_certified_identity,
    verify_domain, Issuer,
};
use sbo_core::presets;
use sbo_core::wire;

#[test]
fn test_genesis_mode_a() {
    let sys_key = SigningKey::generate();
    let batch = presets::genesis(&sys_key);

    // Parse the batch
    let messages = wire::parse_batch(&batch).unwrap();
    assert_eq!(messages.len(), 2);

    // First message is sys identity
    let sys_msg = &messages[0];
    assert_eq!(sys_msg.path.as_str(), "/sys/names/");
    assert_eq!(sys_msg.id.as_str(), "sys");
    assert_eq!(sys_msg.content_schema.as_deref(), Some("identity.v1"));
    assert_eq!(sys_msg.content_type.as_deref(), Some("application/jwt"));

    // Verify JWT
    let jwt = std::str::from_utf8(sys_msg.payload.as_ref().unwrap()).unwrap();
    let claims = verify_self_signed_identity(jwt).unwrap();
    assert_eq!(claims.iss, "self");
    assert_eq!(claims.sub, "sys");
    assert_eq!(claims.public_key, sys_key.public_key().to_string());
}

#[test]
fn test_genesis_mode_b() {
    let domain_key = SigningKey::generate();
    let sys_key = SigningKey::generate();
    let batch = presets::genesis_with_domain(&domain_key, &sys_key, "example.com");

    let messages = wire::parse_batch(&batch).unwrap();
    assert_eq!(messages.len(), 3);

    // First is domain
    let domain_msg = &messages[0];
    assert_eq!(domain_msg.path.as_str(), "/sys/domains/");
    assert_eq!(domain_msg.id.as_str(), "example.com");

    let domain_jwt = std::str::from_utf8(domain_msg.payload.as_ref().unwrap()).unwrap();
    let domain_claims = verify_domain(domain_jwt).unwrap();
    assert_eq!(domain_claims.sub, "example.com");

    // Second is sys identity (domain-certified)
    let sys_msg = &messages[1];
    let sys_jwt = std::str::from_utf8(sys_msg.payload.as_ref().unwrap()).unwrap();
    let sys_claims = verify_domain_certified_identity(sys_jwt, &domain_key.public_key()).unwrap();
    assert_eq!(sys_claims.iss, "domain:example.com");
    assert_eq!(sys_claims.sub, "sys@example.com");
}

#[test]
fn test_claim_name_jwt() {
    let key = SigningKey::generate();
    let msg_bytes = presets::claim_name(&key, "alice");

    let messages = wire::parse_batch(&msg_bytes).unwrap();
    assert_eq!(messages.len(), 1);

    let msg = &messages[0];
    assert_eq!(msg.content_type.as_deref(), Some("application/jwt"));
    assert_eq!(msg.content_schema.as_deref(), Some("identity.v1"));

    let jwt = std::str::from_utf8(msg.payload.as_ref().unwrap()).unwrap();
    let claims = verify_self_signed_identity(jwt).unwrap();
    assert_eq!(claims.sub, "alice");
}
```

**Step 2: Run tests**

Run: `cargo test -p sbo-core --test jwt_identity_test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add sbo-core/tests/jwt_identity_test.rs
git commit -m "test: add JWT identity integration tests"
```

---

## Summary

This plan implements:

1. **JWT module** (`sbo-core/src/jwt.rs`) - Encoding/decoding/verification for identity and domain JWTs
2. **Schema updates** - Validation for `identity.v1`, `domain.v1`, `profile.v1`
3. **Genesis updates** - Mode A (self-signed sys) and Mode B (domain-certified sys)
4. **CLI updates** - Identity create uses JWT, new domain commands
5. **Daemon updates** - IPC handlers for domain operations
6. **Tests** - Integration tests for the full flow

Key changes from old format:
- Identities now use JWT (`Content-Type: application/jwt`) instead of JSON
- `iss` field distinguishes self-signed (`"self"`) from domain-certified (`"domain:X"`)
- Profile data is separate, linked via `profile` field in identity
- Domains live at `/sys/domains/{domain}` instead of `/sys/domain`
