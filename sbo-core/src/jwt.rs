//! JWT encoding/decoding for SBO identity objects
//!
//! All identity and domain objects use JWT format with EdDSA signatures.
//! This is a manual JWT implementation (RFC 7519, RFC 8037) that works with
//! our existing ed25519 signing infrastructure and can be extended to BLS.

use crate::crypto::{verify, PublicKey, SigningKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT encoding error: {0}")]
    Encode(String),

    #[error("JWT decoding error: {0}")]
    Decode(String),

    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid issuer format: {0}")]
    InvalidIssuer(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub type JwtResult<T> = Result<T, JwtError>;

/// Supported JWT algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 (RFC 8037)
    EdDSA,
    // Future: BLS12-381
}

impl Algorithm {
    fn as_str(&self) -> &'static str {
        match self {
            Algorithm::EdDSA => "EdDSA",
        }
    }

    fn from_str(s: &str) -> JwtResult<Self> {
        match s {
            "EdDSA" => Ok(Algorithm::EdDSA),
            other => Err(JwtError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

/// JWT header (RFC 7519)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

impl JwtHeader {
    fn new(alg: Algorithm) -> Self {
        Self {
            alg: alg.as_str().to_string(),
            typ: "JWT".to_string(),
        }
    }
}

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
                return Err(JwtError::InvalidIssuer(
                    "domain: prefix requires domain name".into(),
                ));
            }
            Ok(Issuer::Domain(domain.to_string()))
        } else {
            Err(JwtError::InvalidIssuer(format!(
                "unknown issuer format: {}",
                s
            )))
        }
    }

    /// Serialize to string
    pub fn as_str(&self) -> String {
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

// ============================================================================
// Auth JWT Claims (SBO Auth Specification v0.1)
// ============================================================================

/// User delegation JWT claims - user authorizes an ephemeral key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDelegationClaims {
    /// User's public key: "ed25519:<hex>"
    pub iss: String,
    /// Ephemeral key being delegated to: "ed25519:<hex>"
    pub delegate_to: String,
    /// Issued-at timestamp (Unix seconds)
    pub iat: u64,
    /// Expiration timestamp (Unix seconds)
    pub exp: u64,
}

/// Session binding JWT claims - domain wraps user delegation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBindingClaims {
    /// Domain issuer: "domain:<domain>"
    pub iss: String,
    /// User's email address
    pub sub: String,
    /// Nested user delegation JWT (complete, signed)
    pub user_delegation: String,
    /// Issued-at timestamp (Unix seconds)
    pub iat: u64,
    /// Expiration timestamp (Unix seconds)
    pub exp: u64,
}

/// Auth assertion JWT claims - ephemeral key proves identity to app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAssertionClaims {
    /// User's email address
    pub iss: String,
    /// Application origin (audience)
    pub aud: String,
    /// Challenge from application
    pub nonce: String,
    /// Issued-at timestamp (Unix seconds)
    pub iat: u64,
}

/// Result of successful auth verification
#[derive(Debug, Clone)]
pub struct VerifiedAuth {
    /// User's email address
    pub email: String,
    /// User's public key (from delegation chain)
    pub user_key: PublicKey,
    /// Domain that issued the session binding
    pub domain: String,
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

// ============================================================================
// JWT Encoding/Decoding (RFC 7519, RFC 8037)
// ============================================================================

/// Encode a JWT: base64url(header).base64url(payload).base64url(signature)
fn encode_jwt<T: Serialize>(claims: &T, signing_key: &SigningKey) -> JwtResult<String> {
    let header = JwtHeader::new(Algorithm::EdDSA);

    // Encode header and payload
    let header_json = serde_json::to_vec(&header)?;
    let payload_json = serde_json::to_vec(claims)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // Create signing input: header.payload
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign with ed25519
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.0);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

/// Decode JWT claims without verification (for inspection)
fn decode_claims<T: for<'de> Deserialize<'de>>(token: &str) -> JwtResult<T> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat(format!(
            "expected 3 parts, got {}",
            parts.len()
        )));
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let claims: T = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

/// Decode and verify a JWT with a given public key
fn decode_and_verify<T: for<'de> Deserialize<'de>>(
    token: &str,
    public_key: &PublicKey,
) -> JwtResult<T> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat(format!(
            "expected 3 parts, got {}",
            parts.len()
        )));
    }

    // Verify header algorithm
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)?;
    let _alg = Algorithm::from_str(&header.alg)?;

    // Decode signature
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
    if signature_bytes.len() != 64 {
        return Err(JwtError::InvalidSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = crate::crypto::Signature(sig_arr);

    // Verify signature over header.payload
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verify(public_key, signing_input.as_bytes(), &signature)
        .map_err(|_| JwtError::InvalidSignature)?;

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let claims: T = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

// ============================================================================
// Public API
// ============================================================================

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

    encode_jwt(&claims, signing_key)
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

    encode_jwt(&claims, domain_signing_key)
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

    encode_jwt(&claims, signing_key)
}

/// Decode identity JWT without verification (for inspection)
pub fn decode_identity_claims(token: &str) -> JwtResult<IdentityClaims> {
    decode_claims(token)
}

/// Decode domain JWT without verification (for inspection)
pub fn decode_domain_claims(token: &str) -> JwtResult<DomainClaims> {
    decode_claims(token)
}

/// Verify a self-signed JWT (signature matches public_key in payload)
pub fn verify_self_signed_identity(token: &str) -> JwtResult<IdentityClaims> {
    // First decode without verification to get the public key
    let claims: IdentityClaims = decode_claims(token)?;

    if claims.iss != "self" {
        return Err(JwtError::InvalidIssuer(format!(
            "expected 'self', got '{}'",
            claims.iss
        )));
    }

    // Parse the public key from claims
    let public_key = PublicKey::parse(&claims.public_key)
        .map_err(|e| JwtError::InvalidPublicKey(format!("{}", e)))?;

    // Verify with that key
    decode_and_verify(token, &public_key)
}

/// Verify a domain-certified JWT (signature matches provided domain key)
pub fn verify_domain_certified_identity(
    token: &str,
    domain_key: &PublicKey,
) -> JwtResult<IdentityClaims> {
    let claims: IdentityClaims = decode_and_verify(token, domain_key)?;

    // Verify issuer is domain type
    if !claims.iss.starts_with("domain:") {
        return Err(JwtError::InvalidIssuer(format!(
            "expected 'domain:*', got '{}'",
            claims.iss
        )));
    }

    Ok(claims)
}

/// Verify a self-signed domain JWT
pub fn verify_domain(token: &str) -> JwtResult<DomainClaims> {
    // First decode without verification to get the public key
    let claims: DomainClaims = decode_claims(token)?;

    if claims.iss != "self" {
        return Err(JwtError::InvalidIssuer(format!(
            "domains must be self-signed, got '{}'",
            claims.iss
        )));
    }

    // Parse the public key from claims
    let public_key = PublicKey::parse(&claims.public_key)
        .map_err(|e| JwtError::InvalidPublicKey(format!("{}", e)))?;

    // Verify with that key
    decode_and_verify(token, &public_key)
}

// ============================================================================
// Auth JWT Functions (SBO Auth Specification v0.1)
// ============================================================================

/// Create a user delegation JWT (user key delegates to ephemeral key)
pub fn create_user_delegation(
    user_signing_key: &SigningKey,
    ephemeral_public_key: &PublicKey,
    expires_in_secs: u64,
) -> JwtResult<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = UserDelegationClaims {
        iss: user_signing_key.public_key().to_string(),
        delegate_to: ephemeral_public_key.to_string(),
        iat: now,
        exp: now + expires_in_secs,
    };

    encode_jwt(&claims, user_signing_key)
}

/// Create an auth assertion JWT (ephemeral key signs for app)
pub fn create_auth_assertion(
    ephemeral_signing_key: &SigningKey,
    email: &str,
    audience: &str,
    nonce: &str,
) -> JwtResult<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = AuthAssertionClaims {
        iss: email.to_string(),
        aud: audience.to_string(),
        nonce: nonce.to_string(),
        iat: now,
    };

    encode_jwt(&claims, ephemeral_signing_key)
}

/// Decode user delegation claims without verification
pub fn decode_user_delegation_claims(token: &str) -> JwtResult<UserDelegationClaims> {
    decode_claims(token)
}

/// Decode session binding claims without verification
pub fn decode_session_binding_claims(token: &str) -> JwtResult<SessionBindingClaims> {
    decode_claims(token)
}

/// Decode auth assertion claims without verification
pub fn decode_auth_assertion_claims(token: &str) -> JwtResult<AuthAssertionClaims> {
    decode_claims(token)
}

/// Verify a session binding JWT and extract the nested user delegation
///
/// Returns the session binding claims if valid.
/// Does NOT verify the nested user delegation - call verify_user_delegation for that.
pub fn verify_session_binding(
    token: &str,
    domain_key: &PublicKey,
) -> JwtResult<SessionBindingClaims> {
    let claims: SessionBindingClaims = decode_and_verify(token, domain_key)?;

    // Verify issuer is domain type
    if !claims.iss.starts_with("domain:") {
        return Err(JwtError::InvalidIssuer(format!(
            "expected 'domain:*', got '{}'",
            claims.iss
        )));
    }

    Ok(claims)
}

/// Verify a user delegation JWT
pub fn verify_user_delegation(
    token: &str,
    user_key: &PublicKey,
) -> JwtResult<UserDelegationClaims> {
    let claims: UserDelegationClaims = decode_and_verify(token, user_key)?;

    // Verify issuer matches the provided key
    if claims.iss != user_key.to_string() {
        return Err(JwtError::InvalidIssuer(format!(
            "issuer '{}' doesn't match provided key '{}'",
            claims.iss,
            user_key.to_string()
        )));
    }

    // Check expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if claims.exp <= now {
        return Err(JwtError::InvalidFormat("user delegation expired".into()));
    }

    Ok(claims)
}

/// Verify an auth assertion JWT
pub fn verify_auth_assertion(
    token: &str,
    ephemeral_key: &PublicKey,
) -> JwtResult<AuthAssertionClaims> {
    let claims: AuthAssertionClaims = decode_and_verify(token, ephemeral_key)?;

    // Check iat is recent (within 5 minutes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if claims.iat + 300 < now {
        return Err(JwtError::InvalidFormat("assertion too old".into()));
    }

    Ok(claims)
}

/// Full verification of auth assertion + session binding chain
///
/// This verifies the complete chain:
/// 1. Session binding signature (domain key)
/// 2. User delegation signature (user key from iss)
/// 3. Assertion signature (ephemeral key from delegate_to)
/// 4. Email matches across all JWTs
/// 5. Ephemeral key in assertion matches delegate_to in user delegation
pub fn verify_auth_chain(
    assertion_jwt: &str,
    session_binding_jwt: &str,
    domain_key: &PublicKey,
    expected_aud: &str,
    expected_nonce: &str,
) -> JwtResult<VerifiedAuth> {
    // 1. Verify session binding
    let session_binding = verify_session_binding(session_binding_jwt, domain_key)?;

    // Extract domain from issuer
    let domain = session_binding
        .iss
        .strip_prefix("domain:")
        .ok_or_else(|| JwtError::InvalidIssuer("missing domain: prefix".into()))?
        .to_string();

    // 2. Decode and verify user delegation (nested JWT)
    let user_delegation_claims: UserDelegationClaims =
        decode_claims(&session_binding.user_delegation)?;

    let user_key = PublicKey::parse(&user_delegation_claims.iss)
        .map_err(|e| JwtError::InvalidPublicKey(format!("{}", e)))?;

    let user_delegation =
        verify_user_delegation(&session_binding.user_delegation, &user_key)?;

    // 3. Get ephemeral key from delegation
    let ephemeral_key = PublicKey::parse(&user_delegation.delegate_to)
        .map_err(|e| JwtError::InvalidPublicKey(format!("{}", e)))?;

    // 4. Verify assertion with ephemeral key
    let assertion = verify_auth_assertion(assertion_jwt, &ephemeral_key)?;

    // 5. Verify audience and nonce
    if assertion.aud != expected_aud {
        return Err(JwtError::InvalidFormat(format!(
            "audience mismatch: expected '{}', got '{}'",
            expected_aud, assertion.aud
        )));
    }

    if assertion.nonce != expected_nonce {
        return Err(JwtError::InvalidFormat(format!(
            "nonce mismatch: expected '{}', got '{}'",
            expected_nonce, assertion.nonce
        )));
    }

    // 6. Verify email matches between assertion and session binding
    if assertion.iss != session_binding.sub {
        return Err(JwtError::InvalidFormat(format!(
            "email mismatch: assertion '{}', session binding '{}'",
            assertion.iss, session_binding.sub
        )));
    }

    Ok(VerifiedAuth {
        email: assertion.iss,
        user_key,
        domain,
    })
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

        // JWT should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);

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
        )
        .unwrap();

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

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();

        // Create domain-certified JWT signed by key1
        let domain_jwt = create_domain_certified_identity(
            &key1,
            "example.com",
            "alice@example.com",
            &key2.public_key(),
            None,
        )
        .unwrap();

        // Verifying with wrong key (key2) should fail
        let result = verify_domain_certified_identity(&domain_jwt, &key2.public_key());
        assert!(result.is_err());

        // Verifying with correct key (key1) should succeed
        let result = verify_domain_certified_identity(&domain_jwt, &key1.public_key());
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_without_verify() {
        let key = SigningKey::generate();
        let jwt = create_self_signed_identity(&key, "bob", None).unwrap();

        // Should decode without verification
        let claims = decode_identity_claims(&jwt).unwrap();
        assert_eq!(claims.sub, "bob");
    }

    #[test]
    fn test_tampered_jwt_fails() {
        let key = SigningKey::generate();
        let jwt = create_self_signed_identity(&key, "alice", None).unwrap();

        // Tamper with the payload (change a character)
        let parts: Vec<&str> = jwt.split('.').collect();
        let tampered = format!("{}X.{}.{}", &parts[0][..parts[0].len() - 1], parts[1], parts[2]);

        // Verification should fail
        let result = verify_self_signed_identity(&tampered);
        assert!(result.is_err());
    }

    // ========================================================================
    // Auth JWT Tests
    // ========================================================================

    #[test]
    fn test_user_delegation() {
        let user_key = SigningKey::generate();
        let ephemeral_key = SigningKey::generate();

        let jwt = create_user_delegation(&user_key, &ephemeral_key.public_key(), 3600).unwrap();

        // Should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);

        // Verify with correct key
        let claims = verify_user_delegation(&jwt, &user_key.public_key()).unwrap();
        assert_eq!(claims.iss, user_key.public_key().to_string());
        assert_eq!(claims.delegate_to, ephemeral_key.public_key().to_string());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_auth_assertion() {
        let ephemeral_key = SigningKey::generate();

        let jwt = create_auth_assertion(
            &ephemeral_key,
            "alice@example.com",
            "https://app.example.com",
            "test-nonce-123",
        )
        .unwrap();

        let claims = verify_auth_assertion(&jwt, &ephemeral_key.public_key()).unwrap();
        assert_eq!(claims.iss, "alice@example.com");
        assert_eq!(claims.aud, "https://app.example.com");
        assert_eq!(claims.nonce, "test-nonce-123");
    }

    #[test]
    fn test_full_auth_chain() {
        // Setup keys
        let domain_key = SigningKey::generate();
        let user_key = SigningKey::generate();
        let ephemeral_key = SigningKey::generate();

        // 1. Create user delegation (user -> ephemeral)
        let user_delegation_jwt =
            create_user_delegation(&user_key, &ephemeral_key.public_key(), 3600).unwrap();

        // 2. Create session binding (domain wraps user delegation)
        // Note: In real usage, domain creates this. We simulate it here.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session_binding_claims = SessionBindingClaims {
            iss: "domain:example.com".to_string(),
            sub: "alice@example.com".to_string(),
            user_delegation: user_delegation_jwt,
            iat: now,
            exp: now + 3600,
        };
        let session_binding_jwt = encode_jwt(&session_binding_claims, &domain_key).unwrap();

        // 3. Create auth assertion (ephemeral signs for app)
        let assertion_jwt = create_auth_assertion(
            &ephemeral_key,
            "alice@example.com",
            "https://app.example.com",
            "challenge-xyz",
        )
        .unwrap();

        // 4. Verify the full chain
        let result = verify_auth_chain(
            &assertion_jwt,
            &session_binding_jwt,
            &domain_key.public_key(),
            "https://app.example.com",
            "challenge-xyz",
        )
        .unwrap();

        assert_eq!(result.email, "alice@example.com");
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.user_key, user_key.public_key());
    }

    #[test]
    fn test_auth_chain_wrong_nonce() {
        let domain_key = SigningKey::generate();
        let user_key = SigningKey::generate();
        let ephemeral_key = SigningKey::generate();

        let user_delegation_jwt =
            create_user_delegation(&user_key, &ephemeral_key.public_key(), 3600).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session_binding_claims = SessionBindingClaims {
            iss: "domain:example.com".to_string(),
            sub: "alice@example.com".to_string(),
            user_delegation: user_delegation_jwt,
            iat: now,
            exp: now + 3600,
        };
        let session_binding_jwt = encode_jwt(&session_binding_claims, &domain_key).unwrap();

        let assertion_jwt = create_auth_assertion(
            &ephemeral_key,
            "alice@example.com",
            "https://app.example.com",
            "actual-nonce",
        )
        .unwrap();

        // Should fail with wrong nonce
        let result = verify_auth_chain(
            &assertion_jwt,
            &session_binding_jwt,
            &domain_key.public_key(),
            "https://app.example.com",
            "expected-nonce",
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce mismatch"));
    }

    #[test]
    fn test_auth_chain_email_mismatch() {
        let domain_key = SigningKey::generate();
        let user_key = SigningKey::generate();
        let ephemeral_key = SigningKey::generate();

        let user_delegation_jwt =
            create_user_delegation(&user_key, &ephemeral_key.public_key(), 3600).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session_binding_claims = SessionBindingClaims {
            iss: "domain:example.com".to_string(),
            sub: "alice@example.com".to_string(),
            user_delegation: user_delegation_jwt,
            iat: now,
            exp: now + 3600,
        };
        let session_binding_jwt = encode_jwt(&session_binding_claims, &domain_key).unwrap();

        // Assertion with different email
        let assertion_jwt = create_auth_assertion(
            &ephemeral_key,
            "bob@example.com", // Different email!
            "https://app.example.com",
            "test-nonce",
        )
        .unwrap();

        let result = verify_auth_chain(
            &assertion_jwt,
            &session_binding_jwt,
            &domain_key.public_key(),
            "https://app.example.com",
            "test-nonce",
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("email mismatch"));
    }
}
