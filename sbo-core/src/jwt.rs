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
}
