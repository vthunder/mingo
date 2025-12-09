//! Ed25519 signing and verification

use crate::error::CryptoError;

/// Public key with algorithm identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub bytes: [u8; 32],
}

/// Secret key for signing
pub struct SecretKey {
    pub bytes: [u8; 32],
}

/// Signing key (includes both secret and public parts)
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

/// Ed25519 signature
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 64]);

impl SigningKey {
    /// Generate a new random signing key
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            inner: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            bytes: self.inner.verifying_key().to_bytes(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        Signature(self.inner.sign(message).to_bytes())
    }
}

/// Verify a signature
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Sign a message (convenience function)
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Signature {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key.bytes);
    use ed25519_dalek::Signer;
    Signature(signing_key.sign(message).to_bytes())
}

impl PublicKey {
    /// Parse from "ed25519:<hex>" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let hex_str = s
            .strip_prefix("ed25519:")
            .ok_or_else(|| CryptoError::UnknownAlgorithm(s.to_string()))?;

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidPublicKey);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Format as "ed25519:<hex>"
    pub fn to_string(&self) -> String {
        format!("ed25519:{}", hex::encode(self.bytes))
    }
}

impl Signature {
    /// Parse from hex string
    pub fn parse(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Format as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
