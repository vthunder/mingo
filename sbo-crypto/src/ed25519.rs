//! Ed25519 signature operations (no_std compatible)

use crate::error::CryptoError;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Ed25519 public key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub bytes: [u8; 32],
}

/// Ed25519 signature (64 bytes)
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 64]);

impl PublicKey {
    /// Parse from "ed25519:<hex>" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let hex_str = s
            .strip_prefix("ed25519:")
            .ok_or(CryptoError::UnknownAlgorithm)?;

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Format as "ed25519:<hex>"
    pub fn to_string(&self) -> String {
        alloc::format!("ed25519:{}", hex::encode(self.bytes))
    }

    /// Get algorithm prefix
    pub fn algorithm() -> &'static str {
        "ed25519"
    }
}

impl Signature {
    /// Parse from hex string
    pub fn parse(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength);
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

/// Verify an Ed25519 signature
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_parse_roundtrip() {
        let key_hex = "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pubkey = PublicKey::parse(key_hex).unwrap();
        assert_eq!(pubkey.to_string(), key_hex);
    }

    #[test]
    fn test_signature_parse_roundtrip() {
        let sig_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sig = Signature::parse(sig_hex).unwrap();
        assert_eq!(sig.to_hex(), sig_hex);
    }
}
