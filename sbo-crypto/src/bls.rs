//! BLS12-381 signature operations (no_std compatible)
//!
//! Uses the `blst` crate which has RISC Zero zkVM acceleration.

use crate::error::CryptoError;

#[cfg(feature = "alloc")]
use alloc::string::String;

use blst::min_pk::{PublicKey as BlstPublicKey, Signature as BlstSignature};

/// BLS12-381 public key (48 bytes compressed G1 point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub bytes: [u8; 48],
}

/// BLS12-381 signature (96 bytes compressed G2 point)
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 96]);

/// Domain separation tag for SBO signatures
const DST: &[u8] = b"SBO_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

impl PublicKey {
    /// Parse from "bls12-381:<hex>" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let hex_str = s
            .strip_prefix("bls12-381:")
            .ok_or(CryptoError::UnknownAlgorithm)?;

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        if bytes.len() != 48 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Format as "bls12-381:<hex>"
    pub fn to_string(&self) -> String {
        alloc::format!("bls12-381:{}", hex::encode(self.bytes))
    }

    /// Get algorithm prefix
    pub fn algorithm() -> &'static str {
        "bls12-381"
    }
}

impl Signature {
    /// Parse from hex string
    pub fn parse(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 96 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Format as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Verify a BLS12-381 signature
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    let pk = BlstPublicKey::from_bytes(&public_key.bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = BlstSignature::from_bytes(&signature.0)
        .map_err(|_| CryptoError::InvalidSignature)?;

    let result = sig.verify(true, message, DST, &[], &pk, true);

    if result == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_parse_format() {
        // 48 bytes = 96 hex chars
        let hex_key = "bls12-381:".to_string() + &"ab".repeat(48);
        let pk = PublicKey::parse(&hex_key).unwrap();
        assert_eq!(pk.to_string(), hex_key);
    }

    #[test]
    fn test_signature_parse_format() {
        // 96 bytes = 192 hex chars
        let hex_sig = "cd".repeat(96);
        let sig = Signature::parse(&hex_sig).unwrap();
        assert_eq!(sig.to_hex(), hex_sig);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = "bls12-381:abcd";
        assert!(PublicKey::parse(short_key).is_err());
    }
}
