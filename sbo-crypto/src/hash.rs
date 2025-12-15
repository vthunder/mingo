//! Hashing utilities (no_std compatible)

#[cfg(not(feature = "zkvm"))]
use sha2::{Sha256, Digest};
use crate::error::CryptoError;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
}

/// Content hash with algorithm identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHash {
    pub algo: HashAlgo,
    pub bytes: [u8; 32],
}

/// Compute SHA-256 hash
///
/// When compiled with the `zkvm` feature, uses RISC Zero's accelerated
/// SHA256 precompile which is orders of magnitude faster inside the zkVM.
#[cfg(not(feature = "zkvm"))]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 hash using RISC Zero accelerated precompile
#[cfg(feature = "zkvm")]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::Sha256 as Sha256Trait;
    // RISC Zero's sha module provides an accelerated implementation
    // that runs outside the zkVM and is proven in constant cycles
    let digest = risc0_zkvm::sha::Impl::hash_bytes(data);
    digest.as_bytes().try_into().expect("SHA256 produces 32 bytes")
}

impl ContentHash {
    /// Create a new SHA-256 content hash
    pub fn sha256(data: &[u8]) -> Self {
        Self {
            algo: HashAlgo::Sha256,
            bytes: sha256(data),
        }
    }

    /// Parse from "algo:hex" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let (algo_str, hex_str) = s
            .split_once(':')
            .ok_or(CryptoError::UnknownAlgorithm)?;

        let algo = match algo_str {
            "sha256" => HashAlgo::Sha256,
            _ => return Err(CryptoError::UnknownAlgorithm),
        };

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { algo, bytes: arr })
    }

    /// Format as "algo:hex"
    pub fn to_string(&self) -> String {
        let algo_str = match self.algo {
            HashAlgo::Sha256 => "sha256",
        };
        alloc::format!("{}:{}", algo_str, hex::encode(self.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_content_hash_roundtrip() {
        let hash = ContentHash::sha256(b"hello");
        let s = hash.to_string();
        let parsed = ContentHash::parse(&s).unwrap();
        assert_eq!(hash, parsed);
    }
}
