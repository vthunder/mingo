//! Hashing utilities

use sha2::{Sha256, Digest};
use crate::error::CryptoError;

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
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
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
            .ok_or_else(|| CryptoError::UnknownAlgorithm(s.to_string()))?;

        let algo = match algo_str {
            "sha256" => HashAlgo::Sha256,
            _ => return Err(CryptoError::UnknownAlgorithm(algo_str.to_string())),
        };

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidSignature);
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
        format!("{}:{}", algo_str, hex::encode(self.bytes))
    }
}
