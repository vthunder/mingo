//! Crypto error types (no_std compatible)

/// Cryptographic operation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid signature
    InvalidSignature,
    /// Invalid public key
    InvalidPublicKey,
    /// Unknown algorithm
    UnknownAlgorithm,
    /// Invalid key length
    InvalidKeyLength,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
            CryptoError::UnknownAlgorithm => write!(f, "Unknown algorithm"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
