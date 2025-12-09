//! Error types for sbo-core

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SboError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Database error: {0}")]
    Db(#[from] DbError),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("CRLF line endings not allowed")]
    CrlfNotAllowed,

    #[error("Missing required header: {0}")]
    MissingHeader(String),

    #[error("Invalid header format: {0}")]
    InvalidHeader(String),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

    #[error("Content-Length mismatch: expected {expected}, got {actual}")]
    ContentLengthMismatch { expected: usize, actual: usize },

    #[error("Content-Hash mismatch")]
    ContentHashMismatch,

    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Missing blank line separator")]
    MissingBlankLine,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid action: {0}")]
    InvalidAction(String),

    #[error("Payload required for object type")]
    PayloadRequired,

    #[error("Transfer requires at least one of: New-Owner, New-Path, New-ID")]
    TransferRequiresChange,

    #[error("No policy found for path")]
    NoPolicy,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error("RocksDB error: {0}")]
    RocksDb(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Object not found: {0}")]
    NotFound(String),
}
