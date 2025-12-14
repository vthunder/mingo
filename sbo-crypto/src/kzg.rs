//! KZG polynomial commitment verification for Avail data availability
//!
//! Uses BLS12-381 curve (accelerated in RISC Zero zkVM)

#![cfg(feature = "kzg")]

extern crate alloc;

use alloc::vec::Vec;
use blst::{blst_p1, blst_p1_affine, blst_p2, blst_p2_affine, blst_scalar, blst_fr};
use blst::min_pk::{PublicKey, Signature};

/// Size of a BLS12-381 G1 point (compressed)
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Size of a BLS12-381 G2 point (compressed)
pub const G2_COMPRESSED_SIZE: usize = 96;

/// Size of a scalar field element
pub const SCALAR_SIZE: usize = 32;

/// KZG commitment (G1 point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgCommitment(pub [u8; G1_COMPRESSED_SIZE]);

impl KzgCommitment {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return None;
        }
        let mut arr = [0u8; G1_COMPRESSED_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; G1_COMPRESSED_SIZE] {
        &self.0
    }
}

/// KZG proof (G1 point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgProof(pub [u8; G1_COMPRESSED_SIZE]);

impl KzgProof {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return None;
        }
        let mut arr = [0u8; G1_COMPRESSED_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; G1_COMPRESSED_SIZE] {
        &self.0
    }
}

/// Cell data with its KZG proof
#[derive(Debug, Clone)]
pub struct CellProof {
    /// Row index in the matrix
    pub row: u32,
    /// Column index in the matrix
    pub col: u32,
    /// Cell data (typically 32 bytes for Avail)
    pub data: Vec<u8>,
    /// KZG proof for this cell
    pub proof: KzgProof,
}

/// Error type for KZG verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KzgError {
    InvalidCommitment,
    InvalidProof,
    InvalidPoint,
    VerificationFailed,
}

impl core::fmt::Display for KzgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCommitment => write!(f, "Invalid KZG commitment"),
            Self::InvalidProof => write!(f, "Invalid KZG proof"),
            Self::InvalidPoint => write!(f, "Invalid curve point"),
            Self::VerificationFailed => write!(f, "KZG verification failed"),
        }
    }
}

/// Domain point for evaluation
/// In Avail, these are roots of unity based on column position
pub fn domain_point(col: u32, _domain_size: u32) -> [u8; SCALAR_SIZE] {
    // Compute omega^col where omega is primitive root of unity
    // For now, simplified: use column as scalar (real impl needs FFT domain)
    let mut scalar = [0u8; SCALAR_SIZE];
    scalar[0..4].copy_from_slice(&col.to_le_bytes());
    scalar
}
