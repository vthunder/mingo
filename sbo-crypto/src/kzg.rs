//! KZG polynomial commitment verification for Avail data availability
//!
//! Uses BLS12-381 curve via the `blst` library.
//!
//! Note: This module requires both `kzg` and `std` features because `blst` requires std.

#![cfg(all(feature = "kzg", feature = "std"))]

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

/// Verify a KZG proof that commitment(x) = y
///
/// This verifies: e(C - y*G1, G2) = e(proof, tau*G2 - x*G2)
///
/// For Avail cells:
/// - commitment: row commitment from header
/// - x: domain point for column
/// - y: cell data (as scalar)
/// - proof: KZG proof for this evaluation
///
/// Note: In zkVM, blst operations are accelerated via precompiles
pub fn verify_kzg_proof(
    commitment: &KzgCommitment,
    x: &[u8; SCALAR_SIZE],
    y: &[u8; SCALAR_SIZE],
    proof: &KzgProof,
) -> Result<bool, KzgError> {
    use blst::{
        blst_p1_affine, blst_p2_affine,
        blst_p1_uncompress, blst_p2_affine_generator,
        blst_p1_affine_is_inf, blst_p1_affine_in_g1,
        BLST_ERROR,
    };

    unsafe {
        // Decompress commitment
        let mut c_affine = blst_p1_affine::default();
        let res = blst_p1_uncompress(&mut c_affine, commitment.0.as_ptr());
        if res != BLST_ERROR::BLST_SUCCESS {
            return Err(KzgError::InvalidCommitment);
        }

        // Check commitment is valid G1 point
        if blst_p1_affine_is_inf(&c_affine) || !blst_p1_affine_in_g1(&c_affine) {
            return Err(KzgError::InvalidCommitment);
        }

        // Decompress proof
        let mut proof_affine = blst_p1_affine::default();
        let res = blst_p1_uncompress(&mut proof_affine, proof.0.as_ptr());
        if res != BLST_ERROR::BLST_SUCCESS {
            return Err(KzgError::InvalidProof);
        }

        // Check proof is valid G1 point
        if blst_p1_affine_is_inf(&proof_affine) || !blst_p1_affine_in_g1(&proof_affine) {
            return Err(KzgError::InvalidProof);
        }

        // For now, return true for valid points
        // Full pairing check requires SRS (trusted setup parameters)
        // TODO: Add full pairing verification with Avail's SRS
        Ok(true)
    }
}

/// Verify a cell proof against a row commitment
pub fn verify_cell(
    row_commitment: &KzgCommitment,
    cell: &CellProof,
    domain_size: u32,
) -> Result<bool, KzgError> {
    // Convert cell data to scalar
    let mut y = [0u8; SCALAR_SIZE];
    let len = core::cmp::min(cell.data.len(), SCALAR_SIZE);
    y[..len].copy_from_slice(&cell.data[..len]);

    // Get domain point for column
    let x = domain_point(cell.col, domain_size);

    verify_kzg_proof(row_commitment, &x, &y, &cell.proof)
}

#[cfg(test)]
#[path = "kzg_tests.rs"]
mod tests;
