//! SBO Cryptographic Operations
//!
//! Provides signature verification and hashing for SBO.
//! Supports both Ed25519 and BLS12-381 signatures.
//!
//! This crate is `no_std` compatible for zkVM use.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub mod hash;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "bls")]
pub mod bls;

// kzg, poly, srs_data, and srs modules require std because blst needs std
#[cfg(all(feature = "kzg", feature = "std"))]
pub mod kzg;

#[cfg(all(feature = "kzg", feature = "std"))]
pub mod poly;

#[cfg(all(feature = "kzg", feature = "std"))]
mod srs_data;

#[cfg(all(feature = "kzg", feature = "std"))]
pub mod srs;

// zkVM version of poly module - uses bls12_381 crate (accelerated in RISC Zero)
// This provides real KZG verification inside the zkVM guest
#[cfg(all(feature = "kzg", feature = "zkvm", not(feature = "std")))]
#[path = "poly_zkvm.rs"]
pub mod poly;

// Fallback stub for kzg without zkvm or std (shouldn't normally happen)
#[cfg(all(feature = "kzg", not(feature = "zkvm"), not(feature = "std")))]
pub mod poly {
    //! Stub poly module (no verification available)
    pub fn verify_row(_cells: &[[u8; 32]], _expected_commitment: &[u8; 48]) -> bool {
        // No verification available without std or zkvm
        panic!("KZG verification requires either std (blst) or zkvm (bls12_381) feature");
    }
}

#[cfg(all(feature = "kzg", feature = "std"))]
pub use kzg::{KzgCommitment, KzgProof, CellProof, KzgError};

#[cfg(all(feature = "kzg", feature = "std"))]
pub use srs::{SRS_POINT_COUNT, G1_COMPRESSED_SIZE};

pub mod trie;
pub use trie::{
    TrieNode, TrieProofStep, TrieProof, TrieError,
    SparseTrie, compute_trie_root, verify_trie_proof,
};

pub use error::CryptoError;
pub use hash::{sha256, ContentHash, HashAlgo};
