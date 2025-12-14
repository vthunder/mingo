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

#[cfg(feature = "kzg")]
pub mod kzg;

#[cfg(feature = "kzg")]
pub use kzg::{KzgCommitment, KzgProof, CellProof, KzgError};

pub mod merkle;
pub use merkle::{DataProof, MerkleError, compute_root};

pub use error::CryptoError;
pub use hash::{sha256, ContentHash, HashAlgo};
