//! SBO ZK Validity Proofs
//!
//! This crate provides proof generation and verification for SBO.

pub mod types;

#[cfg(feature = "prove")]
pub mod prover;

pub mod verifier;

pub use types::{BlockProofInput, BlockProofOutput};

#[cfg(feature = "prove")]
pub use prover::{prove_block, prove_genesis, prove_continuation, ProofReceipt, ProverError};

pub use verifier::{verify_receipt, verify_block_proof, verify_proof_chain, VerifierError};
