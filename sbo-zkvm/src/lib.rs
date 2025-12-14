//! SBO ZK Validity Proofs
//!
//! This crate provides proof generation and verification for SBO.

pub mod types;

#[cfg(feature = "prove")]
pub mod prover;

pub mod verifier;

pub use types::{
    BlockProofInput, BlockProofOutput,
    DataProof, CellProof, KzgCommitment, KzgProof,
    ReceiptKind,
};

#[cfg(feature = "prove")]
pub use prover::{
    prove_block, prove_genesis, prove_genesis_with_da,
    prove_continuation, prove_continuation_with_da,
    prove_chain, prove_block_groth16, compress_receipt,
    ProofReceipt, ProverError
};

pub use verifier::{
    verify_receipt, verify_block_proof, verify_block_proof_with_da,
    verify_proof_chain, get_receipt_kind, VerifierError
};
