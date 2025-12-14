//! Proof generation for SBO blocks

use crate::types::{BlockProofInput, BlockProofOutput, DataProof, CellProof, KzgCommitment};
use sbo_zkvm_methods::SBO_ZKVM_GUEST_ELF;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Receipt containing proof and journal
pub struct ProofReceipt {
    /// The verified output (journal)
    pub journal: BlockProofOutput,

    /// Raw receipt bytes (for transmission)
    pub receipt_bytes: Vec<u8>,
}

/// Generate a proof for a block
#[cfg(feature = "prove")]
pub fn prove_block(input: BlockProofInput) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::{default_prover, ExecutorEnv};

    // Build executor environment
    let env = ExecutorEnv::builder()
        .write(&input)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?
        .build()
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?;

    // Get prover and generate proof
    let prover = default_prover();
    let receipt = prover
        .prove(env, SBO_ZKVM_GUEST_ELF)
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?
        .receipt;

    // Decode journal using postcard (same as guest)
    let journal: BlockProofOutput = receipt
        .journal
        .decode()
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    // Serialize receipt using postcard for consistency
    let receipt_bytes = postcard::to_allocvec(&receipt)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    Ok(ProofReceipt {
        journal,
        receipt_bytes,
    })
}

/// Generate genesis proof (block 0) without DA
#[cfg(feature = "prove")]
pub fn prove_genesis(
    block_hash: [u8; 32],
    genesis_actions: Vec<u8>,
) -> Result<ProofReceipt, ProverError> {
    let input = BlockProofInput {
        prev_state_root: [0u8; 32],
        block_number: 0,
        block_hash,
        parent_hash: [0u8; 32],
        actions_data: genesis_actions,
        prev_journal: None,
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input)
}

/// Generate genesis proof with DA verification
#[cfg(feature = "prove")]
pub fn prove_genesis_with_da(
    block_hash: [u8; 32],
    genesis_actions: Vec<u8>,
    data_proof: DataProof,
    row_commitments: Vec<KzgCommitment>,
    cell_proofs: Vec<CellProof>,
    grid_cols: u32,
) -> Result<ProofReceipt, ProverError> {
    let input = BlockProofInput {
        prev_state_root: [0u8; 32],
        block_number: 0,
        block_hash,
        parent_hash: [0u8; 32],
        actions_data: genesis_actions,
        prev_journal: None,
        data_proof: Some(data_proof),
        row_commitments,
        cell_proofs,
        grid_cols,
    };

    prove_block(input)
}

/// Generate continuation proof (block N > 0)
#[cfg(feature = "prove")]
pub fn prove_continuation(
    prev_journal: Vec<u8>,
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
) -> Result<ProofReceipt, ProverError> {
    // Decode previous output to get state root
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input)
}

/// Generate continuation proof with DA verification
#[cfg(feature = "prove")]
pub fn prove_continuation_with_da(
    prev_journal: Vec<u8>,
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
    data_proof: DataProof,
    row_commitments: Vec<KzgCommitment>,
    cell_proofs: Vec<CellProof>,
    grid_cols: u32,
) -> Result<ProofReceipt, ProverError> {
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        data_proof: Some(data_proof),
        row_commitments,
        cell_proofs,
        grid_cols,
    };

    prove_block(input)
}
