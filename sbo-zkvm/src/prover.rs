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
#[derive(Clone)]
pub struct ProofReceipt {
    /// The verified output (journal)
    pub journal: BlockProofOutput,

    /// Raw receipt bytes (for transmission)
    pub receipt_bytes: Vec<u8>,

    /// Kind of receipt (affects size)
    pub kind: crate::types::ReceiptKind,
}

/// Generate a proof for a block with optional recursive verification
#[cfg(feature = "prove")]
pub fn prove_block(input: BlockProofInput, prev_receipt: Option<&[u8]>) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

    // Build executor environment
    let mut env_builder = ExecutorEnv::builder();

    // Write input
    env_builder
        .write(&input)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    // Add assumption for previous receipt (if continuation block)
    if let Some(receipt_bytes) = prev_receipt {
        let prev_receipt: Receipt = postcard::from_bytes(receipt_bytes)
            .map_err(|e| ProverError::SerializationError(format!("Invalid previous receipt: {}", e)))?;
        env_builder.add_assumption(prev_receipt);
    }

    let env = env_builder
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
        kind: crate::types::ReceiptKind::Composite,
    })
}

/// Generate genesis proof (block 0) - no recursion needed
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
        prev_receipt_bytes: None,
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input, None)
}

/// Generate genesis proof with DA verification - no recursion needed
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
        prev_receipt_bytes: None,
        data_proof: Some(data_proof),
        row_commitments,
        cell_proofs,
        grid_cols,
    };

    prove_block(input, None)
}

/// Generate continuation proof (block N > 0) with recursive verification
#[cfg(feature = "prove")]
pub fn prove_continuation(
    prev_receipt_bytes: &[u8],
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::Receipt;

    // Decode previous receipt to get journal
    let prev_receipt: Receipt = postcard::from_bytes(prev_receipt_bytes)
        .map_err(|e| ProverError::SerializationError(format!("Invalid previous receipt: {}", e)))?;

    let prev_journal = prev_receipt.journal.bytes.clone();
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        prev_receipt_bytes: Some(prev_receipt_bytes.to_vec()),
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input, Some(prev_receipt_bytes))
}

/// Generate continuation proof with DA verification and recursive verification
#[cfg(feature = "prove")]
pub fn prove_continuation_with_da(
    prev_receipt_bytes: &[u8],
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
    data_proof: DataProof,
    row_commitments: Vec<KzgCommitment>,
    cell_proofs: Vec<CellProof>,
    grid_cols: u32,
) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::Receipt;

    // Decode previous receipt to get journal
    let prev_receipt: Receipt = postcard::from_bytes(prev_receipt_bytes)
        .map_err(|e| ProverError::SerializationError(format!("Invalid previous receipt: {}", e)))?;

    let prev_journal = prev_receipt.journal.bytes.clone();
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        prev_receipt_bytes: Some(prev_receipt_bytes.to_vec()),
        data_proof: Some(data_proof),
        row_commitments,
        cell_proofs,
        grid_cols,
    };

    prove_block(input, Some(prev_receipt_bytes))
}

/// Prove an entire chain of blocks from genesis
///
/// Takes a list of (block_hash, parent_hash, actions) tuples.
/// Returns the final receipt that proves the entire chain.
#[cfg(feature = "prove")]
pub fn prove_chain(
    blocks: Vec<([u8; 32], [u8; 32], Vec<u8>)>,
) -> Result<ProofReceipt, ProverError> {
    if blocks.is_empty() {
        return Err(ProverError::InvalidInput("Empty block list".to_string()));
    }

    // Prove genesis
    let (genesis_hash, _, genesis_actions) = &blocks[0];
    let mut current_receipt = prove_genesis(*genesis_hash, genesis_actions.clone())?;

    // Prove each continuation block
    for (i, (block_hash, parent_hash, actions)) in blocks.iter().enumerate().skip(1) {
        current_receipt = prove_continuation(
            &current_receipt.receipt_bytes,
            i as u64,
            *block_hash,
            *parent_hash,
            actions.clone(),
        )?;
    }

    Ok(current_receipt)
}
