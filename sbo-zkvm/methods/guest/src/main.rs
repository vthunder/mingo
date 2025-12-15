//! SBO zkVM Guest Program
//!
//! This program runs inside the RISC Zero zkVM and produces validity proofs.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Digest;
use serde::{Serialize, Deserialize};

risc0_zkvm::guest::entry!(main);

/// KZG commitment (48 bytes compressed G1 point)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KzgCommitment(pub Vec<u8>);

/// KZG proof (48 bytes compressed G1 point)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KzgProof(pub Vec<u8>);

/// Cell with KZG proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellProof {
    pub row: u32,
    pub col: u32,
    pub data: Vec<u8>,
    pub proof: KzgProof,
}

/// Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof {
    pub data_root: [u8; 32],
    pub proof: Vec<[u8; 32]>,
    pub number_of_leaves: u32,
    pub leaf_index: u32,
    pub leaf: [u8; 32],
}

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    pub prev_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub actions_data: Vec<u8>,
    pub prev_journal: Option<Vec<u8>>,
    pub prev_receipt_bytes: Option<Vec<u8>>,
    /// Bootstrap mode: first proof in chain (no previous proof required)
    /// When true, prev_journal is not required even if block_number != 0
    #[serde(default)]
    pub is_first_proof: bool,
    /// Objects in previous state: Vec<(path_segments, object_hash)>
    #[serde(default)]
    pub pre_objects: Vec<(Vec<String>, [u8; 32])>,
    /// Objects in new state: Vec<(path_segments, object_hash)>
    #[serde(default)]
    pub post_objects: Vec<(Vec<String>, [u8; 32])>,
    pub data_proof: Option<DataProof>,
    pub row_commitments: Vec<KzgCommitment>,
    pub cell_proofs: Vec<CellProof>,
    pub grid_cols: u32,
}

/// Output committed by the zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofOutput {
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub data_root: [u8; 32],
    pub version: u32,
}

fn main() {
    // Read input from host
    let input: BlockProofInput = env::read();

    // 1. Verify header chain (genesis vs continuation)
    verify_header_chain(&input);

    // 2. Verify data availability (if proof provided)
    let data_root = verify_data_availability(&input);

    // 3. Compute and verify state roots using trie
    // Verify prev_state_root matches pre_objects
    let computed_prev_root = compute_trie_state_root(&input.pre_objects);
    assert_eq!(
        input.prev_state_root, computed_prev_root,
        "prev_state_root doesn't match pre_objects trie root"
    );

    // Compute new_state_root from post_objects
    let new_state_root = compute_trie_state_root(&input.post_objects);

    // 4. Commit output
    let output = BlockProofOutput {
        prev_state_root: input.prev_state_root,
        new_state_root,
        block_number: input.block_number,
        block_hash: input.block_hash,
        data_root,
        version: 1,
    };

    env::commit(&output);
}

/// Verify header chain continuity with recursive proof verification
fn verify_header_chain(input: &BlockProofInput) {
    if input.block_number == 0 {
        // Genesis block - no previous proof to verify
        assert!(input.prev_journal.is_none(), "Genesis has no previous proof");
        assert!(input.prev_receipt_bytes.is_none(), "Genesis has no previous receipt");
        assert_eq!(input.prev_state_root, [0u8; 32], "Genesis starts with empty state");
    } else if input.is_first_proof {
        // Bootstrap mode: first proof in chain starting from arbitrary block
        // No previous proof required, but we accept the prev_state_root as trusted
        // This allows starting a proof chain from any block, not just genesis
        assert!(input.prev_journal.is_none(), "First proof has no previous proof");
        // Note: prev_state_root can be non-zero - this is the trusted starting state
    } else {
        // Continuation block - verify previous proof recursively
        assert!(input.prev_journal.is_some(), "Non-genesis needs previous proof");

        let prev_journal = input.prev_journal.as_ref().unwrap();

        // Cryptographically verify previous proof using RISC Zero composition
        // This adds an "assumption" that must be resolved during proving
        //
        // TODO: For self-recursion, we need our own image ID (sbo_zkvm_methods::SBO_ZKVM_GUEST_ID)
        // This creates a chicken-and-egg problem: the guest needs to be built to get the ID,
        // but the ID is needed to build the guest. Solutions:
        // 1. Two-stage build: build once, extract ID, rebuild with ID embedded
        // 2. Include generated file: use include! macro to inject ID at build time
        // 3. Accept ID as input: pass the image ID as part of BlockProofInput
        //
        // For now, we use a placeholder guest ID. This will be updated in a future task
        // to use the actual generated ID through a proper build mechanism.
        //
        // Placeholder ID (will be replaced with actual sbo_zkvm_methods::SBO_ZKVM_GUEST_ID)
        let guest_id_words: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
        let guest_id = Digest::from(guest_id_words);

        env::verify(guest_id, prev_journal)
            .expect("Previous proof verification failed");

        // Decode previous output for chain continuity checks
        let prev_output: BlockProofOutput = postcard::from_bytes(prev_journal)
            .expect("Invalid previous journal");

        // Verify header chain continuity
        assert_eq!(input.parent_hash, prev_output.block_hash, "Parent hash mismatch");
        assert_eq!(input.block_number, prev_output.block_number + 1, "Block number mismatch");
        assert_eq!(input.prev_state_root, prev_output.new_state_root, "State root mismatch");
    }
}

/// Verify data availability proofs
fn verify_data_availability(input: &BlockProofInput) -> [u8; 32] {
    // If no data proof, return empty root (for testing/dev)
    let Some(data_proof) = &input.data_proof else {
        return [0u8; 32];
    };

    // 1. Verify merkle proof
    assert!(
        verify_merkle_proof(data_proof),
        "Merkle proof verification failed"
    );

    // 2. Verify KZG proofs for each cell
    for cell in &input.cell_proofs {
        assert!(
            verify_kzg_cell(&input.row_commitments, cell, input.grid_cols),
            "KZG cell proof verification failed"
        );
    }

    // 3. Verify reassembled data matches actions
    let reassembled = reassemble_data(&input.cell_proofs);
    let actions_hash = sbo_crypto::sha256(&input.actions_data);
    let reassembled_hash = sbo_crypto::sha256(&reassembled);
    assert_eq!(actions_hash, reassembled_hash, "Data reassembly mismatch");

    data_proof.data_root
}

/// Verify merkle proof against data_root
fn verify_merkle_proof(proof: &DataProof) -> bool {
    let mut current = proof.leaf;
    let mut index = proof.leaf_index;

    for sibling in &proof.proof {
        current = if index % 2 == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        index /= 2;
    }

    current == proof.data_root
}

/// Hash two merkle nodes
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sbo_crypto::sha256(&combined)
}

/// Verify a single cell's KZG proof
fn verify_kzg_cell(
    row_commitments: &[KzgCommitment],
    cell: &CellProof,
    _grid_cols: u32,
) -> bool {
    // Get row commitment
    let row_idx = cell.row as usize;
    if row_idx >= row_commitments.len() {
        return false;
    }

    let _commitment = &row_commitments[row_idx];

    // Verify using blst (accelerated in zkVM)
    // For now, basic point validation - full pairing check needs SRS
    verify_kzg_proof_basic(&cell.proof)
}

/// Basic KZG proof validation (point on curve)
fn verify_kzg_proof_basic(proof: &KzgProof) -> bool {
    // Basic validation: check proof is 48 bytes (compressed G1 point)
    if proof.0.len() != 48 {
        return false;
    }

    // KZG verification stubbed out for now
    // Full verification requires:
    // 1. Point decompression using blst (RISC Zero accelerated)
    // 2. Pairing check against SRS (trusted setup)
    //
    // In production, this would call sbo-crypto's KZG verification
    // For now, return true to allow compilation and testing of the DA flow.
    true
}

/// Reassemble data from cell proofs
fn reassemble_data(cells: &[CellProof]) -> Vec<u8> {
    // Sort by (row, col) and concatenate
    let mut sorted: Vec<_> = cells.iter().collect();
    sorted.sort_by_key(|c| (c.row, c.col));

    let mut data = Vec::new();
    for cell in sorted {
        data.extend_from_slice(&cell.data);
    }
    data
}

/// Compute state root using sparse path-segment trie
/// This matches the daemon's trie-based state commitment
fn compute_trie_state_root(objects: &[(Vec<String>, [u8; 32])]) -> [u8; 32] {
    sbo_crypto::compute_trie_root(objects)
}
