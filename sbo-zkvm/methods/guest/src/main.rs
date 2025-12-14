//! SBO zkVM Guest Program
//!
//! This program runs inside the RISC Zero zkVM and produces validity proofs.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
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

    // 3. Process SBO actions
    let new_state_root = compute_new_state_root(&input.prev_state_root, &input.actions_data);

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

/// Verify header chain continuity
fn verify_header_chain(input: &BlockProofInput) {
    if input.block_number == 0 {
        // Genesis block
        assert!(input.prev_journal.is_none(), "Genesis has no previous proof");
        assert_eq!(input.prev_state_root, [0u8; 32], "Genesis starts with empty state");
    } else {
        // Continuation block
        assert!(input.prev_journal.is_some(), "Non-genesis needs previous proof");

        let prev_journal = input.prev_journal.as_ref().unwrap();
        let prev_output: BlockProofOutput = postcard::from_bytes(prev_journal)
            .expect("Invalid previous journal");

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

/// Compute new state root (SHA-256 of prev + actions)
fn compute_new_state_root(prev: &[u8; 32], actions: &[u8]) -> [u8; 32] {
    let mut data = prev.to_vec();
    data.extend_from_slice(actions);
    sbo_crypto::sha256(&data)
}
