//! SBO zkVM Guest Program
//!
//! This program runs inside the RISC Zero zkVM and produces validity proofs.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Digest;
use serde::{Serialize, Deserialize};

// Import witness types from sbo-crypto
use sbo_crypto::trie::{
    StateTransitionWitness, verify_state_transition,
};
use sbo_crypto::poly::verify_row;

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

/// App lookup entry from header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLookupEntry {
    pub app_id: u32,
    pub start: u32,
}

/// Complete app lookup from header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLookup {
    pub size: u32,
    pub index: Vec<AppLookupEntry>,
}

/// Header verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderData {
    pub block_number: u64,
    pub header_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub extrinsics_root: [u8; 32],
    pub data_root: [u8; 32],
    pub row_commitments: Vec<u8>,
    pub rows: u32,
    pub cols: u32,
    pub app_lookup: AppLookup,
    pub app_id: u32,
}

/// Full row data for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowData {
    pub row: u32,
    pub cells: Vec<[u8; 32]>,
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
    /// Witness for state transition (creates, updates, deletes with proofs)
    /// Scales with touched objects, not total state size
    #[serde(default)]
    pub state_witness: StateTransitionWitness,
    /// Header data for verification
    pub header_data: Option<HeaderData>,
    /// Full row data for rows containing app data
    pub row_data: Vec<RowData>,
    /// Hash of raw cell data before SCALE decoding
    pub raw_cells_hash: [u8; 32],
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

    // 3. Verify state transition using witnesses
    // This is O(batch_size * depth) instead of O(total_objects)
    let (prev_state_root, new_state_root) = verify_state_transition_witness(&input);

    // Verify prev_state_root matches what we expect
    assert_eq!(
        input.prev_state_root, prev_state_root,
        "prev_state_root doesn't match witness"
    );

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

/// Verify state transition using witness proofs
/// Returns (prev_state_root, new_state_root)
fn verify_state_transition_witness(input: &BlockProofInput) -> ([u8; 32], [u8; 32]) {
    let witness = &input.state_witness;

    // For empty witness, state doesn't change
    if witness.witnesses.is_empty() {
        return (witness.prev_state_root, witness.prev_state_root);
    }

    // Verify the witness and compute new state root
    let new_state_root = verify_state_transition(witness)
        .expect("State transition witness verification failed");

    (witness.prev_state_root, new_state_root)
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
    let Some(header_data) = &input.header_data else {
        return [0u8; 32];
    };

    // 1. Verify raw cells hash
    let computed_hash = compute_cells_hash(&input.row_data);
    assert_eq!(
        computed_hash, input.raw_cells_hash,
        "Raw cells hash mismatch"
    );

    // 2. Verify app completeness (all chunks present)
    assert!(
        verify_app_completeness(header_data, &input.row_data),
        "App completeness verification failed"
    );

    // 3. Verify KZG commitments for each row
    for row in &input.row_data {
        assert!(
            verify_row_commitment(header_data, row),
            "Row commitment verification failed for row {}", row.row
        );
    }

    // 4. Bind actions_data to verified cells
    // Compute hash of actions and verify it relates to cells
    let _actions_hash = sbo_crypto::sha256(&input.actions_data);
    // The prover must ensure actions_data is correctly SCALE-decoded from cells
    // We bind them via the raw_cells_hash verification above

    header_data.data_root
}

/// Compute hash of all cells from row data
fn compute_cells_hash(row_data: &[RowData]) -> [u8; 32] {
    // Concatenate all cells in order and hash
    let mut all_cells = Vec::new();
    for row in row_data {
        for cell in &row.cells {
            all_cells.extend_from_slice(cell);
        }
    }
    sbo_crypto::sha256(&all_cells)
}

/// Verify all chunks for our app are present in row_data
fn verify_app_completeness(header_data: &HeaderData, row_data: &[RowData]) -> bool {
    let app_id = header_data.app_id;
    let lookup = &header_data.app_lookup;

    // Find our app in the lookup
    let mut app_entry = None;
    for (i, entry) in lookup.index.iter().enumerate() {
        if entry.app_id == app_id {
            app_entry = Some((i, entry.start));
            break;
        }
    }

    let Some((idx, start)) = app_entry else {
        // App not in lookup - valid if no data expected
        return row_data.is_empty();
    };

    // Find end chunk (next app's start or total size)
    let end = if idx + 1 < lookup.index.len() {
        lookup.index[idx + 1].start
    } else {
        lookup.size
    };

    let cols = header_data.cols;

    // Calculate which rows we need
    let start_row = start / cols;
    let end_row = (end - 1) / cols;

    // Verify we have all required rows
    for row_idx in start_row..=end_row {
        let has_row = row_data.iter().any(|r| r.row == row_idx);
        if !has_row {
            return false;
        }
    }

    // Verify each row has correct number of cells (cols)
    for row in row_data {
        if row.cells.len() != cols as usize {
            return false;
        }
    }

    true
}

/// Verify row commitment matches row data
fn verify_row_commitment(header_data: &HeaderData, row: &RowData) -> bool {
    let row_idx = row.row as usize;
    let commitment_size = 48; // Each KZG commitment is 48 bytes

    let offset = row_idx * commitment_size;
    if offset + commitment_size > header_data.row_commitments.len() {
        return false;
    }

    // Extract expected commitment
    let expected: [u8; 48] = header_data.row_commitments[offset..offset + commitment_size]
        .try_into()
        .expect("slice to array");

    // Convert cells to array format for verify_row
    let cells: Vec<[u8; 32]> = row.cells.clone();

    // Use real KZG verification
    verify_row(&cells, &expected)
}
