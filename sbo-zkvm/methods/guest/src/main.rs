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

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    pub prev_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub actions_data: Vec<u8>,
    pub prev_journal: Option<Vec<u8>>,
}

/// Output committed by the zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofOutput {
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub version: u32,
}

fn main() {
    // Read input from host
    let input: BlockProofInput = env::read();

    // Verify header chain (genesis vs continuation)
    if input.block_number == 0 {
        // Genesis block: no previous proof, state starts empty
        assert!(input.prev_journal.is_none(), "Genesis has no previous proof");
        assert_eq!(input.prev_state_root, [0u8; 32], "Genesis starts with empty state");
    } else {
        // Continuation: verify previous proof exists
        assert!(input.prev_journal.is_some(), "Non-genesis needs previous proof");

        // Decode previous output
        let prev_journal = input.prev_journal.as_ref().unwrap();
        let prev_output: BlockProofOutput = postcard::from_bytes(prev_journal)
            .expect("Invalid previous journal");

        // Verify header chain continuity
        assert_eq!(input.parent_hash, prev_output.block_hash, "Parent hash mismatch");
        assert_eq!(input.block_number, prev_output.block_number + 1, "Block number mismatch");
        assert_eq!(input.prev_state_root, prev_output.new_state_root, "State root mismatch");
    }

    // Process SBO actions (simplified for now - just hash the data)
    let new_state_root = compute_new_state_root(&input.prev_state_root, &input.actions_data);

    // Commit output
    let output = BlockProofOutput {
        prev_state_root: input.prev_state_root,
        new_state_root,
        block_number: input.block_number,
        block_hash: input.block_hash,
        version: 1,
    };

    env::commit(&output);
}

/// Compute new state root (simplified: SHA-256 of prev + actions)
fn compute_new_state_root(prev: &[u8; 32], actions: &[u8]) -> [u8; 32] {
    use sbo_crypto::sha256;

    let mut data = prev.to_vec();
    data.extend_from_slice(actions);
    sha256(&data)
}
