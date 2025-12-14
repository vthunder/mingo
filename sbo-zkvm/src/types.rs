//! Types for zkVM proof input and output
//!
//! Placeholder - will be implemented in Task 2

use serde::{Serialize, Deserialize};

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    /// Previous block's state root (32 bytes)
    pub prev_state_root: [u8; 32],

    /// Block number being proven
    pub block_number: u64,

    /// Block hash (for header chain verification)
    pub block_hash: [u8; 32],

    /// Parent block hash
    pub parent_hash: [u8; 32],

    /// Raw SBO actions data
    pub actions_data: Vec<u8>,

    /// Previous proof's journal (for recursive verification)
    /// None for genesis proof
    pub prev_journal: Option<Vec<u8>>,
}

/// Output committed by the zkVM (the "journal")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockProofOutput {
    /// State root before this block
    pub prev_state_root: [u8; 32],

    /// State root after this block
    pub new_state_root: [u8; 32],

    /// Block number that was proven
    pub block_number: u64,

    /// Hash of the block that was proven
    pub block_hash: [u8; 32],

    /// Protocol version
    pub version: u32,
}

impl BlockProofOutput {
    /// Current protocol version
    pub const VERSION: u32 = 1;

    /// Empty state root (for genesis)
    pub const EMPTY_STATE_ROOT: [u8; 32] = [0u8; 32];
}
