//! Merkle proof verification for Avail data proofs
//!
//! Avail uses a binary merkle tree for data_root

extern crate alloc;

use alloc::vec::Vec;
use crate::sha256;

/// Calculate ceil(log2(n)) without floating point
fn log2_ceil(n: u32) -> usize {
    if n == 0 {
        return 0;
    }
    let mut bits = 32 - n.leading_zeros() as usize;
    // If n is not a power of 2, we need one more level
    if n & (n - 1) != 0 {
        bits
    } else {
        bits - 1
    }
}

/// Merkle proof for data inclusion
#[derive(Debug, Clone)]
pub struct DataProof {
    /// Root hashes: (data_root, blob_root, bridge_root)
    pub data_root: [u8; 32],

    /// Proof elements (sibling hashes)
    pub proof: Vec<[u8; 32]>,

    /// Total number of leaves
    pub number_of_leaves: u32,

    /// Index of the leaf being proven
    pub leaf_index: u32,

    /// The leaf value
    pub leaf: [u8; 32],
}

/// Error type for merkle operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    InvalidProofLength,
    InvalidLeafIndex,
    RootMismatch,
}

impl core::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofLength => write!(f, "Invalid proof length"),
            Self::InvalidLeafIndex => write!(f, "Invalid leaf index"),
            Self::RootMismatch => write!(f, "Merkle root mismatch"),
        }
    }
}

impl DataProof {
    /// Verify this merkle proof against data_root
    pub fn verify(&self) -> Result<bool, MerkleError> {
        if self.leaf_index >= self.number_of_leaves {
            return Err(MerkleError::InvalidLeafIndex);
        }

        let expected_depth = log2_ceil(self.number_of_leaves);
        if self.proof.len() != expected_depth {
            return Err(MerkleError::InvalidProofLength);
        }

        let mut current = self.leaf;
        let mut index = self.leaf_index;

        for sibling in &self.proof {
            current = if index % 2 == 0 {
                // Current is left child
                hash_pair(&current, sibling)
            } else {
                // Current is right child
                hash_pair(sibling, &current)
            };
            index /= 2;
        }

        if current == self.data_root {
            Ok(true)
        } else {
            Err(MerkleError::RootMismatch)
        }
    }
}

/// Hash two nodes together (standard merkle)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

/// Compute merkle root from leaves
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number: promote single node
                chunk[0]
            };
            next_level.push(hash);
        }

        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
#[path = "merkle_tests.rs"]
mod tests;
