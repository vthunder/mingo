//! ZK Proof Generation Module
//!
//! Generates validity proofs for batches of processed blocks.
//! Supports dev mode (fake proofs) and will integrate with RISC Zero zkVM.

use crate::config::ProverConfig;
use sbo_core::proof::{SbopMessage, serialize_sbop};
use sha2::{Sha256, Digest};

/// Receipt kinds for proof generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptKind {
    /// Composite receipt (default, fastest)
    Composite,
    /// Succinct receipt (compressed)
    Succinct,
    /// Groth16 SNARK (on-chain verifiable)
    Groth16,
}

impl ReceiptKind {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "succinct" => Self::Succinct,
            "groth16" => Self::Groth16,
            _ => Self::Composite,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Composite => "composite",
            Self::Succinct => "succinct",
            Self::Groth16 => "groth16",
        }
    }
}

/// Block batch for proof generation
#[derive(Debug, Clone)]
pub struct BlockBatch {
    /// Starting block number
    pub from_block: u64,
    /// Ending block number (inclusive)
    pub to_block: u64,
    /// State root before processing
    pub pre_state_root: [u8; 32],
    /// State root after processing
    pub post_state_root: [u8; 32],
    /// Serialized block data (all transactions)
    pub block_data: Vec<u8>,
}

/// Proof generation result
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// The generated proof receipt
    pub receipt: Vec<u8>,
    /// Receipt kind used
    pub receipt_kind: ReceiptKind,
    /// Block range
    pub from_block: u64,
    pub to_block: u64,
}

/// ZK Prover for generating validity proofs
pub struct Prover {
    config: ProverConfig,
    /// Pending blocks for batching
    pending_blocks: Vec<BlockBatch>,
}

impl Prover {
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
            pending_blocks: Vec::new(),
        }
    }

    /// Add a processed block to the pending batch
    pub fn add_block(
        &mut self,
        block_number: u64,
        pre_state_root: [u8; 32],
        post_state_root: [u8; 32],
        block_data: Vec<u8>,
    ) {
        let batch = BlockBatch {
            from_block: block_number,
            to_block: block_number,
            pre_state_root,
            post_state_root,
            block_data,
        };
        self.pending_blocks.push(batch);
    }

    /// Check if we have enough blocks to generate a proof
    pub fn should_prove(&self) -> bool {
        self.pending_blocks.len() as u64 >= self.config.batch_size
    }

    /// Generate a proof for pending blocks
    /// Returns None if not enough blocks, or proof generation failed
    pub fn generate_proof(&mut self) -> Option<ProofResult> {
        if !self.should_prove() {
            return None;
        }

        // Take batch_size blocks
        let batch_count = self.config.batch_size as usize;
        let blocks: Vec<_> = self.pending_blocks.drain(..batch_count).collect();

        if blocks.is_empty() {
            return None;
        }

        let from_block = blocks.first()?.from_block;
        let to_block = blocks.last()?.to_block;
        let pre_state_root = blocks.first()?.pre_state_root;
        let post_state_root = blocks.last()?.post_state_root;

        // Combine all block data
        let combined_data: Vec<u8> = blocks.iter()
            .flat_map(|b| b.block_data.iter().cloned())
            .collect();

        let receipt_kind = ReceiptKind::from_str(&self.config.receipt_kind);

        let receipt = if self.config.dev_mode {
            // Dev mode: generate fake proof
            self.generate_dev_receipt(
                from_block,
                to_block,
                &pre_state_root,
                &post_state_root,
                &combined_data,
            )
        } else {
            // Production mode: call zkVM (not yet implemented)
            tracing::warn!(
                "Production proof generation not yet implemented, using dev mode"
            );
            self.generate_dev_receipt(
                from_block,
                to_block,
                &pre_state_root,
                &post_state_root,
                &combined_data,
            )
        };

        Some(ProofResult {
            receipt,
            receipt_kind,
            from_block,
            to_block,
        })
    }

    /// Generate a fake proof for dev mode testing
    fn generate_dev_receipt(
        &self,
        from_block: u64,
        to_block: u64,
        pre_state_root: &[u8; 32],
        post_state_root: &[u8; 32],
        block_data: &[u8],
    ) -> Vec<u8> {
        // Dev mode receipt is a hash of all inputs
        // This allows testing the flow without real ZK proofs
        let mut hasher = Sha256::new();
        hasher.update(b"SBO_DEV_RECEIPT_V1");
        hasher.update(&from_block.to_le_bytes());
        hasher.update(&to_block.to_le_bytes());
        hasher.update(pre_state_root);
        hasher.update(post_state_root);
        hasher.update(block_data);

        let hash: [u8; 32] = hasher.finalize().into();

        // Fake receipt format: "DEV:" + hex hash
        let mut receipt = b"DEV:".to_vec();
        receipt.extend_from_slice(&hash);
        receipt
    }

    /// Create an SBOP message from a proof result
    pub fn create_sbop_message(&self, result: &ProofResult) -> Vec<u8> {
        let msg = SbopMessage {
            version: "0.1".to_string(),
            block_from: result.from_block,
            block_to: result.to_block,
            receipt_kind: result.receipt_kind.as_str().to_string(),
            receipt_bytes: result.receipt.clone(),
        };

        serialize_sbop(&msg)
    }

    /// Get pending block count
    pub fn pending_count(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Check if dev mode is enabled
    pub fn is_dev_mode(&self) -> bool {
        self.config.dev_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_batching() {
        let config = ProverConfig {
            enabled: true,
            batch_size: 3,
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        };

        let mut prover = Prover::new(config);

        // Add 2 blocks - shouldn't trigger proof
        prover.add_block(100, [0u8; 32], [1u8; 32], vec![1, 2, 3]);
        prover.add_block(101, [1u8; 32], [2u8; 32], vec![4, 5, 6]);
        assert!(!prover.should_prove());
        assert!(prover.generate_proof().is_none());

        // Add 3rd block - should trigger proof
        prover.add_block(102, [2u8; 32], [3u8; 32], vec![7, 8, 9]);
        assert!(prover.should_prove());

        let result = prover.generate_proof().unwrap();
        assert_eq!(result.from_block, 100);
        assert_eq!(result.to_block, 102);
        assert_eq!(result.receipt_kind, ReceiptKind::Composite);

        // Receipt should be DEV format
        assert!(result.receipt.starts_with(b"DEV:"));

        // Pending should be empty now
        assert_eq!(prover.pending_count(), 0);
    }

    #[test]
    fn test_sbop_message_creation() {
        let config = ProverConfig {
            enabled: true,
            batch_size: 1,
            receipt_kind: "succinct".to_string(),
            dev_mode: true,
        };

        let prover = Prover::new(config);

        let result = ProofResult {
            receipt: vec![1, 2, 3, 4],
            receipt_kind: ReceiptKind::Succinct,
            from_block: 100,
            to_block: 105,
        };

        let sbop_bytes = prover.create_sbop_message(&result);

        // Should be valid SBOP message
        assert!(sbo_core::proof::is_sbop_message(&sbop_bytes));

        // Parse and verify
        let parsed = sbo_core::proof::parse_sbop(&sbop_bytes).unwrap();
        assert_eq!(parsed.block_from, 100);
        assert_eq!(parsed.block_to, 105);
        assert_eq!(parsed.receipt_kind, "succinct");
    }

    #[test]
    fn test_receipt_kind_parsing() {
        assert_eq!(ReceiptKind::from_str("composite"), ReceiptKind::Composite);
        assert_eq!(ReceiptKind::from_str("Succinct"), ReceiptKind::Succinct);
        assert_eq!(ReceiptKind::from_str("GROTH16"), ReceiptKind::Groth16);
        assert_eq!(ReceiptKind::from_str("unknown"), ReceiptKind::Composite);
    }
}
