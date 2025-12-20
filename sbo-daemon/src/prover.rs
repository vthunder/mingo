//! ZK Proof Generation Module
//!
//! Generates validity proofs for batches of processed blocks.
//! Supports dev mode (fake proofs) and will integrate with RISC Zero zkVM.

use crate::config::ProverConfig;
use sbo_core::proof::{SbopMessage, serialize_sbop};
use sbo_core::StateTransitionWitness;
use sha2::{Sha256, Digest};

#[cfg(feature = "zkvm")]
use sbo_zkvm::types::{HeaderData, RowData};

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
    /// Witness for state transition (creates, updates, deletes with proofs)
    pub state_witness: StateTransitionWitness,
    /// DA verification header data (optional, for zkVM proving)
    #[cfg(feature = "zkvm")]
    pub header_data: Option<HeaderData>,
    /// DA verification row data (optional, for zkVM proving)
    #[cfg(feature = "zkvm")]
    pub row_data: Vec<RowData>,
    /// Hash of raw cells for binding
    #[cfg(feature = "zkvm")]
    pub raw_cells_hash: [u8; 32],
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
    /// Pending blocks with state changes for batching
    pending_blocks: Vec<BlockBatch>,
    /// Block number when state first changed (for batch_size countdown)
    state_change_block: Option<u64>,
    /// Whether we've generated a proof yet (for bootstrap mode)
    first_proof_generated: bool,
}

impl Prover {
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
            pending_blocks: Vec::new(),
            state_change_block: None,
            first_proof_generated: false,
        }
    }

    /// Add a processed block to the pending batch (with DA data).
    /// Only blocks with state changes are queued for proving.
    #[cfg(feature = "zkvm")]
    pub fn add_block_with_da(
        &mut self,
        block_number: u64,
        pre_state_root: [u8; 32],
        post_state_root: [u8; 32],
        block_data: Vec<u8>,
        state_witness: StateTransitionWitness,
        header_data: Option<HeaderData>,
        row_data: Vec<RowData>,
        raw_cells_hash: [u8; 32],
    ) {
        // Only add if state actually changed
        if pre_state_root == post_state_root {
            return;
        }

        // Track when state first changed (for batch_size countdown)
        if self.state_change_block.is_none() {
            self.state_change_block = Some(block_number);
        }

        let batch = BlockBatch {
            from_block: block_number,
            to_block: block_number,
            pre_state_root,
            post_state_root,
            block_data,
            state_witness,
            header_data,
            row_data,
            raw_cells_hash,
        };
        self.pending_blocks.push(batch);
    }

    /// Add a processed block to the pending batch (without DA data).
    pub fn add_block(
        &mut self,
        block_number: u64,
        pre_state_root: [u8; 32],
        post_state_root: [u8; 32],
        block_data: Vec<u8>,
        state_witness: StateTransitionWitness,
    ) {
        // Only add if state actually changed
        if pre_state_root == post_state_root {
            return;
        }

        if self.state_change_block.is_none() {
            self.state_change_block = Some(block_number);
        }

        let batch = BlockBatch {
            from_block: block_number,
            to_block: block_number,
            pre_state_root,
            post_state_root,
            block_data,
            state_witness,
            #[cfg(feature = "zkvm")]
            header_data: None,
            #[cfg(feature = "zkvm")]
            row_data: Vec::new(),
            #[cfg(feature = "zkvm")]
            raw_cells_hash: [0u8; 32],
        };
        self.pending_blocks.push(batch);
    }

    /// Check if we should generate a proof.
    /// Proves when batch_size blocks have passed since the first state change.
    pub fn should_prove(&self, current_block: u64) -> bool {
        if self.pending_blocks.is_empty() {
            return false;
        }

        // Check if batch_size blocks have passed since state changed
        if let Some(change_block) = self.state_change_block {
            current_block >= change_block + self.config.batch_size
        } else {
            false
        }
    }

    /// Generate a proof for pending blocks
    /// Returns None if no pending state changes, or proof generation failed
    pub fn generate_proof(&mut self) -> Option<ProofResult> {
        if self.pending_blocks.is_empty() {
            return None;
        }

        // Take all pending blocks with state changes
        let blocks: Vec<_> = self.pending_blocks.drain(..).collect();

        // Reset state change tracking for next batch
        self.state_change_block = None;

        if blocks.is_empty() {
            return None;
        }

        let from_block = blocks.first()?.from_block;
        let to_block = blocks.last()?.to_block;
        let pre_state_root = blocks.first()?.pre_state_root;
        let post_state_root = blocks.last()?.post_state_root;

        // Merge all witnesses from all blocks in the batch
        let mut merged_witnesses = Vec::new();
        let mut merged_sibling_hints = Vec::new();
        for block in &blocks {
            merged_witnesses.extend(block.state_witness.witnesses.clone());
            merged_sibling_hints.extend(block.state_witness.sibling_hints.clone());
        }
        let state_witness = StateTransitionWitness {
            prev_state_root: pre_state_root,
            witnesses: merged_witnesses,
            sibling_hints: merged_sibling_hints,
        };

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
            // Production mode: call zkVM
            #[cfg(feature = "zkvm")]
            {
                match self.generate_zkvm_receipt(
                    &blocks,
                    from_block,
                    to_block,
                    &pre_state_root,
                    &post_state_root,
                    &combined_data,
                    &state_witness,
                    receipt_kind,
                ) {
                    Ok(receipt) => receipt,
                    Err(e) => {
                        tracing::error!("zkVM proof generation failed: {}", e);
                        return None;
                    }
                }
            }
            #[cfg(not(feature = "zkvm"))]
            {
                tracing::error!(
                    "zkVM feature not enabled. Build with --features zkvm for real proofs"
                );
                return None;
            }
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

    /// Generate a real zkVM proof
    #[cfg(feature = "zkvm")]
    fn generate_zkvm_receipt(
        &mut self,
        blocks: &[BlockBatch],
        from_block: u64,
        to_block: u64,
        pre_state_root: &[u8; 32],
        _post_state_root: &[u8; 32],
        block_data: &[u8],
        state_witness: &StateTransitionWitness,
        receipt_kind: ReceiptKind,
    ) -> Result<Vec<u8>, String> {
        use sbo_zkvm::{BlockProofInput, prove_block, compress_receipt};

        // Check if this is the first proof (bootstrap mode)
        let is_first_proof = !self.first_proof_generated;

        tracing::info!(
            "Generating zkVM proof for blocks {}-{} (kind: {:?}, first_proof: {}, witnesses: {})",
            from_block, to_block, receipt_kind, is_first_proof, state_witness.witnesses.len()
        );

        // Build block hash from data
        let mut hasher = Sha256::new();
        hasher.update(block_data);
        let block_hash: [u8; 32] = hasher.finalize().into();

        // Build parent hash (for now, just use pre_state_root as parent)
        let parent_hash = *pre_state_root;

        // Get DA data from first block (all blocks in batch should have same header_data for same block range)
        let header_data = blocks.first().and_then(|b| b.header_data.clone());
        let row_data = blocks.first().map(|b| b.row_data.clone()).unwrap_or_default();
        let raw_cells_hash = blocks.first().map(|b| b.raw_cells_hash).unwrap_or([0u8; 32]);

        let input = BlockProofInput {
            prev_state_root: *pre_state_root,
            block_number: from_block,
            block_hash,
            parent_hash,
            actions_data: block_data.to_vec(),
            prev_journal: None,
            prev_receipt_bytes: None,
            is_first_proof,  // Bootstrap mode for first proof
            state_witness: state_witness.clone(),
            header_data,  // Use DA data from block
            row_data,     // Use DA data from block
            raw_cells_hash,  // Use DA data from block
        };

        // Generate proof
        let proof_receipt = prove_block(input, None)
            .map_err(|e| format!("Proof generation failed: {}", e))?;

        // Mark that we've generated a proof
        self.first_proof_generated = true;

        tracing::info!(
            "Generated composite proof ({} bytes), state: {:?} -> {:?}",
            proof_receipt.receipt_bytes.len(),
            hex::encode(&proof_receipt.journal.prev_state_root[..4]),
            hex::encode(&proof_receipt.journal.new_state_root[..4])
        );

        // Compress if needed
        let final_receipt = match receipt_kind {
            ReceiptKind::Composite => proof_receipt,
            ReceiptKind::Succinct | ReceiptKind::Groth16 => {
                let target = match receipt_kind {
                    ReceiptKind::Succinct => sbo_zkvm::ReceiptKind::Succinct,
                    ReceiptKind::Groth16 => sbo_zkvm::ReceiptKind::Groth16,
                    _ => unreachable!(),
                };
                tracing::info!("Compressing to {:?}...", receipt_kind);
                compress_receipt(&proof_receipt, target)
                    .map_err(|e| format!("Compression failed: {}", e))?
            }
        };

        tracing::info!(
            "Final proof: {} bytes ({:?})",
            final_receipt.receipt_bytes.len(),
            receipt_kind
        );

        Ok(final_receipt.receipt_bytes)
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
    fn test_prover_state_change_batching() {
        let config = ProverConfig {
            enabled: true,
            batch_size: 3, // Wait 3 blocks after state change
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        };

        let mut prover = Prover::new(config);

        // Block with state change at block 100
        prover.add_block(100, [0u8; 32], [1u8; 32], vec![1, 2, 3], StateTransitionWitness::default());

        // Not enough blocks passed yet (need 3 blocks after change)
        assert!(!prover.should_prove(100)); // Same block
        assert!(!prover.should_prove(101)); // 1 block later
        assert!(!prover.should_prove(102)); // 2 blocks later

        // Now 3 blocks have passed - should prove
        assert!(prover.should_prove(103));

        let result = prover.generate_proof().unwrap();
        assert_eq!(result.from_block, 100);
        assert_eq!(result.to_block, 100);
        assert_eq!(result.receipt_kind, ReceiptKind::Composite);

        // Receipt should be DEV format
        assert!(result.receipt.starts_with(b"DEV:"));

        // Pending should be empty now
        assert_eq!(prover.pending_count(), 0);

        // After proof, should not prove again until new state change
        assert!(!prover.should_prove(104));
    }

    #[test]
    fn test_prover_ignores_no_state_change() {
        let config = ProverConfig {
            enabled: true,
            batch_size: 1,
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        };

        let mut prover = Prover::new(config);

        // Block with NO state change (pre == post)
        prover.add_block(100, [0u8; 32], [0u8; 32], vec![1, 2, 3], StateTransitionWitness::default());

        // Should not have any pending blocks
        assert_eq!(prover.pending_count(), 0);
        assert!(!prover.should_prove(101));
    }

    #[test]
    fn test_prover_multiple_changes_batched() {
        let config = ProverConfig {
            enabled: true,
            batch_size: 2, // Wait 2 blocks after first state change
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        };

        let mut prover = Prover::new(config);

        // Multiple state changes within batch window
        prover.add_block(100, [0u8; 32], [1u8; 32], vec![1, 2, 3], StateTransitionWitness::default());
        prover.add_block(101, [1u8; 32], [2u8; 32], vec![4, 5, 6], StateTransitionWitness::default());

        // 2 pending changes
        assert_eq!(prover.pending_count(), 2);

        // Should prove at block 102 (2 blocks after block 100)
        assert!(prover.should_prove(102));

        let result = prover.generate_proof().unwrap();
        // All changes are batched into one proof
        assert_eq!(result.from_block, 100);
        assert_eq!(result.to_block, 101);
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

    #[test]
    fn test_prover_with_da_data_dev_mode() {
        use sbo_core::StateTransitionWitness;

        let config = ProverConfig {
            enabled: true,
            batch_size: 1,
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        };

        let mut prover = Prover::new(config);

        // Block with state change
        let pre_state = [0u8; 32];
        let post_state = [1u8; 32];
        let block_data = vec![1, 2, 3, 4, 5];

        // Add block without DA data (basic path)
        prover.add_block(
            100,
            pre_state,
            post_state,
            block_data.clone(),
            StateTransitionWitness::default(),
        );

        // Should prove after batch_size blocks
        assert!(prover.should_prove(101));

        let result = prover.generate_proof().unwrap();
        assert_eq!(result.from_block, 100);
        assert_eq!(result.to_block, 100);

        // Dev mode receipt should start with "DEV:"
        assert!(result.receipt.starts_with(b"DEV:"));

        // Receipt should be reproducible (same inputs = same output)
        let mut prover2 = Prover::new(ProverConfig {
            enabled: true,
            batch_size: 1,
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        });

        prover2.add_block(
            100,
            pre_state,
            post_state,
            block_data,
            StateTransitionWitness::default(),
        );

        let result2 = prover2.generate_proof().unwrap();
        assert_eq!(result.receipt, result2.receipt);
    }

    #[cfg(feature = "zkvm")]
    #[test]
    fn test_prover_with_da_data_full() {
        use sbo_core::StateTransitionWitness;
        use sbo_zkvm::types::{HeaderData, RowData, AppLookup, AppLookupEntry};

        let config = ProverConfig {
            enabled: true,
            batch_size: 1,
            receipt_kind: "composite".to_string(),
            dev_mode: true, // Still use dev mode to avoid slow zkVM
        };

        let mut prover = Prover::new(config);

        // Create mock DA data
        let header_data = HeaderData {
            block_number: 100,
            header_hash: [1u8; 32],
            parent_hash: [2u8; 32],
            state_root: [3u8; 32],
            extrinsics_root: [4u8; 32],
            data_root: [5u8; 32],
            row_commitments: vec![0u8; 48], // One row commitment
            rows: 1,
            cols: 64,
            app_lookup: AppLookup {
                size: 64,
                index: vec![AppLookupEntry { app_id: 506, start: 0 }],
            },
            app_id: 506,
        };

        let row_data = vec![RowData {
            row: 0,
            cells: vec![[0u8; 32]; 64],
        }];

        // Compute raw cells hash
        let mut all_cells = Vec::new();
        for row in &row_data {
            for cell in &row.cells {
                all_cells.extend_from_slice(cell);
            }
        }
        let raw_cells_hash: [u8; 32] = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&all_cells);
            hasher.finalize().into()
        };

        // Add block with DA data
        prover.add_block_with_da(
            100,
            [0u8; 32],
            [1u8; 32],
            vec![1, 2, 3, 4],
            StateTransitionWitness::default(),
            Some(header_data),
            row_data,
            raw_cells_hash,
        );

        assert!(prover.should_prove(101));

        let result = prover.generate_proof().unwrap();
        assert_eq!(result.from_block, 100);
        assert!(result.receipt.starts_with(b"DEV:"));
    }

    #[test]
    fn test_sbop_message_with_da_proof() {
        let config = ProverConfig {
            enabled: true,
            batch_size: 1,
            receipt_kind: "composite".to_string(),
            dev_mode: true,
        };

        let prover = Prover::new(config);

        // Create a proof result
        let result = ProofResult {
            receipt: b"DEV:test_receipt_data".to_vec(),
            receipt_kind: ReceiptKind::Composite,
            from_block: 100,
            to_block: 110,
        };

        let sbop_bytes = prover.create_sbop_message(&result);

        // Verify it's a valid SBOP message
        assert!(sbo_core::proof::is_sbop_message(&sbop_bytes));

        // Parse and verify contents
        let parsed = sbo_core::proof::parse_sbop(&sbop_bytes).unwrap();
        assert_eq!(parsed.block_from, 100);
        assert_eq!(parsed.block_to, 110);
        assert_eq!(parsed.receipt_kind, "composite");
        assert_eq!(parsed.receipt_bytes, b"DEV:test_receipt_data".to_vec());
    }
}
