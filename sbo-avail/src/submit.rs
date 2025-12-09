//! Data submission

/// Result of a data submission
#[derive(Debug, Clone)]
pub struct SubmitResult {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Block number (if confirmed)
    pub block_number: Option<u64>,
    /// Block hash (if confirmed)
    pub block_hash: Option<[u8; 32]>,
}
