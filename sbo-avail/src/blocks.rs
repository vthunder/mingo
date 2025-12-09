//! Block types

/// A block from the DA layer
#[derive(Debug, Clone)]
pub struct Block {
    /// Block number
    pub number: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// Transactions in this block (filtered by app_id)
    pub transactions: Vec<Transaction>,
}

/// A transaction from the DA layer
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction index in block
    pub index: u32,
    /// Raw transaction data
    pub data: Vec<u8>,
}
