//! Block indexer

use crate::error::SboError;
use crate::state::StateDb;

/// Block indexer that processes DA layer blocks
pub struct Indexer {
    #[allow(dead_code)]
    state: StateDb,
}

impl Indexer {
    /// Create a new indexer with the given state database
    pub fn new(state: StateDb) -> Self {
        Self { state }
    }

    /// Process a single block
    pub fn process_block(&mut self, _block_number: u64, _transactions: Vec<Vec<u8>>) -> Result<(), SboError> {
        todo!("Implement block processing")
    }
}
