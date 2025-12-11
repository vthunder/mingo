//! SBO Avail DA Layer Integration
//!
//! Provides connectivity to the Avail data availability layer
//! using the light client in app mode.

mod client;
mod blocks;
mod submit;

pub use client::{AvailClient, AvailConfig};
pub use blocks::{Block, Transaction};
pub use submit::SubmitResult;

use thiserror::Error;

/// DA layer abstraction trait
pub trait DataAvailability {
    /// Stream blocks from a given height
    fn stream_blocks(&self, from: u64) -> impl futures::Stream<Item = Block> + Send;

    /// Submit data to the DA layer
    fn submit(&self, data: &[u8]) -> impl std::future::Future<Output = Result<SubmitResult, DaError>> + Send;

    /// Get a specific block
    fn get_block(&self, number: u64) -> impl std::future::Future<Output = Result<Option<Block>, DaError>> + Send;
}

#[derive(Debug, Error)]
pub enum DaError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Submission failed: {0}")]
    Submission(String),

    #[error("Block not found: {0}")]
    BlockNotFound(u64),

    #[error("Light client error: {0}")]
    LightClient(String),
}
