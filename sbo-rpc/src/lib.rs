//! SBO RPC client and Avail data matrix decoding
//!
//! This crate provides functionality to:
//! - Connect to Avail RPC nodes
//! - Fetch data from the Kate data matrix
//! - Decode application data from matrix cells
//!
//! # Matrix Data Format
//!
//! Per avail-core kate/recovery, the data matrix contains:
//! - SCALE-encoded `Vec<Vec<u8>>` where each inner `Vec<u8>` is one raw encoded extrinsic
//! - Reference: https://github.com/availproject/avail-core/blob/main/kate/recovery/src/com.rs

mod client;
mod decode;
mod error;

pub use client::{RpcClient, RpcConfig};
pub use decode::{
    decode_app_data_from_rows,
    decode_app_extrinsics,
    extract_data_from_encoded_extrinsic,
    decode_compact,
    unpad_iec_9797_1,
    CHUNK_SIZE,
    DATA_CHUNK_SIZE,
};
pub use error::{Error, Result};

/// Transaction data from a block
#[derive(Debug, Clone)]
pub struct BlockData {
    pub block_number: u64,
    pub transactions: Vec<AppTransaction>,
}

/// A transaction for a specific app_id
#[derive(Debug, Clone)]
pub struct AppTransaction {
    pub app_id: u32,
    pub index: u32,
    pub data: Vec<u8>,
}
