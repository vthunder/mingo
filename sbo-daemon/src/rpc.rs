//! Avail RPC Client
//!
//! Fetches block data from Avail RPC nodes using avail-rust SDK.

use std::io::Read as _;
use crate::config::RpcConfig;
use avail_rust::{
    Client,
    EncodeSelector,
    ext::avail_rust_core::rpc::system::fetch_extrinsics::Options as RpcOptions,
};
use flate2::read::GzDecoder;

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

/// RPC client for fetching block data
pub struct RpcClient {
    config: RpcConfig,
    client: Option<Client>,
    verbose: bool,
}

impl RpcClient {
    pub fn new(config: RpcConfig, verbose: bool) -> Self {
        Self { config, client: None, verbose }
    }

    /// Connect to the RPC endpoint
    pub async fn connect(&mut self) -> crate::Result<()> {
        let endpoint = self.config.endpoints.first().ok_or_else(|| {
            crate::DaemonError::Rpc("No RPC endpoints configured".to_string())
        })?;

        if self.verbose {
            tracing::info!("Connecting to Avail RPC: {}", endpoint);
        }

        let client = Client::new(endpoint)
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("Failed to connect: {}", e)))?;

        self.client = Some(client);

        if self.verbose {
            tracing::info!("Connected to Avail RPC");
        }

        Ok(())
    }

    /// Get the client, connecting if needed
    async fn get_client(&mut self) -> crate::Result<&Client> {
        if self.client.is_none() {
            self.connect().await?;
        }
        self.client.as_ref().ok_or_else(|| {
            crate::DaemonError::Rpc("Client not initialized".to_string())
        })
    }

    /// Check if a block has any data for the given app_ids
    /// Returns the list of app_ids that have data in this block
    pub async fn get_block_app_ids(
        &mut self,
        block_number: u64,
        watched_app_ids: &[u32],
    ) -> crate::Result<Vec<u32>> {
        let client = self.get_client().await?.clone();
        let block = client.block(block_number as u32);

        let header = block.header()
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("Failed to get header: {}", e)))?;

        // Get app_lookup index from header extension
        let index = match &header.extension {
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V3(ext) => {
                &ext.app_lookup.index
            }
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
                &ext.app_lookup.index
            }
        };

        // Find which of our watched app_ids have data in this block
        // Note: app_lookup indexes are DA matrix positions, NOT extrinsic indexes
        let matching: Vec<u32> = index.iter()
            .filter(|item| watched_app_ids.contains(&item.app_id))
            .map(|item| item.app_id)
            .collect();

        Ok(matching)
    }

    /// Fetch block data for specific app_ids
    pub async fn fetch_block_data_for_app_ids(
        &mut self,
        block_number: u64,
        watched_app_ids: &[u32],
    ) -> crate::Result<BlockData> {
        // First check if this block has any data for our app_ids (presence check only)
        let matching_app_ids = self.get_block_app_ids(block_number, watched_app_ids).await?;

        if matching_app_ids.is_empty() {
            return Ok(BlockData {
                block_number,
                transactions: Vec::new(),
            });
        }

        tracing::debug!(
            "Block {} has data for app_ids: {:?}",
            block_number,
            matching_app_ids
        );

        // Fetch all extrinsics and process all SubmitData
        // Note: app_lookup indexes are DA matrix positions, not extrinsic indexes,
        // so we can't filter extrinsics by app_id. We process all and let the
        // SBO parser/repo matching handle filtering.
        let client = self.get_client().await?.clone();
        let block = client.block(block_number as u32);
        let opts = RpcOptions::new()
            .encode_as(EncodeSelector::Call);

        let mut infos = block.extrinsic_infos(opts)
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("Failed to fetch extrinsics: {}", e)))?;

        let mut transactions = Vec::new();

        // Process all extrinsics with pallet_id 29 (DataAvailability) and variant_id 1 (SubmitData)
        // We use the first matching app_id since we can't determine per-extrinsic app_id
        // from the extrinsic itself (it's determined by the submitter's account)
        let app_id = matching_app_ids[0];

        for info in &mut infos {
            if info.pallet_id == 29 && info.variant_id == 1 {

                if let Some(call_data) = info.data.take() {
                    if let Ok(bytes) = hex::decode(&call_data) {
                        if bytes.len() > 2 {
                            let payload = &bytes[2..];
                            match decode_compact_and_data(payload) {
                                Ok(mut data) => {
                                    // Try gzip decompression
                                    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
                                        let mut decoder = GzDecoder::new(data.as_slice());
                                        let mut decompressed = Vec::new();
                                        if decoder.read_to_end(&mut decompressed).is_ok() {
                                            data = decompressed;
                                        }
                                    }

                                    transactions.push(AppTransaction {
                                        app_id,
                                        index: info.ext_index,
                                        data,
                                    });
                                }
                                Err(e) => {
                                    tracing::trace!(
                                        "Block {} ext {} decode error: {}",
                                        block_number,
                                        info.ext_index,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::debug!(
            "Block {} has {} transactions for watched app_ids",
            block_number,
            transactions.len()
        );

        Ok(BlockData {
            block_number,
            transactions,
        })
    }

    /// Fetch block data for a specific app_id by block number (legacy interface)
    pub async fn fetch_block_data(
        &mut self,
        block_number: u64,
        app_id: u32,
    ) -> crate::Result<BlockData> {
        self.fetch_block_data_for_app_ids(block_number, &[app_id]).await
    }

    /// Fetch block data for multiple app_ids
    pub async fn fetch_block_data_multi(
        &mut self,
        block_number: u64,
        app_ids: &[u32],
    ) -> crate::Result<Vec<BlockData>> {
        // Fetch once for all app_ids
        let data = self.fetch_block_data_for_app_ids(block_number, app_ids).await?;

        // Split by app_id for compatibility with existing interface
        let mut results = Vec::new();
        for &app_id in app_ids {
            let txs: Vec<_> = data.transactions.iter()
                .filter(|tx| tx.app_id == app_id)
                .cloned()
                .collect();
            results.push(BlockData {
                block_number,
                transactions: txs,
            });
        }

        Ok(results)
    }

    /// Get the latest finalized block number
    pub async fn get_finalized_head(&mut self) -> crate::Result<u64> {
        let client = self.get_client().await?;

        let block = client.best().block_header()
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("Failed to get latest block: {}", e)))?;

        Ok(block.number as u64)
    }
}

/// Decode SCALE compact-encoded length and return the data bytes
fn decode_compact_and_data(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        return Err("Empty bytes".to_string());
    }

    let first = bytes[0];
    let mode = first & 0b11;

    let (length, header_size): (usize, usize) = match mode {
        0b00 => {
            // Single-byte mode: upper 6 bits are the value
            ((first >> 2) as usize, 1)
        }
        0b01 => {
            // Two-byte mode: upper 6 bits + next byte
            if bytes.len() < 2 {
                return Err("Not enough bytes for 2-byte compact".to_string());
            }
            let val = u16::from_le_bytes([first, bytes[1]]) >> 2;
            (val as usize, 2)
        }
        0b10 => {
            // Four-byte mode
            if bytes.len() < 4 {
                return Err("Not enough bytes for 4-byte compact".to_string());
            }
            let val = u32::from_le_bytes([first, bytes[1], bytes[2], bytes[3]]) >> 2;
            (val as usize, 4)
        }
        0b11 => {
            // Big-integer mode: first byte upper 6 bits = (num_bytes - 4)
            let num_bytes = ((first >> 2) + 4) as usize;
            if bytes.len() < 1 + num_bytes {
                return Err("Not enough bytes for big-int compact".to_string());
            }
            // Read the bytes as little-endian
            let mut val = 0usize;
            for (i, &b) in bytes[1..1 + num_bytes].iter().enumerate() {
                val |= (b as usize) << (8 * i);
            }
            (val, 1 + num_bytes)
        }
        _ => unreachable!(),
    };

    let data_start = header_size;
    let data_end = data_start + length;

    if bytes.len() < data_end {
        return Err(format!(
            "Not enough data: expected {} bytes, have {}",
            length,
            bytes.len() - data_start
        ));
    }

    Ok(bytes[data_start..data_end].to_vec())
}
