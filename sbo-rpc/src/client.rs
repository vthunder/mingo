//! Avail RPC Client
//!
//! Fetches block data from Avail RPC nodes using avail-rust SDK.
//! Uses Kate RPC to query the data matrix directly by app_id.

use avail_rust::Client;
use avail_rust::ext::avail_rust_core::rpc::kate;

use crate::decode::decode_app_data_from_rows;
use crate::error::{Error, Result};
use crate::{AppTransaction, BlockData};

/// RPC configuration
#[derive(Debug, Clone, Default)]
pub struct RpcConfig {
    pub endpoints: Vec<String>,
}

/// RPC client for fetching block data
pub struct RpcClient {
    config: RpcConfig,
    client: Option<Client>,
    verbose: bool,
}

impl RpcClient {
    pub fn new(config: RpcConfig) -> Self {
        Self { config, client: None, verbose: false }
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Connect to the RPC endpoint
    pub async fn connect(&mut self) -> Result<()> {
        let endpoint = self.config.endpoints.first().ok_or(Error::NoEndpoints)?;

        if self.verbose {
            tracing::info!("Connecting to Avail RPC: {}", endpoint);
        }

        let client = Client::new(endpoint)
            .await
            .map_err(|e| Error::Rpc(format!("Failed to connect: {}", e)))?;

        self.client = Some(client);

        if self.verbose {
            tracing::info!("Connected to Avail RPC");
        }

        Ok(())
    }

    /// Get the client, connecting if needed
    async fn get_client(&mut self) -> Result<&Client> {
        if self.client.is_none() {
            self.connect().await?;
        }
        self.client.as_ref().ok_or(Error::Rpc("Client not initialized".to_string()))
    }

    /// Get the latest finalized block number
    pub async fn get_finalized_head(&mut self) -> Result<u64> {
        let client = self.get_client().await?;

        let block = client.best().block_header()
            .await
            .map_err(|e| Error::Rpc(format!("Failed to get latest block: {}", e)))?;

        Ok(block.number as u64)
    }

    /// Check if a block has any data for the given app_ids
    /// Returns the list of app_ids that have data in this block
    pub async fn get_block_app_ids(
        &mut self,
        block_number: u64,
        watched_app_ids: &[u32],
    ) -> Result<Vec<u32>> {
        let client = self.get_client().await?.clone();
        let block = client.block(block_number as u32);

        let header = block.header()
            .await
            .map_err(|e| Error::Rpc(format!("Failed to get header: {}", e)))?;

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
        let matching: Vec<u32> = index.iter()
            .filter(|item| watched_app_ids.contains(&item.app_id))
            .map(|item| item.app_id)
            .collect();

        Ok(matching)
    }

    /// Fetch block data for specific app_ids using Kate RPC (data matrix query)
    ///
    /// This queries the DA matrix directly, which is more efficient than parsing
    /// extrinsics and scales better as block sizes grow.
    pub async fn fetch_block_data(
        &mut self,
        block_number: u64,
        app_id: u32,
    ) -> Result<BlockData> {
        self.fetch_block_data_for_app_ids(block_number, &[app_id]).await
    }

    /// Fetch block data for multiple app_ids
    pub async fn fetch_block_data_for_app_ids(
        &mut self,
        block_number: u64,
        watched_app_ids: &[u32],
    ) -> Result<BlockData> {
        let client = self.get_client().await?.clone();
        let block = client.block(block_number as u32);

        // Get block header for app_lookup index and grid dimensions
        let header = block.header()
            .await
            .map_err(|e| Error::Rpc(format!("Failed to get header: {}", e)))?;

        // Get app_lookup index and grid dimensions from header extension
        let (app_lookup_size, app_lookup_index, cols, _rows) = match &header.extension {
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V3(ext) => {
                (ext.app_lookup.size, &ext.app_lookup.index, ext.commitment.cols as u32, ext.commitment.rows as u32)
            }
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
                (ext.app_lookup.size, &ext.app_lookup.index, ext.commitment.cols as u32, ext.commitment.rows as u32)
            }
        };

        if self.verbose {
            tracing::info!(
                "Block {} header: app_lookup_size={}, index_entries={}, cols={}",
                block_number, app_lookup_size, app_lookup_index.len(), cols
            );
        }

        // Find data ranges for our watched app_ids
        let mut app_ranges: Vec<(u32, u32, u32)> = Vec::new(); // (app_id, start_chunk, end_chunk)

        for (i, item) in app_lookup_index.iter().enumerate() {
            if watched_app_ids.contains(&item.app_id) {
                let end = if i + 1 < app_lookup_index.len() {
                    app_lookup_index[i + 1].start
                } else {
                    app_lookup_size
                };
                app_ranges.push((item.app_id, item.start, end));
            }
        }

        if app_ranges.is_empty() {
            return Ok(BlockData {
                block_number,
                transactions: Vec::new(),
            });
        }

        // Calculate which rows we need to fetch
        let mut rows_needed: Vec<u32> = Vec::new();
        for &(_, start, end) in &app_ranges {
            if cols == 0 { continue; }
            let start_row = start / cols;
            let end_row = (end.saturating_sub(1)) / cols;
            for row in start_row..=end_row {
                if !rows_needed.contains(&row) {
                    rows_needed.push(row);
                }
            }
        }
        rows_needed.sort();

        if rows_needed.is_empty() {
            return Ok(BlockData {
                block_number,
                transactions: Vec::new(),
            });
        }

        // Get block hash for Kate RPC
        let block_hash = header.hash();

        // Fetch rows via Kate RPC (max 64 rows per call)
        // IMPORTANT: Map original row indices to extended row indices (2*N)
        let mut all_rows: Vec<(u32, kate::GRow)> = Vec::new();
        for chunk in rows_needed.chunks(64) {
            let extended_rows: Vec<u32> = chunk.iter().map(|r| r * 2).collect();
            let fetched = kate::query_rows(
                &client.rpc_client,
                extended_rows,
                Some(block_hash),
            )
            .await
            .map_err(|e| Error::Rpc(format!("kate_queryRows failed: {}", e)))?;

            // Store with original row indices
            for (i, row) in fetched.into_iter().enumerate() {
                all_rows.push((chunk[i], row));
            }
        }

        if self.verbose {
            tracing::info!(
                "Block {}: fetched {} rows (needed {:?}), cols={}",
                block_number, all_rows.len(), rows_needed, cols
            );
        }

        // Decode data for each app_id from the fetched rows
        let mut transactions = Vec::new();
        let mut tx_index = 0u32;

        for (app_id, start_cell, end_cell) in app_ranges {
            let data = decode_app_data_from_rows(
                &all_rows,
                start_cell,
                end_cell,
                cols,
                self.verbose,
            );

            if !data.is_empty() {
                transactions.push(AppTransaction {
                    app_id,
                    index: tx_index,
                    data,
                });
                tx_index += 1;
            }
        }

        Ok(BlockData {
            block_number,
            transactions,
        })
    }
}
