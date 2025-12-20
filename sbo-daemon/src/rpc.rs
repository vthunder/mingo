//! Avail RPC Client
//!
//! Fetches block data from Avail RPC nodes using avail-rust SDK.
//! Uses Kate RPC to query the data matrix directly by app_id.

use std::io::Read as _;
use std::io::Write as _;
use crate::config::RpcConfig;
use avail_rust::Client;
use avail_rust::ext::avail_rust_core::rpc::kate;
use flate2::read::GzDecoder;
use parity_scale_codec::Decode;

/// AppExtrinsic as stored in Avail's data matrix
/// See: https://github.com/availproject/avail-core/blob/main/core/src/app_extrinsic.rs
#[derive(Debug, Clone, Decode)]
struct AppExtrinsic {
    app_id: u32,
    data: Vec<u8>,
}

#[cfg(feature = "zkvm")]
use sbo_zkvm::types::{HeaderData, RowData, AppLookup, AppLookupEntry};

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

/// Data needed for zkVM DA verification
#[cfg(feature = "zkvm")]
#[derive(Debug, Clone)]
pub struct DaVerificationData {
    /// Header verification data
    pub header_data: HeaderData,
    /// Row data for rows containing app data
    pub row_data: Vec<RowData>,
    /// Hash of raw cells (for binding)
    pub raw_cells_hash: [u8; 32],
}

/// RPC client for fetching block data
pub struct RpcClient {
    config: RpcConfig,
    client: Option<Client>,
    verbose: bool,
    verbose_decode: bool,
    debug_save_raw: bool,
}

impl RpcClient {
    pub fn new(config: RpcConfig, verbose: bool, verbose_decode: bool, debug_save_raw: bool) -> Self {
        Self { config, client: None, verbose, verbose_decode, debug_save_raw }
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

    /// Fetch block data for specific app_ids using Kate RPC (data matrix query)
    ///
    /// This queries the DA matrix directly, which is more efficient than parsing
    /// extrinsics and scales better as block sizes grow.
    pub async fn fetch_block_data_for_app_ids(
        &mut self,
        block_number: u64,
        watched_app_ids: &[u32],
    ) -> crate::Result<BlockData> {
        let client = self.get_client().await?.clone();
        let block = client.block(block_number as u32);

        // Get block header for app_lookup index and grid dimensions
        let header = block.header()
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("Failed to get header: {}", e)))?;

        // Get app_lookup index and grid dimensions from header extension
        // Both V3 and V4 have size, index, and commitment.cols - extract the values
        let (app_lookup_size, app_lookup_index, cols, rows) = match &header.extension {
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V3(ext) => {
                (ext.app_lookup.size, &ext.app_lookup.index, ext.commitment.cols as u32, ext.commitment.rows as u32)
            }
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
                (ext.app_lookup.size, &ext.app_lookup.index, ext.commitment.cols as u32, ext.commitment.rows as u32)
            }
        };

        if self.verbose_decode {
            tracing::info!(
                "Block {} header: app_lookup_size={}, index_entries={}, cols={}, rows={}",
                block_number, app_lookup_size, app_lookup_index.len(), cols, rows
            );
            for item in app_lookup_index.iter() {
                tracing::info!("  app_lookup entry: app_id={}, start={}", item.app_id, item.start);
            }
        }

        // Find data ranges for our watched app_ids
        // app_lookup uses chunk indices (each chunk = 31 bytes of data)
        let mut app_ranges: Vec<(u32, u32, u32)> = Vec::new(); // (app_id, start_chunk, end_chunk)

        for (i, item) in app_lookup_index.iter().enumerate() {
            if watched_app_ids.contains(&item.app_id) {
                // End is either the next entry's start or the total size
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

        tracing::debug!(
            "Block {} app_ranges for watched ids: {:?}, cols={}",
            block_number,
            app_ranges,
            cols
        );

        // Calculate which rows we need to fetch
        // The start/end values are flat chunk indices into the data matrix
        // Each row has `cols` cells of original data (extension is vertical, adding rows)
        let mut rows_needed: Vec<u32> = Vec::new();
        for &(_, start, end) in &app_ranges {
            if cols == 0 {
                continue;
            }
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

        tracing::debug!(
            "Block {} fetching {} rows: {:?}",
            block_number,
            rows_needed.len(),
            rows_needed
        );

        // Get block hash for Kate RPC
        let block_hash = header.hash();

        // === DEBUG: Save block data to files (only with --debug save-raw-block) ===
        if self.debug_save_raw {
            // Note: We fetch the EXTENDED matrix rows (2*original_rows) for debug purposes.
            // The RPC returns an interleaved matrix where:
            //   - Even rows (0, 2, 4, ...) contain original data
            //   - Odd rows (1, 3, 5, ...) contain erasure-coded parity data
            // The header `rows` is the ORIGINAL row count.
            let extended_rows = rows * 2;
            let all_row_indices: Vec<u32> = (0..extended_rows).collect();

            let mut debug_all_rows: Vec<(u32, kate::GRow)> = Vec::new();
            for chunk in all_row_indices.chunks(64) {
                if let Ok(fetched) = kate::query_rows(
                    &client.rpc_client,
                    chunk.to_vec(),
                    Some(block_hash),
                ).await {
                    for (i, row) in fetched.into_iter().enumerate() {
                        debug_all_rows.push((chunk[i], row));
                    }
                }
            }

            let debug_dir = std::path::Path::new("/tmp/sbo-debug");
            let _ = std::fs::create_dir_all(debug_dir);

            // 1. Save header as JSON
            let header_path = debug_dir.join(format!("block_{}_header.json", block_number));
            let header_json = format!(
                "{{\"block_number\":{},\"hash\":\"{:?}\",\"parent_hash\":\"{:?}\",\"state_root\":\"{:?}\",\"extrinsics_root\":\"{:?}\",\"app_lookup_size\":{},\"cols\":{},\"rows\":{},\"app_lookup\":[{}]}}",
                block_number,
                block_hash,
                header.parent_hash,
                header.state_root,
                header.extrinsics_root,
                app_lookup_size,
                cols,
                rows,
                app_lookup_index.iter().map(|i| format!("{{\"app_id\":{},\"start\":{}}}", i.app_id, i.start)).collect::<Vec<_>>().join(",")
            );
            let _ = std::fs::write(&header_path, &header_json);

            // 2. Save ALL matrix rows as raw scalars (32 bytes each, big-endian)
            // Note: This saves the extended matrix (2*original rows)
            let matrix_path = debug_dir.join(format!("block_{}_matrix.bin", block_number));
            if let Ok(mut f) = std::fs::File::create(&matrix_path) {
                let _ = f.write_all(&cols.to_le_bytes());
                let _ = f.write_all(&extended_rows.to_le_bytes());
                for (_row_idx, row) in &debug_all_rows {
                    for scalar in row.iter() {
                        let bytes: [u8; 32] = scalar.to_big_endian();
                        let _ = f.write_all(&bytes);
                    }
                }
            }

            // 3. Save the app_lookup index
            let lookup_path = debug_dir.join(format!("block_{}_lookup.bin", block_number));
            if let Ok(mut f) = std::fs::File::create(&lookup_path) {
                let _ = f.write_all(&app_lookup_size.to_le_bytes());
                let _ = f.write_all(&(app_lookup_index.len() as u32).to_le_bytes());
                for item in app_lookup_index.iter() {
                    let _ = f.write_all(&item.app_id.to_le_bytes());
                    let _ = f.write_all(&item.start.to_le_bytes());
                }
            }

            tracing::info!("Saved debug files to /tmp/sbo-debug/ for block {}", block_number);
        }

        // Fetch rows via Kate RPC (max 64 rows per call) - only needed rows for actual processing
        // IMPORTANT: The header `rows` is the ORIGINAL row count. The RPC returns the EXTENDED matrix
        // (2x rows due to erasure coding). Original data is in even extended rows:
        //   Original row 0 → Extended row 0
        //   Original row 1 → Extended row 2
        //   Original row N → Extended row 2*N
        // We request extended rows (2*N) and map them back to original indices.
        let mut all_rows: Vec<(u32, kate::GRow)> = Vec::new();
        for chunk in rows_needed.chunks(64) {
            // Convert original row indices to extended row indices (multiply by 2)
            let extended_rows: Vec<u32> = chunk.iter().map(|r| r * 2).collect();
            let rows = kate::query_rows(
                &client.rpc_client,
                extended_rows,
                Some(block_hash),
            )
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("kate_queryRows failed: {}", e)))?;

            // Store with original row indices (for decode_app_data_from_rows lookups)
            for (i, row) in rows.into_iter().enumerate() {
                all_rows.push((chunk[i], row));
            }
        }

        // Log fetched rows info
        tracing::info!(
            "Block {}: fetched {} rows (needed {:?}), cols={}",
            block_number,
            all_rows.len(),
            rows_needed,
            cols
        );
        for (row_idx, row) in &all_rows {
            tracing::debug!("  row {}: {} cells", row_idx, row.len());
        }

        // Decode data for each app_id from the fetched rows
        let mut transactions = Vec::new();
        let mut tx_index = 0u32;

        for (app_id, start_cell, end_cell) in app_ranges {
            // Log chunk range for debugging
            let expected_cells = end_cell.saturating_sub(start_cell);
            let expected_bytes = expected_cells as usize * DATA_CHUNK_SIZE;
            tracing::info!(
                "Block {} app_id={}: chunks {}..{} ({} cells, ~{} bytes expected)",
                block_number, app_id, start_cell, end_cell, expected_cells, expected_bytes
            );

            let mut data = decode_app_data_from_rows(
                &all_rows,
                start_cell,
                end_cell,
                cols,
                self.verbose_decode,
            );

            tracing::info!(
                "Block {} app_id={}: raw data after cell decode = {} bytes",
                block_number, app_id, data.len()
            );

            // Try gzip decompression
            if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
                let mut decoder = GzDecoder::new(data.as_slice());
                let mut decompressed = Vec::new();
                if decoder.read_to_end(&mut decompressed).is_ok() {
                    tracing::info!(
                        "Block {} app_id={}: decompressed {} -> {} bytes",
                        block_number, app_id, data.len(), decompressed.len()
                    );
                    data = decompressed;
                }
            }

            tracing::debug!(
                "Block {} app_id={} data_len={} (cells {}..{})",
                block_number,
                app_id,
                data.len(),
                start_cell,
                end_cell
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

    /// Fetch DA verification data for zkVM proving
    ///
    /// Returns header data, row data, and raw cells hash needed for
    /// the zkVM guest to verify data availability.
    #[cfg(feature = "zkvm")]
    pub async fn fetch_da_verification_data(
        &mut self,
        block_number: u64,
        app_id: u32,
    ) -> crate::Result<Option<DaVerificationData>> {
        let client = self.get_client().await?.clone();
        let block = client.block(block_number as u32);

        // Get block header
        let header = block.header()
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("Failed to get header: {}", e)))?;

        let block_hash = header.hash();

        // Extract data from header extension (V3 and V4 supported)
        let (app_lookup_size, app_lookup_index, cols, rows, row_commitments) = match &header.extension {
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V3(ext) => {
                // KateCommitment.commitment is already Vec<u8> (concatenated 48-byte G1 points)
                let commitments = ext.commitment.commitment.clone();
                (ext.app_lookup.size, &ext.app_lookup.index,
                 ext.commitment.cols as u32, ext.commitment.rows as u32, commitments)
            }
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
                let commitments = ext.commitment.commitment.clone();
                (ext.app_lookup.size, &ext.app_lookup.index,
                 ext.commitment.cols as u32, ext.commitment.rows as u32, commitments)
            }
        };

        // Find our app's chunk range
        let mut app_start = None;
        let mut app_end = app_lookup_size;

        for (i, item) in app_lookup_index.iter().enumerate() {
            if item.app_id == app_id {
                app_start = Some(item.start);
                // End is next entry's start or total size
                if i + 1 < app_lookup_index.len() {
                    app_end = app_lookup_index[i + 1].start;
                }
                break;
            }
        }

        let Some(start_chunk) = app_start else {
            // App not found in this block
            return Ok(None);
        };

        // Calculate which rows we need
        let start_row = start_chunk / cols;
        let end_row = (app_end.saturating_sub(1)) / cols;
        let rows_needed: Vec<u32> = (start_row..=end_row).collect();

        if rows_needed.is_empty() {
            return Ok(None);
        }

        // Fetch rows via Kate RPC
        // IMPORTANT: Map original row indices to extended row indices (2*N)
        // See comment in get_block_data for explanation of erasure coding row interleaving
        let mut all_rows: Vec<(u32, kate::GRow)> = Vec::new();
        for chunk in rows_needed.chunks(64) {
            let extended_rows: Vec<u32> = chunk.iter().map(|r| r * 2).collect();
            let fetched = kate::query_rows(
                &client.rpc_client,
                extended_rows,
                Some(block_hash),
            )
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("kate_queryRows failed: {}", e)))?;

            // Store with original row indices
            for (i, row) in fetched.into_iter().enumerate() {
                all_rows.push((chunk[i], row));
            }
        }

        // Convert to RowData format and compute raw cells hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        let mut row_data = Vec::new();

        for (row_idx, row) in all_rows {
            let cells: Vec<[u8; 32]> = row.iter()
                .map(|scalar| {
                    let bytes: [u8; 32] = scalar.to_big_endian();
                    hasher.update(&bytes);
                    bytes
                })
                .collect();

            row_data.push(RowData {
                row: row_idx,
                cells,
            });
        }

        let raw_cells_hash: [u8; 32] = hasher.finalize().into();

        // Build app_lookup for our type
        let app_lookup = AppLookup {
            size: app_lookup_size,
            index: app_lookup_index.iter()
                .map(|item| AppLookupEntry {
                    app_id: item.app_id,
                    start: item.start,
                })
                .collect(),
        };

        // Build header data
        let header_data = HeaderData {
            block_number,
            header_hash: block_hash.0,
            parent_hash: header.parent_hash.0,
            state_root: header.state_root.0,
            extrinsics_root: header.extrinsics_root.0,
            data_root: header.extrinsics_root.0, // Will be updated when we find data_root
            row_commitments,
            rows,
            cols,
            app_lookup,
            app_id,
        };

        Ok(Some(DaVerificationData {
            header_data,
            row_data,
            raw_cells_hash,
        }))
    }
}

/// Avail matrix constants (from avail-core)
const CHUNK_SIZE: usize = 32;       // U256 = 32 bytes per cell
const DATA_CHUNK_SIZE: usize = 31;  // Actual data per cell (last byte is padding)

/// Decode app data from fetched matrix rows
///
/// The data matrix contains SCALE-encoded extrinsics, not raw submitted data.
/// Structure: Vec<Extrinsic> where each extrinsic contains the submitted blob.
///
/// Based on avail-light/avail-core implementation:
/// - Rows are fetched via kate::query_rows
/// - Each scalar is converted to big-endian 32 bytes
/// - Only first 31 bytes (DATA_CHUNK_SIZE) contain data, last byte is padding
/// - Cells are processed in row-major order (chunk_idx = row * cols + col)
/// - IEC 9797-1 padding is removed
/// - Then SCALE Vec<Vec<u8>> is decoded to get actual submitted blobs
fn decode_app_data_from_rows(
    rows: &[(u32, kate::GRow)],
    start_chunk: u32,
    end_chunk: u32,
    cols: u32,
    verbose: bool,
) -> Vec<u8> {
    if verbose {
        tracing::info!(
            "decode_app_data_from_rows: start_chunk={}, end_chunk={}, cols={}, fetched_rows={}",
            start_chunk, end_chunk, cols, rows.len()
        );
    }

    let mut data = Vec::new();
    let mut cells_processed = 0u32;
    let mut cells_missing = 0u32;

    // Process cells in row-major order
    for chunk_idx in start_chunk..end_chunk {
        let row_idx = chunk_idx / cols;
        let col_idx = chunk_idx % cols;

        if let Some((_, row)) = rows.iter().find(|(r, _)| *r == row_idx) {
            if (col_idx as usize) < row.len() {
                let scalar = &row[col_idx as usize];
                // Big-endian, take first 31 bytes (last byte is padding per avail-core)
                let bytes: [u8; CHUNK_SIZE] = scalar.to_big_endian();
                data.extend_from_slice(&bytes[..DATA_CHUNK_SIZE]);
                cells_processed += 1;
            } else {
                cells_missing += 1;
            }
        } else {
            cells_missing += 1;
        }
    }

    // Always log cell processing stats for debugging
    if cells_missing > 0 || verbose {
        tracing::info!(
            "decode: processed={} cells, missing={}, raw_len={} bytes",
            cells_processed, cells_missing, data.len()
        );
    }

    // Apply IEC 9797-1 unpadding (remove 0x80 + trailing zeros)
    let unpadded_len = unpad_iec_9797_1(&data);
    if unpadded_len < data.len() {
        tracing::debug!(
            "IEC 9797-1 unpadding: {} -> {} bytes",
            data.len(), unpadded_len
        );
        data.truncate(unpadded_len);
    }

    // Decode SCALE Vec<Vec<u8>> to extract submitted blobs
    // The matrix contains extrinsic data, structured as Vec<(extrinsic_len, extrinsic_bytes)>
    // We need to extract the actual submitted data from within each extrinsic
    match decode_app_extrinsics(&data) {
        Ok(blobs) => {
            if verbose {
                tracing::info!("Decoded {} blob(s) from extrinsics", blobs.len());
            }
            // Concatenate all blobs (typically just one)
            let mut result = Vec::new();
            for (i, blob) in blobs.iter().enumerate() {
                tracing::debug!("  blob {}: {} bytes", i, blob.len());
                result.extend_from_slice(blob);
            }
            result
        }
        Err(e) => {
            tracing::warn!("Failed to decode extrinsics: {}, returning raw data", e);
            data
        }
    }
}

/// Decode SCALE-encoded Vec<AppExtrinsic> from the data matrix
///
/// The data matrix contains app extrinsics as Vec<AppExtrinsic> where:
/// - AppExtrinsic { app_id: u32, data: Vec<u8> }
/// - AppExtrinsic.data contains an ENCODED UncheckedExtrinsic
/// - The actual submitted data is inside the extrinsic's call
///
/// Uses parity-scale-codec for proper SCALE decoding.
fn decode_app_extrinsics(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // Use parity-scale-codec to properly decode Vec<AppExtrinsic>
    let extrinsics: Vec<AppExtrinsic> = Vec::<AppExtrinsic>::decode(&mut &data[..])
        .map_err(|e| {
            tracing::error!("SCALE decode error: {:?}", e);
            "Failed to decode Vec<AppExtrinsic>"
        })?;

    tracing::debug!("Decoded {} AppExtrinsic(s) from {} bytes", extrinsics.len(), data.len());

    // Extract the submitted data from each AppExtrinsic
    // AppExtrinsic.data contains an encoded extrinsic, we need to extract the inner data
    let blobs: Vec<Vec<u8>> = extrinsics
        .into_iter()
        .filter_map(|ext| {
            tracing::debug!("  AppExtrinsic: app_id={}, encoded_ext_len={}", ext.app_id, ext.data.len());
            extract_data_from_encoded_extrinsic(&ext.data)
        })
        .collect();

    Ok(blobs)
}

/// Extract the submitted data blob from an encoded UncheckedExtrinsic
///
/// UncheckedExtrinsic structure (signed v4):
/// - Version byte: 0x84 (signed v4)
/// - Address: MultiAddress (1 byte type + 32 bytes for Id)
/// - Signature: MultiSignature (1 byte type + 64 bytes for Sr25519/Ed25519)
/// - Extra: Era (1-2 bytes) + Nonce (compact) + Tip (compact) + AppId (compact)
/// - Call: pallet_index (u8) + call_index (u8) + data (Vec<u8>)
fn extract_data_from_encoded_extrinsic(encoded: &[u8]) -> Option<Vec<u8>> {
    if encoded.is_empty() {
        return None;
    }

    let mut input = &encoded[..];

    // Version byte
    let version = *input.first()?;
    input = &input[1..];

    let is_signed = (version & 0x80) != 0;

    if is_signed {
        // Skip MultiAddress (type byte + address data)
        let addr_type = *input.first()?;
        input = &input[1..];

        let addr_len = match addr_type {
            0x00 => 32, // Id
            0x01 => {   // Index - compact u32
                let (_, consumed) = decode_compact(input)?;
                consumed
            }
            0x02 => {   // Raw - Vec<u8>
                let (len, consumed) = decode_compact(input)?;
                consumed + len
            }
            0x03 => 32, // Address32
            0x04 => 20, // Address20
            _ => return None,
        };
        if addr_len > input.len() { return None; }
        input = &input[addr_len..];

        // Skip MultiSignature (type byte + signature data)
        let sig_type = *input.first()?;
        input = &input[1..];

        let sig_len = match sig_type {
            0x00 | 0x01 => 64, // Ed25519 or Sr25519
            0x02 => 65,        // Ecdsa
            _ => return None,
        };
        if sig_len > input.len() { return None; }
        input = &input[sig_len..];

        // Skip Era
        let era_byte = *input.first()?;
        input = &input[1..];
        if era_byte != 0x00 && !input.is_empty() {
            // Mortal era is 2 bytes total, we already consumed 1
            input = &input[1..];
        }

        // Skip Nonce (compact)
        let (_, consumed) = decode_compact(input)?;
        input = &input[consumed..];

        // Skip Tip (compact)
        let (_, consumed) = decode_compact(input)?;
        input = &input[consumed..];

        // Skip AppId in SignedExtra (compact u32)
        let (_, consumed) = decode_compact(input)?;
        input = &input[consumed..];
    }

    // Now at the Call
    // Skip pallet_index and call_index
    if input.len() < 2 { return None; }
    let _pallet = input[0];
    let _call = input[1];
    input = &input[2..];

    // The remaining data is Vec<u8> - the actual submitted blob
    let data: Vec<u8> = Vec::<u8>::decode(&mut &input[..]).ok()?;

    tracing::debug!("  Extracted {} bytes from extrinsic", data.len());
    Some(data)
}

/// Decode a SCALE compact integer, returns (value, bytes_consumed)
fn decode_compact(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let mode = data[0] & 0b11;
    match mode {
        0b00 => Some(((data[0] >> 2) as usize, 1)),
        0b01 => {
            if data.len() < 2 { return None; }
            let val = u16::from_le_bytes([data[0], data[1]]) >> 2;
            Some((val as usize, 2))
        }
        0b10 => {
            if data.len() < 4 { return None; }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) >> 2;
            Some((val as usize, 4))
        }
        0b11 => {
            let num_bytes = ((data[0] >> 2) + 4) as usize;
            if data.len() < 1 + num_bytes || num_bytes > 8 { return None; }
            let mut bytes = [0u8; 8];
            bytes[..num_bytes].copy_from_slice(&data[1..1 + num_bytes]);
            Some((u64::from_le_bytes(bytes) as usize, 1 + num_bytes))
        }
        _ => None,
    }
}

/// Remove IEC 9797-1 padding (0x80 followed by zeros)
/// Returns the length of the unpadded data
fn unpad_iec_9797_1(data: &[u8]) -> usize {
    // Scan backwards: skip zeros, then expect 0x80
    let mut i = data.len();
    while i > 0 && data[i - 1] == 0x00 {
        i -= 1;
    }
    // Check for the 0x80 marker
    if i > 0 && data[i - 1] == 0x80 {
        i - 1
    } else {
        // No valid padding found, return original length
        data.len()
    }
}

