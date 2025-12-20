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
            let total_rows = rows as u32;
            let all_row_indices: Vec<u32> = (0..total_rows).collect();

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
            let matrix_path = debug_dir.join(format!("block_{}_matrix.bin", block_number));
            if let Ok(mut f) = std::fs::File::create(&matrix_path) {
                let _ = f.write_all(&cols.to_le_bytes());
                let _ = f.write_all(&total_rows.to_le_bytes());
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
        let mut all_rows: Vec<(u32, kate::GRow)> = Vec::new();
        for chunk in rows_needed.chunks(64) {
            let rows = kate::query_rows(
                &client.rpc_client,
                chunk.to_vec(),
                Some(block_hash),
            )
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("kate_queryRows failed: {}", e)))?;

            for (i, row) in rows.into_iter().enumerate() {
                all_rows.push((chunk[i], row));
            }
        }

        // Decode data for each app_id from the fetched rows
        let mut transactions = Vec::new();
        let mut tx_index = 0u32;

        for (app_id, start_cell, end_cell) in app_ranges {
            let mut data = decode_app_data_from_rows(
                &all_rows,
                start_cell,
                end_cell,
                cols,
                self.verbose_decode,
            );

            // Try gzip decompression
            if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
                let mut decoder = GzDecoder::new(data.as_slice());
                let mut decompressed = Vec::new();
                if decoder.read_to_end(&mut decompressed).is_ok() {
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
                // Serialize row commitments
                let commitments: Vec<u8> = ext.commitment.commitment.iter()
                    .flat_map(|c| c.0.to_vec())
                    .collect();
                (ext.app_lookup.size, &ext.app_lookup.index,
                 ext.commitment.cols as u32, ext.commitment.rows as u32, commitments)
            }
            avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
                let commitments: Vec<u8> = ext.commitment.commitment.iter()
                    .flat_map(|c| c.0.to_vec())
                    .collect();
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
        let mut all_rows: Vec<(u32, kate::GRow)> = Vec::new();
        for chunk in rows_needed.chunks(64) {
            let fetched = kate::query_rows(
                &client.rpc_client,
                chunk.to_vec(),
                Some(block_hash),
            )
            .await
            .map_err(|e| crate::DaemonError::Rpc(format!("kate_queryRows failed: {}", e)))?;

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

    if verbose {
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

/// Decode SCALE-encoded Vec<Extrinsic> to extract submitted data blobs
///
/// Structure in the matrix:
/// - Vec length (compact)
/// - For each extrinsic:
///   - Extrinsic length (compact)
///   - Extrinsic bytes: [signature...][call: pallet_idx, call_idx, app_id, data_len, data]
///
/// We extract the innermost 'data' field from each extrinsic.
fn decode_app_extrinsics(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut offset = 0;

    // Decode Vec length
    let (vec_len, consumed) = decode_scale_compact(&data[offset..])
        .ok_or("Failed to decode Vec length")?;
    offset += consumed;

    tracing::debug!("Extrinsics Vec length: {}", vec_len);

    let mut blobs = Vec::new();

    for i in 0..vec_len {
        if offset >= data.len() {
            tracing::warn!("Unexpected end of data at extrinsic {}", i);
            break;
        }

        // Decode extrinsic length
        let (ext_len, consumed) = decode_scale_compact(&data[offset..])
            .ok_or("Failed to decode extrinsic length")?;
        offset += consumed;

        tracing::debug!("Extrinsic {}: length={}, starts at offset {}", i, ext_len, offset);

        if offset + ext_len > data.len() {
            tracing::warn!("Extrinsic {} extends past data end", i);
            break;
        }

        // Extract the data blob from within the extrinsic
        // The extrinsic contains signature, call info, app_id, and the data
        // We look for the data length prefix followed by actual data
        let ext_data = &data[offset..offset + ext_len];

        if let Some(blob) = extract_data_from_extrinsic(ext_data) {
            blobs.push(blob);
        } else {
            tracing::warn!("Could not extract data blob from extrinsic {}", i);
        }

        offset += ext_len;
    }

    Ok(blobs)
}

/// Extract the submitted data blob from within an extrinsic
///
/// Extrinsic structure (signed):
/// - Version byte (0x84 for signed v4)
/// - Address type + address
/// - Signature type + signature (64 bytes for ed25519/sr25519)
/// - Era, nonce, tip (variable)
/// - Call: pallet_index (u8), call_index (u8), app_id (compact), data (Vec<u8>)
///
/// We scan for the data by looking for the compact length that precedes our actual data.
fn extract_data_from_extrinsic(ext: &[u8]) -> Option<Vec<u8>> {
    // Strategy: find "SBO-" magic (if present) and work backwards to find the length prefix
    const SBO_MAGIC: &[u8] = b"SBO-";

    if let Some(sbo_pos) = ext.windows(4).position(|w| w == SBO_MAGIC) {
        // Look for compact length prefix just before SBO-
        // Try 2-byte compact first (most common for our data sizes)
        if sbo_pos >= 2 {
            if let Some((len, 2)) = decode_scale_compact(&ext[sbo_pos - 2..]) {
                let data_end = sbo_pos + len;
                if data_end <= ext.len() {
                    tracing::debug!(
                        "Found data via SBO- magic: offset={}, len={}",
                        sbo_pos, len
                    );
                    return Some(ext[sbo_pos..data_end].to_vec());
                }
            }
        }
        // Try 1-byte compact
        if sbo_pos >= 1 {
            if let Some((len, 1)) = decode_scale_compact(&ext[sbo_pos - 1..]) {
                let data_end = sbo_pos + len;
                if data_end <= ext.len() {
                    return Some(ext[sbo_pos..data_end].to_vec());
                }
            }
        }
        // Fallback: take from SBO- to end (trim trailing zeros)
        let mut end = ext.len();
        while end > sbo_pos && ext[end - 1] == 0 {
            end -= 1;
        }
        return Some(ext[sbo_pos..end].to_vec());
    }

    // No SBO- magic found - try to decode based on structure
    // This handles non-SBO data or data without the magic header

    // Scan for a reasonable compact length followed by non-zero data
    for offset in (ext.len().saturating_sub(200))..ext.len().saturating_sub(4) {
        if let Some((len, compact_size)) = decode_scale_compact(&ext[offset..]) {
            let data_start = offset + compact_size;
            let data_end = data_start + len;

            // Validate: data should fit, be reasonable size, and start with non-zero
            if data_end <= ext.len() && len >= 10 && data_start < ext.len() && ext[data_start] != 0 {
                tracing::debug!(
                    "Found data via scan: offset={}, len={}",
                    data_start, len
                );
                return Some(ext[data_start..data_end].to_vec());
            }
        }
    }

    None
}

/// Decode a SCALE compact-encoded integer
/// Returns (value, bytes_consumed) or None if invalid
fn decode_scale_compact(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let mode = data[0] & 0b11;
    match mode {
        0b00 => {
            // Single byte mode: value = byte >> 2
            Some(((data[0] >> 2) as usize, 1))
        }
        0b01 => {
            // Two byte mode: value = u16 >> 2
            if data.len() < 2 {
                return None;
            }
            let val = u16::from_le_bytes([data[0], data[1]]) >> 2;
            Some((val as usize, 2))
        }
        0b10 => {
            // Four byte mode: value = u32 >> 2
            if data.len() < 4 {
                return None;
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) >> 2;
            Some((val as usize, 4))
        }
        0b11 => {
            // Big integer mode: first byte >> 2 = number of following bytes - 4
            let num_bytes = ((data[0] >> 2) + 4) as usize;
            if data.len() < 1 + num_bytes || num_bytes > 8 {
                return None;
            }
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

