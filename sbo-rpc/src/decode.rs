//! Avail data matrix decoding
//!
//! Decodes application data from Avail's Kate data matrix.
//!
//! # Data Format
//!
//! Per avail-core kate/recovery, the data matrix contains:
//! - SCALE-encoded `Vec<Vec<u8>>` where each inner `Vec<u8>` is one raw encoded extrinsic
//! - Reference: https://github.com/availproject/avail-core/blob/main/kate/recovery/src/com.rs
//!   - AppData = Vec<Vec<u8>> = "list of extrinsics encoded in a block"
//!   - decode_app_extrinsics returns Result<AppData, _>

use std::io::Read as _;
use avail_rust::ext::avail_rust_core::rpc::kate;
use flate2::read::GzDecoder;
use parity_scale_codec::Decode;

/// Avail matrix constants (from avail-core)
pub const CHUNK_SIZE: usize = 32;       // U256 = 32 bytes per cell
pub const DATA_CHUNK_SIZE: usize = 31;  // Actual data per cell (last byte is padding)

/// Decode app data from fetched matrix rows
///
/// The data matrix contains SCALE-encoded extrinsics, not raw submitted data.
/// Structure: Vec<Vec<u8>> where each inner Vec is one encoded extrinsic.
///
/// Based on avail-core kate/recovery implementation:
/// - Rows are fetched via kate::query_rows
/// - Each scalar is converted to big-endian 32 bytes
/// - Only first 31 bytes (DATA_CHUNK_SIZE) contain data, last byte is padding
/// - Cells are processed in row-major order (chunk_idx = row * cols + col)
/// - IEC 9797-1 padding is removed
/// - Then SCALE Vec<Vec<u8>> is decoded to get actual submitted blobs
pub fn decode_app_data_from_rows(
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

    // Log cell processing stats (verbose only, or warn if missing cells)
    if cells_missing > 0 {
        tracing::warn!(
            "decode: processed={} cells, missing={}, raw_len={} bytes",
            cells_processed, cells_missing, data.len()
        );
    } else if verbose {
        tracing::info!(
            "decode: processed={} cells, raw_len={} bytes",
            cells_processed, data.len()
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

/// Decode SCALE-encoded Vec<Vec<u8>> from the data matrix
///
/// Per avail-core kate/recovery, the data matrix contains:
///   Vec<Vec<u8>> where each inner Vec<u8> is one raw encoded UncheckedExtrinsic
///
/// Reference: https://github.com/availproject/avail-core/blob/main/kate/recovery/src/com.rs
///   - AppData = Vec<Vec<u8>> = "list of extrinsics encoded in a block"
///   - decode_app_extrinsics returns Result<AppData, _>
///
/// Uses parity-scale-codec for proper SCALE decoding.
pub fn decode_app_extrinsics(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // Decode as Vec<Vec<u8>> per avail-core spec
    let extrinsics: Vec<Vec<u8>> = Vec::<Vec<u8>>::decode(&mut &data[..])
        .map_err(|e| {
            tracing::error!("SCALE decode error: {:?}", e);
            "Failed to decode Vec<Vec<u8>>"
        })?;

    tracing::debug!("Decoded {} extrinsic(s) from {} bytes", extrinsics.len(), data.len());

    // Extract the submitted data from each encoded extrinsic
    let blobs: Vec<Vec<u8>> = extrinsics
        .into_iter()
        .filter_map(|ext_bytes| {
            tracing::debug!("  Extrinsic: {} bytes", ext_bytes.len());
            extract_data_from_encoded_extrinsic(&ext_bytes)
        })
        .collect();

    Ok(blobs)
}

/// Extract the submitted data blob from an encoded UncheckedExtrinsic
///
/// Each extrinsic in the Vec<Vec<u8>> may include a compact length prefix.
/// This is because SCALE-encoded extrinsics are typically stored with their length.
///
/// UncheckedExtrinsic structure (signed v4):
/// - [Optional: compact length prefix]
/// - Version byte: 0x84 (signed v4)
/// - Address: MultiAddress (1 byte type + 32 bytes for Id)
/// - Signature: MultiSignature (1 byte type + 64 bytes for Sr25519/Ed25519)
/// - Extra: Era (1-2 bytes) + Nonce (compact) + Tip (compact) + AppId (compact)
/// - Call: pallet_index (u8) + call_index (u8) + data (Vec<u8>)
pub fn extract_data_from_encoded_extrinsic(encoded: &[u8]) -> Option<Vec<u8>> {
    if encoded.is_empty() {
        return None;
    }

    let mut input = &encoded[..];
    let original_len = input.len();

    // Check if there's a length prefix (extrinsic may be stored with compact length)
    // The first byte's lower 2 bits indicate the compact encoding mode
    let first = input[0];
    let mode = first & 0b11;

    // Check if first bytes could be a reasonable length prefix
    if mode == 0b01 || mode == 0b10 {
        // Two or four byte compact - could be a length prefix
        if let Some((len, consumed)) = decode_compact(input) {
            if consumed + len <= original_len && len > 100 {
                // Plausible length prefix - skip it
                tracing::debug!("  Detected length prefix: {} bytes (consumed {} for header)", len, consumed);
                input = &input[consumed..];
            }
        }
    }

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

    // Check for gzip compression and decompress if needed
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut decoder = GzDecoder::new(data.as_slice());
        let mut decompressed = Vec::new();
        if decoder.read_to_end(&mut decompressed).is_ok() {
            tracing::debug!("  Decompressed: {} -> {} bytes", data.len(), decompressed.len());
            return Some(decompressed);
        }
    }

    Some(data)
}

/// Decode a SCALE compact integer, returns (value, bytes_consumed)
pub fn decode_compact(data: &[u8]) -> Option<(usize, usize)> {
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
pub fn unpad_iec_9797_1(data: &[u8]) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_compact() {
        // Single byte mode (0b00)
        assert_eq!(decode_compact(&[0x00]), Some((0, 1)));
        assert_eq!(decode_compact(&[0x04]), Some((1, 1)));
        assert_eq!(decode_compact(&[0xfc]), Some((63, 1)));

        // Two byte mode (0b01)
        assert_eq!(decode_compact(&[0x01, 0x01]), Some((64, 2)));
        assert_eq!(decode_compact(&[0xfd, 0x03]), Some((255, 2)));

        // Four byte mode (0b10)
        assert_eq!(decode_compact(&[0x02, 0x00, 0x01, 0x00]), Some((16384, 4)));
    }

    #[test]
    fn test_unpad_iec_9797_1() {
        // With padding
        assert_eq!(unpad_iec_9797_1(&[0x01, 0x02, 0x80, 0x00, 0x00]), 2);
        assert_eq!(unpad_iec_9797_1(&[0x01, 0x80]), 1);

        // No padding
        assert_eq!(unpad_iec_9797_1(&[0x01, 0x02, 0x03]), 3);
        assert_eq!(unpad_iec_9797_1(&[0x01, 0x02, 0x00]), 3); // Just zeros, no 0x80
    }
}
