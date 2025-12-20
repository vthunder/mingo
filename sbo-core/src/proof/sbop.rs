//! SBOP (SBO Proof) message format
//!
//! Format:
//! ```text
//! SBOP-Version: 0.1
//! Block-From: 1
//! Block-To: 100
//! Receipt-Kind: succinct
//! Receipt-Length: 45678
//! Content-Encoding: base64
//!
//! <base64 encoded receipt bytes>
//! ```

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SbopError {
    #[error("Missing header: {0}")]
    MissingHeader(String),
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("Invalid base64: {0}")]
    InvalidBase64(String),
    #[error("Receipt length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

/// Parsed SBOP message
#[derive(Debug, Clone)]
pub struct SbopMessage {
    pub version: String,
    pub block_from: u64,
    pub block_to: u64,
    pub receipt_kind: String,
    pub receipt_bytes: Vec<u8>,
}

/// Check if bytes start with SBOP-Version header
pub fn is_sbop_message(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SBOP-Version:")
}

/// Parse SBOP message from bytes
pub fn parse_sbop(bytes: &[u8]) -> Result<SbopMessage, SbopError> {
    use std::collections::HashMap;
    use base64::{Engine, engine::general_purpose::STANDARD};

    // Split headers and payload at blank line
    let mut pos = 0;
    let mut headers: HashMap<String, String> = HashMap::new();

    while pos < bytes.len() {
        let line_end = bytes[pos..].iter().position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(bytes.len());

        let line = &bytes[pos..line_end];

        if line.is_empty() {
            pos = line_end + 1;
            break;
        }

        let line_str = std::str::from_utf8(line)
            .map_err(|_| SbopError::InvalidHeader("Invalid UTF-8".to_string()))?;

        let colon_pos = line_str.find(": ")
            .ok_or_else(|| SbopError::InvalidHeader("Missing ': ' separator".to_string()))?;

        let name = line_str[..colon_pos].to_string();
        let value = line_str[colon_pos + 2..].to_string();
        headers.insert(name, value);

        pos = line_end + 1;
    }

    // Parse required headers
    let version = headers.get("SBOP-Version")
        .ok_or_else(|| SbopError::MissingHeader("SBOP-Version".to_string()))?
        .clone();

    if !version.starts_with("0.") {
        return Err(SbopError::UnsupportedVersion(version));
    }

    let block_from: u64 = headers.get("Block-From")
        .ok_or_else(|| SbopError::MissingHeader("Block-From".to_string()))?
        .parse()
        .map_err(|_| SbopError::InvalidHeader("Block-From not a number".to_string()))?;

    let block_to: u64 = headers.get("Block-To")
        .ok_or_else(|| SbopError::MissingHeader("Block-To".to_string()))?
        .parse()
        .map_err(|_| SbopError::InvalidHeader("Block-To not a number".to_string()))?;

    let receipt_kind = headers.get("Receipt-Kind")
        .ok_or_else(|| SbopError::MissingHeader("Receipt-Kind".to_string()))?
        .clone();

    let receipt_length: usize = headers.get("Receipt-Length")
        .ok_or_else(|| SbopError::MissingHeader("Receipt-Length".to_string()))?
        .parse()
        .map_err(|_| SbopError::InvalidHeader("Receipt-Length not a number".to_string()))?;

    // Payload is base64-encoded receipt
    // Calculate expected base64 length from Receipt-Length
    let expected_base64_len = ((receipt_length + 2) / 3) * 4;
    let _expected_total_len = pos + expected_base64_len;

    let payload = &bytes[pos..];

    // Find the end of valid base64 content (stop at first non-base64 character)
    // Base64 chars: A-Z, a-z, 0-9, +, /, =, and whitespace
    let base64_end = payload.iter()
        .position(|&b| !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'\n' | b'\r' | b' ' | b'\t'))
        .unwrap_or(payload.len());

    // Log diagnostic info about sizes
    let trailing_bytes = bytes.len().saturating_sub(pos + base64_end);
    if trailing_bytes > 0 || base64_end != expected_base64_len {
        eprintln!(
            "SBOP parse diagnostics: total_bytes={}, headers_end={}, payload_len={}, base64_end={}, expected_base64={}, trailing_garbage={}",
            bytes.len(), pos, payload.len(), base64_end, expected_base64_len, trailing_bytes
        );
        if trailing_bytes > 0 && trailing_bytes <= 50 {
            eprintln!("  trailing bytes: {:02x?}", &bytes[pos + base64_end..]);
        }
    }

    let payload = &payload[..base64_end];
    let payload_str = std::str::from_utf8(payload)
        .map_err(|_| SbopError::InvalidBase64("Not valid UTF-8".to_string()))?
        .trim();

    let receipt_bytes = STANDARD.decode(payload_str)
        .map_err(|e| SbopError::InvalidBase64(format!("{} (base64_len={}, expected={})", e, payload_str.len(), expected_base64_len)))?;

    if receipt_bytes.len() != receipt_length {
        return Err(SbopError::LengthMismatch {
            expected: receipt_length,
            actual: receipt_bytes.len(),
        });
    }

    Ok(SbopMessage {
        version,
        block_from,
        block_to,
        receipt_kind,
        receipt_bytes,
    })
}

/// Serialize SBOP message to bytes
pub fn serialize_sbop(msg: &SbopMessage) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let encoded = STANDARD.encode(&msg.receipt_bytes);

    format!(
        "SBOP-Version: {}\n\
         Block-From: {}\n\
         Block-To: {}\n\
         Receipt-Kind: {}\n\
         Receipt-Length: {}\n\
         Content-Encoding: base64\n\
         \n\
         {}",
        msg.version,
        msg.block_from,
        msg.block_to,
        msg.receipt_kind,
        msg.receipt_bytes.len(),
        encoded
    ).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let msg = SbopMessage {
            version: "0.1".to_string(),
            block_from: 1,
            block_to: 100,
            receipt_kind: "succinct".to_string(),
            receipt_bytes: vec![1, 2, 3, 4, 5],
        };

        let bytes = serialize_sbop(&msg);
        let parsed = parse_sbop(&bytes).unwrap();

        assert_eq!(parsed.version, msg.version);
        assert_eq!(parsed.block_from, msg.block_from);
        assert_eq!(parsed.block_to, msg.block_to);
        assert_eq!(parsed.receipt_kind, msg.receipt_kind);
        assert_eq!(parsed.receipt_bytes, msg.receipt_bytes);
    }

    #[test]
    fn test_is_sbop() {
        assert!(is_sbop_message(b"SBOP-Version: 0.1\n"));
        assert!(!is_sbop_message(b"SBO-Version: 0.5\n"));
    }

    #[test]
    fn test_large_receipt() {
        // Test with larger receipt data
        let receipt_bytes: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let msg = SbopMessage {
            version: "0.1".to_string(),
            block_from: 50,
            block_to: 100,
            receipt_kind: "groth16".to_string(),
            receipt_bytes,
        };

        let bytes = serialize_sbop(&msg);
        let parsed = parse_sbop(&bytes).unwrap();

        assert_eq!(parsed.receipt_bytes.len(), 1000);
        assert_eq!(parsed.receipt_bytes, msg.receipt_bytes);
    }
}
