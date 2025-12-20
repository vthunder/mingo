//! SBOQ (SBO Query/Object Proof) message format v0.2
//!
//! SBOQ messages contain trie proofs for object inclusion/non-existence in state.
//! Format:
//! ```text
//! SBOQ-Version: 0.2
//! Path: /path/to/object/
//! Id: object-id
//! Creator: creator-id
//! Block: 12345
//! State-Root: <hex>
//! Object-Hash: <hex> | null
//! Proof-Format: trie
//! Proof-Length: <n>
//! Object-Length: <bytes>
//!
//! [{"segment":"seg1","siblings":{"other":"sha256:..."}},...]
//! <raw SBO object bytes>
//! ```

use thiserror::Error;
use sbo_crypto::{TrieProof, TrieProofStep, TrieError};
use std::collections::BTreeMap;

/// Error type for SBOQ parsing
#[derive(Debug, Error)]
pub enum SboqError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Missing header: {0}")]
    MissingHeader(String),
    #[error("Invalid hex: {0}")]
    InvalidHex(String),
    #[error("Invalid number: {0}")]
    InvalidNumber(String),
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),
    #[error("Trie error: {0}")]
    TrieError(String),
}

impl From<TrieError> for SboqError {
    fn from(e: TrieError) -> Self {
        SboqError::TrieError(e.to_string())
    }
}

/// SBOQ message for object inclusion/non-existence proofs (trie-based)
#[derive(Debug, Clone)]
pub struct SboqMessage {
    /// Version string (e.g., "0.2")
    pub version: String,
    /// Object path
    pub path: String,
    /// Object ID
    pub id: String,
    /// Creator ID
    pub creator: String,
    /// Block number of state root
    pub block: u64,
    /// State root this proof is against
    pub state_root: [u8; 32],
    /// Object hash (sha256 of raw SBO bytes), None for non-existence proof
    pub object_hash: Option<[u8; 32]>,
    /// Trie proof (path segments, siblings at each level)
    pub trie_proof: TrieProof,
    /// The raw SBO object being proven (optional)
    pub object: Option<Vec<u8>>,
}

/// Check if data is an SBOQ message
pub fn is_sboq_message(data: &[u8]) -> bool {
    data.starts_with(b"SBOQ-Version:")
}

/// Parse an SBOQ message from wire format
pub fn parse_sboq(data: &[u8]) -> Result<SboqMessage, SboqError> {
    // Find the blank line that separates headers from body
    let blank_line_pos = find_blank_line(data)
        .ok_or_else(|| SboqError::InvalidFormat("Missing blank line after headers".to_string()))?;

    let header_section = &data[..blank_line_pos];
    let body_start = blank_line_pos + 1; // Skip the blank line's newline

    let text = std::str::from_utf8(header_section)
        .map_err(|e| SboqError::InvalidFormat(e.to_string()))?;

    // Parse headers
    let mut version = None;
    let mut path = None;
    let mut id = None;
    let mut creator = None;
    let mut block = None;
    let mut state_root = None;
    let mut object_hash: Option<Option<[u8; 32]>> = None;
    let mut proof_format = None;
    let mut proof_length = None;
    let mut object_length = None;

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }

        let (key, value) = line.split_once(':')
            .ok_or_else(|| SboqError::InvalidFormat("Invalid header".to_string()))?;

        let value = value.trim();
        match key {
            "SBOQ-Version" => version = Some(value.to_string()),
            "Path" => path = Some(value.to_string()),
            "Id" => id = Some(value.to_string()),
            "Creator" => creator = Some(value.to_string()),
            "Block" => block = Some(value.parse::<u64>()
                .map_err(|e| SboqError::InvalidNumber(e.to_string()))?),
            "State-Root" => state_root = Some(parse_hex_32(value)?),
            "Object-Hash" => {
                if value == "null" {
                    object_hash = Some(None);
                } else {
                    object_hash = Some(Some(parse_hex_32(value)?));
                }
            }
            "Proof-Format" => proof_format = Some(value.to_string()),
            "Proof-Length" => proof_length = Some(value.parse::<usize>()
                .map_err(|e| SboqError::InvalidNumber(e.to_string()))?),
            "Object-Length" => object_length = Some(value.parse::<usize>()
                .map_err(|e| SboqError::InvalidNumber(e.to_string()))?),
            _ => {} // Ignore unknown headers
        }
    }

    // Validate proof format
    let fmt = proof_format.ok_or(SboqError::MissingHeader("Proof-Format".to_string()))?;
    if fmt != "trie" {
        return Err(SboqError::InvalidFormat(format!("Unknown proof format: {}", fmt)));
    }

    let proof_len = proof_length.ok_or(SboqError::MissingHeader("Proof-Length".to_string()))?;

    // Find the end of proof JSON (look for closing bracket then newline)
    let body = &data[body_start..];
    let proof_end = find_proof_end(body, proof_len)?;

    let proof_json = std::str::from_utf8(&body[..proof_end])
        .map_err(|e| SboqError::InvalidFormat(e.to_string()))?;

    // Parse proof JSON
    let proof_steps = parse_proof_json(proof_json)?;

    // Extract path segments from the proof steps
    let path_segments: Vec<String> = proof_steps.iter()
        .filter_map(|step| step.segment.clone())
        .collect();

    let state_root_val = state_root.ok_or(SboqError::MissingHeader("State-Root".to_string()))?;
    let object_hash_val = object_hash.ok_or(SboqError::MissingHeader("Object-Hash".to_string()))?;

    let trie_proof = TrieProof {
        state_root: state_root_val,
        path_segments,
        object_hash: object_hash_val,
        proof: proof_steps,
    };

    // Parse object if Object-Length was specified
    let obj_start = body_start + proof_end;
    let object_bytes = if let Some(obj_len) = object_length {
        if obj_len > 0 {
            let obj_end = obj_start + obj_len;
            if obj_end > data.len() {
                return Err(SboqError::InvalidFormat(
                    format!("Data too short for object: need {} bytes, have {}", obj_len, data.len() - obj_start)
                ));
            }
            Some(data[obj_start..obj_end].to_vec())
        } else {
            None
        }
    } else {
        None
    };

    Ok(SboqMessage {
        version: version.ok_or(SboqError::MissingHeader("SBOQ-Version".to_string()))?,
        path: path.ok_or(SboqError::MissingHeader("Path".to_string()))?,
        id: id.ok_or(SboqError::MissingHeader("Id".to_string()))?,
        creator: creator.ok_or(SboqError::MissingHeader("Creator".to_string()))?,
        block: block.ok_or(SboqError::MissingHeader("Block".to_string()))?,
        state_root: state_root_val,
        object_hash: object_hash_val,
        trie_proof,
        object: object_bytes,
    })
}

/// Find end of proof JSON array
fn find_proof_end(data: &[u8], _expected_len: usize) -> Result<usize, SboqError> {
    // Find the end of the JSON array (closing bracket followed by newline)
    let mut depth = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, &byte) in data.iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match byte {
            b'\\' if in_string => escape_next = true,
            b'"' => in_string = !in_string,
            b'[' if !in_string => depth += 1,
            b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    // Found the end of the array
                    // Skip any trailing newline
                    let mut end = i + 1;
                    if end < data.len() && data[end] == b'\n' {
                        end += 1;
                    }
                    return Ok(end);
                }
            }
            _ => {}
        }
    }

    Err(SboqError::InvalidFormat("Unterminated proof JSON array".to_string()))
}

/// Parse proof JSON into TrieProofStep vector
fn parse_proof_json(json: &str) -> Result<Vec<TrieProofStep>, SboqError> {
    // Parse as JSON array
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| SboqError::InvalidJson(e.to_string()))?;

    let arr = value.as_array()
        .ok_or_else(|| SboqError::InvalidJson("Expected JSON array".to_string()))?;

    let mut steps = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item.as_object()
            .ok_or_else(|| SboqError::InvalidJson("Expected JSON object in proof array".to_string()))?;

        // Parse segment (can be null for non-existence)
        let segment = match obj.get("segment") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Null) => None,
            None => None,
            _ => return Err(SboqError::InvalidJson("Invalid segment type".to_string())),
        };

        // Parse siblings
        let siblings_obj = obj.get("siblings")
            .and_then(|v| v.as_object())
            .ok_or_else(|| SboqError::InvalidJson("Missing siblings object".to_string()))?;

        let mut siblings = BTreeMap::new();
        for (key, val) in siblings_obj {
            let hash_str = val.as_str()
                .ok_or_else(|| SboqError::InvalidJson("Sibling hash must be string".to_string()))?;

            // Parse "sha256:<hex>" format
            let hex_part = hash_str.strip_prefix("sha256:")
                .ok_or_else(|| SboqError::InvalidJson("Hash must start with sha256:".to_string()))?;

            let hash = parse_hex_32(hex_part)?;
            siblings.insert(key.clone(), hash);
        }

        steps.push(TrieProofStep { segment, siblings });
    }

    Ok(steps)
}

/// Find the position of a blank line (empty line = just a newline after previous newline)
fn find_blank_line(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == b'\n' && data[i + 1] == b'\n' {
            return Some(i + 1); // Return position of the second newline
        }
    }
    None
}

/// Serialize an SBOQ message to wire format
pub fn serialize_sboq(msg: &SboqMessage) -> Vec<u8> {
    let mut output = String::new();

    // Headers
    output.push_str(&format!("SBOQ-Version: {}\n", msg.version));
    output.push_str(&format!("Path: {}\n", msg.path));
    output.push_str(&format!("Id: {}\n", msg.id));
    output.push_str(&format!("Creator: {}\n", msg.creator));
    output.push_str(&format!("Block: {}\n", msg.block));
    output.push_str(&format!("State-Root: {}\n", hex::encode(msg.state_root)));

    match msg.object_hash {
        Some(hash) => output.push_str(&format!("Object-Hash: {}\n", hex::encode(hash))),
        None => output.push_str("Object-Hash: null\n"),
    }

    output.push_str("Proof-Format: trie\n");
    output.push_str(&format!("Proof-Length: {}\n", msg.trie_proof.proof.len()));

    if let Some(ref obj) = msg.object {
        output.push_str(&format!("Object-Length: {}\n", obj.len()));
    }

    // Empty line separates headers from body
    output.push('\n');

    // Serialize proof steps as JSON array
    let proof_json = serialize_proof_json(&msg.trie_proof.proof);
    output.push_str(&proof_json);
    output.push('\n');

    // Convert to bytes
    let mut bytes = output.into_bytes();

    // Append object if present (raw bytes, no marker needed)
    if let Some(ref obj) = msg.object {
        bytes.extend_from_slice(obj);
    }

    bytes
}

/// Serialize proof steps to JSON
fn serialize_proof_json(steps: &[TrieProofStep]) -> String {
    let mut json = String::from("[");

    for (i, step) in steps.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }

        json.push_str("{\"segment\":");
        match &step.segment {
            Some(s) => {
                json.push('"');
                json.push_str(&escape_json_string(s));
                json.push('"');
            }
            None => json.push_str("null"),
        }

        json.push_str(",\"siblings\":{");
        let mut first = true;
        for (key, hash) in &step.siblings {
            if !first {
                json.push(',');
            }
            first = false;
            json.push('"');
            json.push_str(&escape_json_string(key));
            json.push_str("\":\"sha256:");
            json.push_str(&hex::encode(hash));
            json.push('"');
        }
        json.push_str("}}");
    }

    json.push(']');
    json
}

/// Escape special characters for JSON string
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], SboqError> {
    let bytes = hex::decode(s.trim())
        .map_err(|e| SboqError::InvalidHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(SboqError::InvalidHex(format!("Expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Create an SboqMessage from a TrieProof
#[allow(dead_code)]
pub fn sboq_from_trie_proof(
    path: &str,
    id: &str,
    creator: &str,
    block: u64,
    proof: TrieProof,
    object: Option<Vec<u8>>,
) -> SboqMessage {
    SboqMessage {
        version: "0.2".to_string(),
        path: path.to_string(),
        id: id.to_string(),
        creator: creator.to_string(),
        block,
        state_root: proof.state_root,
        object_hash: proof.object_hash,
        trie_proof: proof,
        object,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sboq_roundtrip() {
        let proof = TrieProof {
            state_root: [1u8; 32],
            path_segments: vec!["sys".to_string(), "names".to_string(), "user1".to_string(), "alice".to_string()],
            object_hash: Some([2u8; 32]),
            proof: vec![
                TrieProofStep {
                    segment: Some("sys".to_string()),
                    siblings: {
                        let mut m = BTreeMap::new();
                        m.insert("other".to_string(), [3u8; 32]);
                        m
                    },
                },
                TrieProofStep {
                    segment: Some("names".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: Some("user1".to_string()),
                    siblings: {
                        let mut m = BTreeMap::new();
                        m.insert("user2".to_string(), [4u8; 32]);
                        m
                    },
                },
                TrieProofStep {
                    segment: Some("alice".to_string()),
                    siblings: {
                        let mut m = BTreeMap::new();
                        m.insert("bob".to_string(), [5u8; 32]);
                        m
                    },
                },
            ],
        };

        let msg = SboqMessage {
            version: "0.2".to_string(),
            path: "/sys/names/".to_string(),
            id: "alice".to_string(),
            creator: "user1".to_string(),
            block: 12345,
            state_root: [1u8; 32],
            object_hash: Some([2u8; 32]),
            trie_proof: proof,
            object: None,
        };

        let serialized = serialize_sboq(&msg);
        assert!(is_sboq_message(&serialized));

        let parsed = parse_sboq(&serialized).expect("parse should succeed");
        assert_eq!(parsed.version, "0.2");
        assert_eq!(parsed.path, "/sys/names/");
        assert_eq!(parsed.id, "alice");
        assert_eq!(parsed.creator, "user1");
        assert_eq!(parsed.block, 12345);
        assert_eq!(parsed.state_root, [1u8; 32]);
        assert_eq!(parsed.object_hash, Some([2u8; 32]));
        assert_eq!(parsed.trie_proof.proof.len(), 4);
        assert!(parsed.object.is_none());
    }

    #[test]
    fn test_sboq_roundtrip_with_object() {
        let object_data = b"SBO-Version: 0.5\nPath: /sys/names/\nId: alice\n\n{\"hello\":\"world\"}";

        let proof = TrieProof {
            state_root: [1u8; 32],
            path_segments: vec!["sys".to_string(), "names".to_string(), "user1".to_string(), "alice".to_string()],
            object_hash: Some([2u8; 32]),
            proof: vec![
                TrieProofStep {
                    segment: Some("sys".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: Some("names".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: Some("user1".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: Some("alice".to_string()),
                    siblings: BTreeMap::new(),
                },
            ],
        };

        let msg = SboqMessage {
            version: "0.2".to_string(),
            path: "/sys/names/".to_string(),
            id: "alice".to_string(),
            creator: "user1".to_string(),
            block: 12345,
            state_root: [1u8; 32],
            object_hash: Some([2u8; 32]),
            trie_proof: proof,
            object: Some(object_data.to_vec()),
        };

        let serialized = serialize_sboq(&msg);
        let text = String::from_utf8_lossy(&serialized);
        assert!(text.contains("Object-Length:"));
        assert!(text.contains("Proof-Format: trie"));

        let parsed = parse_sboq(&serialized).expect("parse should succeed");
        assert_eq!(parsed.object, Some(object_data.to_vec()));
    }

    #[test]
    fn test_sboq_nonexistence() {
        let proof = TrieProof {
            state_root: [1u8; 32],
            path_segments: vec!["sys".to_string(), "names".to_string(), "user1".to_string(), "nonexistent".to_string()],
            object_hash: None,
            proof: vec![
                TrieProofStep {
                    segment: Some("sys".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: Some("names".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: Some("user1".to_string()),
                    siblings: BTreeMap::new(),
                },
                TrieProofStep {
                    segment: None, // Divergence point
                    siblings: {
                        let mut m = BTreeMap::new();
                        m.insert("alice".to_string(), [2u8; 32]);
                        m.insert("bob".to_string(), [3u8; 32]);
                        m
                    },
                },
            ],
        };

        let msg = SboqMessage {
            version: "0.2".to_string(),
            path: "/sys/names/".to_string(),
            id: "nonexistent".to_string(),
            creator: "user1".to_string(),
            block: 12345,
            state_root: [1u8; 32],
            object_hash: None,
            trie_proof: proof,
            object: None,
        };

        let serialized = serialize_sboq(&msg);
        let text = String::from_utf8_lossy(&serialized);
        assert!(text.contains("Object-Hash: null"));

        let parsed = parse_sboq(&serialized).expect("parse should succeed");
        assert!(parsed.object_hash.is_none());
    }

    #[test]
    fn test_is_sboq() {
        assert!(is_sboq_message(b"SBOQ-Version: 0.2\n"));
        assert!(!is_sboq_message(b"SBOP-Version: 0.2\n"));
        assert!(!is_sboq_message(b"random data"));
    }
}
