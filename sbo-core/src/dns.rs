//! DNS resolution for sbo:// URIs
//!
//! Resolves sbo://domain.com/ URIs via DNS TXT records at _sbo.domain.com

use std::fmt;

/// Parsed SBO DNS record
#[derive(Debug, Clone, PartialEq)]
pub struct SboRecord {
    /// CAIP-2 chain identifier (e.g., "avail:mainnet")
    pub chain: String,
    /// Application ID on the chain
    pub app_id: u32,
    /// Genesis hash for verification (e.g., "sha256:abc123...")
    pub genesis: Option<String>,
    /// Block number containing genesis
    pub first_block: Option<u64>,
    /// URL for bootstrap checkpoint
    pub checkpoint: Option<String>,
    /// URL of full node for data fetching
    pub node: Option<String>,
}

/// DNS resolution error
#[derive(Debug, Clone)]
pub enum DnsError {
    /// No _sbo. TXT record found
    NoRecord,
    /// Record exists but is malformed
    MalformedRecord(String),
    /// Unsupported version (e.g., sbo=v2)
    UnsupportedVersion(String),
    /// DNS lookup failed
    LookupFailed(String),
    /// URI is not an sbo:// URI
    NotSboUri,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NoRecord => write!(f, "No SBO DNS record found"),
            DnsError::MalformedRecord(msg) => write!(f, "Malformed SBO record: {}", msg),
            DnsError::UnsupportedVersion(v) => write!(f, "Unsupported SBO record version: {}", v),
            DnsError::LookupFailed(msg) => write!(f, "DNS lookup failed: {}", msg),
            DnsError::NotSboUri => write!(f, "Not an sbo:// URI"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Parse a DNS TXT record into an SboRecord
///
/// Format: "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc..."
pub fn parse_record(txt: &str) -> Result<SboRecord, DnsError> {
    let mut version: Option<&str> = None;
    let mut chain: Option<&str> = None;
    let mut app_id: Option<u32> = None;
    let mut genesis: Option<String> = None;
    let mut first_block: Option<u64> = None;
    let mut checkpoint: Option<String> = None;
    let mut node: Option<String> = None;

    for part in txt.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "sbo" => version = Some(value),
                "chain" => chain = Some(value),
                "appId" => {
                    app_id = Some(value.parse().map_err(|_| {
                        DnsError::MalformedRecord(format!("invalid appId: {}", value))
                    })?);
                }
                "genesis" => genesis = Some(value.to_string()),
                "firstBlock" => {
                    first_block = Some(value.parse().map_err(|_| {
                        DnsError::MalformedRecord(format!("invalid firstBlock: {}", value))
                    })?);
                }
                "checkpoint" => checkpoint = Some(value.to_string()),
                "node" => node = Some(value.to_string()),
                _ => {} // Ignore unknown fields for forward compatibility
            }
        }
    }

    // Validate version
    match version {
        Some("v1") => {}
        Some(v) => return Err(DnsError::UnsupportedVersion(v.to_string())),
        None => return Err(DnsError::MalformedRecord("missing sbo version".to_string())),
    }

    // Validate required fields
    let chain = chain
        .ok_or_else(|| DnsError::MalformedRecord("missing chain".to_string()))?
        .to_string();

    let app_id = app_id.ok_or_else(|| DnsError::MalformedRecord("missing appId".to_string()))?;

    Ok(SboRecord {
        chain,
        app_id,
        genesis,
        first_block,
        checkpoint,
        node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_record() {
        let txt = "sbo=v1 chain=avail:mainnet appId=13";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.chain, "avail:mainnet");
        assert_eq!(record.app_id, 13);
        assert_eq!(record.genesis, None);
        assert_eq!(record.first_block, None);
        assert_eq!(record.checkpoint, None);
        assert_eq!(record.node, None);
    }

    #[test]
    fn test_parse_full_record() {
        let txt = "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc123 firstBlock=1000 checkpoint=https://example.com/cp.json node=https://sbo.example.com";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.chain, "avail:mainnet");
        assert_eq!(record.app_id, 13);
        assert_eq!(record.genesis, Some("sha256:abc123".to_string()));
        assert_eq!(record.first_block, Some(1000));
        assert_eq!(record.checkpoint, Some("https://example.com/cp.json".to_string()));
        assert_eq!(record.node, Some("https://sbo.example.com".to_string()));
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "chain=avail:mainnet appId=13";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_unsupported_version() {
        let txt = "sbo=v2 chain=avail:mainnet appId=13";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_parse_missing_chain() {
        let txt = "sbo=v1 appId=13";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_missing_app_id() {
        let txt = "sbo=v1 chain=avail:mainnet";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let txt = "sbo=v1 chain=avail:mainnet appId=13 futureField=whatever";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.app_id, 13);
    }
}
