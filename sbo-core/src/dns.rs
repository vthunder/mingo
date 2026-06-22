//! DNS resolution for sbo:// URIs and email identity discovery
//!
//! - Resolves sbo://domain.com/ URIs via DNS TXT records at _sbo.domain.com
//! - Discovers SBO identities for email addresses via _sbo-id.domain.com + .well-known

use std::fmt;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

/// Parsed SBO DNS record
#[derive(Debug, Clone, PartialEq)]
pub struct SboRecord {
    /// Repository URI (e.g., "sbo+raw://avail:turing:506/")
    pub repository_uri: String,
    /// Discovery host for .well-known/sbo (optional, defaults to domain itself)
    pub discovery_host: Option<String>,
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
/// Format: "v=sbo1 r=sbo+raw://avail:turing:506/ h=https://auth.example.com"
pub fn parse_record(txt: &str) -> Result<SboRecord, DnsError> {
    let mut version: Option<&str> = None;
    let mut repository_uri: Option<String> = None;
    let mut discovery_host: Option<String> = None;

    for part in txt.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "v" => version = Some(value),
                "r" => repository_uri = Some(value.to_string()),
                "h" => discovery_host = Some(value.to_string()),
                _ => {} // Ignore unknown fields for forward compatibility
            }
        }
    }

    // Validate version
    match version {
        Some("sbo1") => {}
        Some(v) => return Err(DnsError::UnsupportedVersion(v.to_string())),
        None => return Err(DnsError::MalformedRecord("missing v= version".to_string())),
    }

    // Validate required fields
    let repository_uri = repository_uri
        .ok_or_else(|| DnsError::MalformedRecord("missing r= repository URI".to_string()))?;

    Ok(SboRecord {
        repository_uri,
        discovery_host,
    })
}

/// Resolve a domain to an SBO record via DNS TXT lookup
///
/// Queries _sbo.{domain} for TXT records
pub async fn resolve(domain: &str) -> Result<SboRecord, DnsError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let lookup_name = format!("_sbo.{}", domain);

    let response = resolver
        .txt_lookup(&lookup_name)
        .await
        .map_err(|e| {
            use hickory_resolver::error::ResolveErrorKind;
            match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => DnsError::NoRecord,
                _ => DnsError::LookupFailed(e.to_string()),
            }
        })?;

    // Try each TXT record until we find a valid one
    let mut last_error = DnsError::NoRecord;
    for record in response.iter() {
        let txt: String = record.iter()
            .map(|data| String::from_utf8_lossy(data))
            .collect();

        match parse_record(&txt) {
            Ok(sbo_record) => return Ok(sbo_record),
            Err(e) => last_error = e,
        }
    }

    Err(last_error)
}

/// Convert an sbo:// URI to sbo+raw:// using DNS resolution
///
/// Example: sbo://myapp.com/alice/nft -> sbo+raw://avail:turing:506/alice/nft
pub async fn resolve_uri(uri: &str) -> Result<String, DnsError> {
    let uri = uri.trim();

    if !uri.starts_with("sbo://") {
        return Err(DnsError::NotSboUri);
    }

    // Parse: sbo://domain.com/path/to/thing
    let rest = &uri[6..]; // Remove "sbo://"

    let (domain, path) = if let Some(idx) = rest.find('/') {
        (&rest[..idx], &rest[idx..])
    } else {
        (rest, "/")
    };

    let record = resolve(domain).await?;

    // Combine repository URI with path
    let base = record.repository_uri.trim_end_matches('/');
    Ok(format!("{}{}", base, path))
}

/// Extract domain from an sbo:// URI
///
/// Returns None if not an sbo:// URI
pub fn extract_domain(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if !uri.starts_with("sbo://") {
        return None;
    }

    let rest = &uri[6..];
    let domain = if let Some(idx) = rest.find('/') {
        &rest[..idx]
    } else {
        rest
    };

    Some(domain.to_string())
}

/// Check if a URI is a DNS-based sbo:// URI
pub fn is_dns_uri(uri: &str) -> bool {
    uri.trim().starts_with("sbo://")
}

/// Get the discovery host for a domain
///
/// Returns the h= field from DNS if present, otherwise the domain itself.
/// Returns just the hostname - callers add the scheme.
pub fn get_discovery_host(record: &SboRecord, domain: &str) -> String {
    record
        .discovery_host
        .clone()
        .unwrap_or_else(|| domain.to_string())
}

/// Parse an email address into (user, domain)
pub fn parse_email(email: &str) -> Option<(&str, &str)> {
    let (user, domain) = email.split_once('@')?;
    if user.is_empty() || domain.is_empty() {
        return None;
    }
    Some((user, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_record() {
        let txt = "v=sbo1 r=sbo+raw://avail:turing:506/";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.repository_uri, "sbo+raw://avail:turing:506/");
        assert_eq!(record.discovery_host, None);
    }

    #[test]
    fn test_parse_full_record() {
        let txt = "v=sbo1 r=sbo+raw://avail:mainnet:13/ h=https://auth.example.com";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.repository_uri, "sbo+raw://avail:mainnet:13/");
        assert_eq!(record.discovery_host, Some("https://auth.example.com".to_string()));
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "r=sbo+raw://avail:turing:506/";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_unsupported_version() {
        let txt = "v=sbo2 r=sbo+raw://avail:turing:506/";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_parse_missing_repository_uri() {
        let txt = "v=sbo1 h=https://auth.example.com";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let txt = "v=sbo1 r=sbo+raw://avail:turing:506/ futureField=whatever";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.repository_uri, "sbo+raw://avail:turing:506/");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("sbo://myapp.com/path"), Some("myapp.com".to_string()));
        assert_eq!(extract_domain("sbo://myapp.com/"), Some("myapp.com".to_string()));
        assert_eq!(extract_domain("sbo://myapp.com"), Some("myapp.com".to_string()));
        assert_eq!(extract_domain("sbo+raw://avail:mainnet:13/"), None);
    }

    #[test]
    fn test_is_dns_uri() {
        assert!(is_dns_uri("sbo://myapp.com/"));
        assert!(is_dns_uri("sbo://myapp.com/path/to/thing"));
        assert!(!is_dns_uri("sbo+raw://avail:mainnet:13/"));
        assert!(!is_dns_uri("https://example.com"));
    }

    #[test]
    fn test_parse_email() {
        assert_eq!(parse_email("alice@example.com"), Some(("alice", "example.com")));
        assert_eq!(parse_email("user@sub.domain.org"), Some(("user", "sub.domain.org")));
        assert_eq!(parse_email("invalid"), None);
        assert_eq!(parse_email("@domain.com"), None);
        assert_eq!(parse_email("user@"), None);
        assert_eq!(parse_email(""), None);
    }
}
