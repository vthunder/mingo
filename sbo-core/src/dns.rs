//! DNS resolution for sbo:// URIs and email identity discovery
//!
//! - Resolves sbo://domain.com/ URIs via DNS TXT records at _sbo.domain.com
//! - Discovers SBO identities for email addresses via _sbo-id.domain.com + .well-known

use std::fmt;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use serde::Deserialize;

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

// ============================================================================
// Service Discovery (/.well-known/sbo)
// ============================================================================

/// Discovery document from /.well-known/sbo
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    /// Protocol version (e.g., "1")
    pub version: String,
    /// Path to user-visible login page (e.g., "/sbo/login")
    #[serde(default)]
    pub authentication: Option<String>,
    /// Path to session binding initiation endpoint (e.g., "/sbo/session")
    #[serde(default)]
    pub provisioning: Option<String>,
    /// Path to session binding poll endpoint (e.g., "/sbo/session/poll")
    #[serde(default)]
    pub provisioning_poll: Option<String>,
    /// Delegation to another host (if present, fetch discovery from there instead)
    #[serde(default)]
    pub authority: Option<String>,
}

/// Fetch the discovery document from a host
///
/// Fetches GET https://{host}/.well-known/sbo?domain={domain}
/// Follows delegation if `authority` is present.
pub async fn fetch_discovery(host: &str, domain: &str) -> Result<DiscoveryDocument, DnsError> {
    fetch_discovery_with_depth(host, domain, 0).await
}

/// Internal: fetch discovery with recursion depth limit
fn fetch_discovery_with_depth<'a>(
    host: &'a str,
    domain: &'a str,
    depth: u8,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<DiscoveryDocument, DnsError>> + Send + 'a>> {
    Box::pin(async move {
        if depth > 5 {
            return Err(DnsError::LookupFailed("too many delegation hops".into()));
        }

        let url = format!("https://{}/.well-known/sbo?domain={}", host, domain);

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| DnsError::LookupFailed(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(DnsError::LookupFailed(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        let doc: DiscoveryDocument = response
            .json()
            .await
            .map_err(|e| DnsError::MalformedRecord(format!("invalid JSON response: {}", e)))?;

        // Follow delegation if present
        if let Some(ref authority) = doc.authority {
            return fetch_discovery_with_depth(authority, domain, depth + 1).await;
        }

        Ok(doc)
    })
}

/// Get the discovery host for a domain
///
/// Returns the h= field from DNS if present, otherwise the domain itself.
pub fn get_discovery_host(record: &SboRecord, domain: &str) -> String {
    record
        .discovery_host
        .clone()
        .unwrap_or_else(|| format!("https://{}", domain))
}

// ============================================================================
// Email Identity Discovery
// ============================================================================

/// Parsed _sbo-id DNS record for identity discovery
#[derive(Debug, Clone, PartialEq)]
pub struct SboIdRecord {
    /// Host serving the identity discovery endpoint
    pub host: String,
}

/// Identity discovery response from .well-known endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityDiscoveryResponse {
    /// Protocol version
    pub version: u32,
    /// SBO URI for the identity
    pub sbo_uri: String,
}

/// Parse a _sbo-id DNS TXT record
///
/// Format: "v=sbo-id1 host=example.com"
pub fn parse_sbo_id_record(txt: &str) -> Result<SboIdRecord, DnsError> {
    let mut version: Option<&str> = None;
    let mut host: Option<&str> = None;

    for part in txt.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "v" => version = Some(value),
                "host" => host = Some(value),
                _ => {} // Ignore unknown fields
            }
        }
    }

    // Validate version
    match version {
        Some("sbo-id1") => {}
        Some(v) => return Err(DnsError::UnsupportedVersion(v.to_string())),
        None => return Err(DnsError::MalformedRecord("missing v= version".to_string())),
    }

    // Validate required fields
    let host = host
        .ok_or_else(|| DnsError::MalformedRecord("missing host".to_string()))?
        .to_string();

    Ok(SboIdRecord { host })
}

/// Resolve identity discovery host for a domain via DNS
///
/// Queries _sbo-id.{domain} for TXT records
pub async fn resolve_identity_host(domain: &str) -> Result<SboIdRecord, DnsError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let lookup_name = format!("_sbo-id.{}", domain);

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

        match parse_sbo_id_record(&txt) {
            Ok(sbo_id_record) => return Ok(sbo_id_record),
            Err(e) => last_error = e,
        }
    }

    Err(last_error)
}

/// Discover the SBO URI for an email address
///
/// 1. Parses email into user@domain
/// 2. Queries DNS for _sbo-id.{domain} to get discovery host
/// 3. Fetches https://{host}/.well-known/sbo-identity/{domain}/{user}
/// 4. Returns the sbo_uri from the response
pub async fn resolve_email(email: &str) -> Result<String, DnsError> {
    // Parse email
    let (user, domain) = email
        .split_once('@')
        .ok_or_else(|| DnsError::MalformedRecord(format!("invalid email: {}", email)))?;

    if user.is_empty() || domain.is_empty() {
        return Err(DnsError::MalformedRecord(format!("invalid email: {}", email)));
    }

    // Look up identity host via DNS
    let sbo_id = resolve_identity_host(domain).await?;

    // Fetch .well-known endpoint
    let url = format!(
        "https://{}/.well-known/sbo-identity/{}/{}",
        sbo_id.host, domain, user
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| DnsError::LookupFailed(format!("HTTP request failed: {}", e)))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(DnsError::NoRecord);
    }

    if !response.status().is_success() {
        return Err(DnsError::LookupFailed(format!(
            "HTTP {} from {}",
            response.status(),
            url
        )));
    }

    let discovery: IdentityDiscoveryResponse = response
        .json()
        .await
        .map_err(|e| DnsError::MalformedRecord(format!("invalid JSON response: {}", e)))?;

    if discovery.version != 1 {
        return Err(DnsError::UnsupportedVersion(format!("v{}", discovery.version)));
    }

    Ok(discovery.sbo_uri)
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

    // Identity discovery tests

    #[test]
    fn test_parse_sbo_id_record() {
        let txt = "v=sbo-id1 host=id.example.com";
        let record = parse_sbo_id_record(txt).unwrap();
        assert_eq!(record.host, "id.example.com");
    }

    #[test]
    fn test_parse_sbo_id_record_missing_version() {
        let txt = "host=id.example.com";
        let err = parse_sbo_id_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_sbo_id_record_wrong_version() {
        let txt = "v=sbo-id2 host=id.example.com";
        let err = parse_sbo_id_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_parse_sbo_id_record_missing_host() {
        let txt = "v=sbo-id1";
        let err = parse_sbo_id_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
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
