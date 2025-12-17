//! Repository management
//!
//! Handles the set of followed SBO repositories.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Known chain aliases that map to CAIP-2 identifiers
/// Format: (alias_namespace, alias_reference) -> (caip2_namespace, caip2_reference)
const CHAIN_ALIASES: &[(&str, &str, &str, &str)] = &[
    // avail:turing -> polkadot:<genesis_hash_prefix>
    ("avail", "turing", "polkadot", "d3d2f3a3495dc597434a99d7d449ebad"),
    // avail:mainnet -> polkadot:<genesis_hash_prefix>
    ("avail", "mainnet", "polkadot", "b91746b45e0346cc2f815a520b9c6cb4"),
];

/// A CAIP-2 chain identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainId {
    /// Namespace (e.g., "polkadot", "eip155", "avail")
    pub namespace: String,
    /// Reference (e.g., genesis hash prefix, chain id)
    pub reference: String,
}

impl ChainId {
    /// Parse a CAIP-2 chain identifier like "polkadot:abc123" or "avail:turing"
    pub fn parse(s: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(crate::DaemonError::Repo(format!(
                "Invalid CAIP-2 chain identifier: expected 'namespace:reference', got: {}",
                s
            )));
        }

        let namespace = parts[0].to_lowercase();
        let reference = parts[1].to_lowercase();

        Ok(Self { namespace, reference })
    }

    /// Resolve aliases to canonical CAIP-2 identifiers
    pub fn resolve(&self) -> Self {
        for (alias_ns, alias_ref, caip_ns, caip_ref) in CHAIN_ALIASES {
            if self.namespace == *alias_ns && self.reference == *alias_ref {
                return Self {
                    namespace: caip_ns.to_string(),
                    reference: caip_ref.to_string(),
                };
            }
        }
        // No alias found, return as-is
        self.clone()
    }

    /// Check if this is an Avail chain (mainnet or turing)
    pub fn is_avail(&self) -> bool {
        let resolved = self.resolve();
        resolved.namespace == "polkadot" && (
            resolved.reference == "d3d2f3a3495dc597434a99d7d449ebad" ||  // turing
            resolved.reference == "b91746b45e0346cc2f815a520b9c6cb4"    // mainnet
        )
    }

    /// Get the display name for this chain
    pub fn display_name(&self) -> String {
        // Check if we can use a friendly alias
        for (alias_ns, alias_ref, caip_ns, caip_ref) in CHAIN_ALIASES {
            if self.namespace == *caip_ns && self.reference == *caip_ref {
                return format!("{}:{}", alias_ns, alias_ref);
            }
        }
        format!("{}:{}", self.namespace, self.reference)
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

/// Parsed SBO URI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SboUri {
    /// CAIP-2 chain identifier
    pub chain: ChainId,
    /// App ID on the network
    pub app_id: u32,
    /// Optional path prefix filter
    pub path_prefix: Option<String>,
}

impl SboUri {
    /// Parse a raw SBO URI like "sbo+raw://avail:turing:18/" or "sbo+raw://polkadot:abc123:42/nft/"
    ///
    /// Note: This only handles direct chain references (sbo+raw://).
    /// DNS-resolved URIs (sbo://) require resolution first - see SboUri::resolve_dns().
    pub fn parse(uri: &str) -> crate::Result<Self> {
        let uri = uri.trim();

        // Only accept sbo+raw:// for direct chain references
        // sbo:// URIs require DNS resolution first
        let rest = if uri.starts_with("sbo+raw://") {
            &uri[10..] // Remove "sbo+raw://"
        } else if uri.starts_with("sbo://") {
            return Err(crate::DaemonError::Repo(format!(
                "DNS-based URI requires resolution: {}. Use sbo+raw:// for direct chain references.",
                uri
            )));
        } else {
            return Err(crate::DaemonError::Repo(format!(
                "Invalid SBO URI: must start with 'sbo+raw://' for direct chain references: {}",
                uri
            )));
        };

        // Split authority from path
        let (authority, path) = if let Some(idx) = rest.find('/') {
            (&rest[..idx], Some(&rest[idx..]))
        } else {
            (rest, None)
        };

        // Parse namespace:reference:app_id
        let parts: Vec<&str> = authority.split(':').collect();
        if parts.len() != 3 {
            return Err(crate::DaemonError::Repo(format!(
                "Invalid SBO URI authority: expected 'namespace:reference:app_id', got: {}",
                authority
            )));
        }

        let chain = ChainId {
            namespace: parts[0].to_lowercase(),
            reference: parts[1].to_lowercase(),
        };

        let app_id: u32 = parts[2].parse().map_err(|_| {
            crate::DaemonError::Repo(format!("Invalid app_id: {}", parts[2]))
        })?;

        let path_prefix = path.map(|p| p.to_string()).filter(|p| p != "/");

        Ok(Self {
            chain,
            app_id,
            path_prefix,
        })
    }

    /// Convert back to URI string (using friendly aliases where possible)
    pub fn to_string(&self) -> String {
        let chain_str = self.chain.display_name();
        match &self.path_prefix {
            Some(prefix) => format!("sbo+raw://{}:{}{}", chain_str, self.app_id, prefix),
            None => format!("sbo+raw://{}:{}/", chain_str, self.app_id),
        }
    }

    /// Convert to canonical URI string (using full CAIP-2 identifiers)
    pub fn to_canonical_string(&self) -> String {
        let resolved = self.chain.resolve();
        match &self.path_prefix {
            Some(prefix) => format!("sbo+raw://{}:{}{}", resolved, self.app_id, prefix),
            None => format!("sbo+raw://{}:{}/", resolved, self.app_id),
        }
    }
}

/// A followed repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    /// Unique identifier (hash of URI)
    pub id: String,
    /// The SBO URI
    pub uri: SboUri,
    /// Display URI (may be sbo:// DNS-based or sbo+raw://)
    pub display_uri: String,
    /// Local filesystem path
    pub path: PathBuf,
    /// Last synced block number
    pub head: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Last DNS check timestamp (None if never checked, or sbo+raw://)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_checked_at: Option<u64>,
}

impl Repo {
    /// Create a new repo with optional starting block
    pub fn new(display_uri: String, uri: SboUri, path: PathBuf, from_block: Option<u64>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let id = Self::compute_id(&uri);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // head is set to from_block - 1 so syncing starts AT from_block
        // (sync processes blocks from head+1 onwards)
        let head = from_block.map(|b| b.saturating_sub(1)).unwrap_or(0);

        // Set dns_checked_at to now if display_uri is sbo://, None for sbo+raw://
        let dns_checked_at = if display_uri.starts_with("sbo://") {
            Some(now)
        } else {
            None
        };

        Self {
            id,
            uri,
            display_uri,
            path,
            head,
            created_at: now,
            dns_checked_at,
        }
    }

    fn compute_id(uri: &SboUri) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(uri.to_string().as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }

    /// Get the state database for this repo
    pub fn state_db(&self) -> crate::Result<sbo_core::state::StateDb> {
        let repo_dir = crate::repo_dir_for_uri(&self.uri.to_string());
        let state_dir = repo_dir.join("state");
        sbo_core::state::StateDb::open(&state_dir)
            .map_err(|e| crate::DaemonError::Repo(format!("Failed to open state db: {}", e)))
    }
}

/// Manages the set of followed repositories
pub struct RepoManager {
    repos: HashMap<String, Repo>,
    index_path: PathBuf,
}

impl RepoManager {
    /// Load repos from index file
    pub fn load(index_path: PathBuf) -> crate::Result<Self> {
        let repos = if index_path.exists() {
            let content = std::fs::read_to_string(&index_path)?;
            let list: Vec<Repo> = serde_json::from_str(&content)
                .map_err(|e| crate::DaemonError::Repo(format!("Failed to parse repos index: {}", e)))?;
            list.into_iter().map(|r| (r.id.clone(), r)).collect()
        } else {
            HashMap::new()
        };

        Ok(Self {
            repos,
            index_path,
        })
    }

    /// Save repos to index file
    pub fn save(&self) -> crate::Result<()> {
        let list: Vec<&Repo> = self.repos.values().collect();
        let content = serde_json::to_string_pretty(&list)
            .map_err(|e| crate::DaemonError::Repo(format!("Failed to serialize repos: {}", e)))?;

        if let Some(parent) = self.index_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.index_path, content)?;
        Ok(())
    }

    /// Add a new repo with optional starting block
    pub fn add(&mut self, display_uri: String, uri: SboUri, path: PathBuf, from_block: Option<u64>) -> crate::Result<&Repo> {
        // Create repo directory first (needed for canonicalization)
        std::fs::create_dir_all(&path)?;

        // Canonicalize path so ./foo and /full/path/to/foo are treated the same
        let canonical_path = path.canonicalize().map_err(|e| {
            crate::DaemonError::Repo(format!("Cannot canonicalize path {}: {}", path.display(), e))
        })?;

        // Check if path is already used
        for repo in self.repos.values() {
            if repo.path == canonical_path {
                return Err(crate::DaemonError::Repo(format!(
                    "Path already used by repo {}: {}",
                    repo.uri.to_string(),
                    canonical_path.display()
                )));
            }
        }

        let repo = Repo::new(display_uri, uri.clone(), canonical_path, from_block);
        let id = repo.id.clone();

        // Create repo metadata directory using sanitized URI
        let repo_dir = crate::repo_dir_for_uri(&uri.to_string());
        std::fs::create_dir_all(&repo_dir)?;

        // Write repo config
        let config_path = repo_dir.join("config.json");
        let config_content = serde_json::to_string_pretty(&repo)
            .map_err(|e| crate::DaemonError::Repo(format!("Failed to serialize repo config: {}", e)))?;
        std::fs::write(config_path, config_content)?;

        self.repos.insert(id.clone(), repo);
        self.save()?;

        Ok(self.repos.get(&id).unwrap())
    }

    /// Remove a repo by path
    pub fn remove(&mut self, path: &Path) -> crate::Result<Repo> {
        // Canonicalize path for consistent lookup (stored paths are canonical)
        let canonical = path.canonicalize().map_err(|e| {
            crate::DaemonError::Repo(format!("Cannot canonicalize path {}: {}", path.display(), e))
        })?;

        let id = self
            .repos
            .iter()
            .find(|(_, r)| r.path == canonical)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| crate::DaemonError::Repo(format!("No repo at path: {}", canonical.display())))?;

        let repo = self.repos.remove(&id).unwrap();

        // Remove repo directory (includes config.json and state/)
        let repo_dir = crate::repo_dir_for_uri(&repo.uri.to_string());
        if repo_dir.exists() {
            tracing::info!("Removing repo directory at {}", repo_dir.display());
            std::fs::remove_dir_all(&repo_dir)?;
        }

        self.save()?;
        Ok(repo)
    }

    /// Remove a repo by URI
    pub fn remove_by_uri(&mut self, uri: &str) -> crate::Result<Repo> {
        // Parse and normalize the URI
        let parsed = SboUri::parse(uri)?;
        let normalized = parsed.to_string();

        let id = self
            .repos
            .iter()
            .find(|(_, r)| r.uri.to_string() == normalized)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| crate::DaemonError::Repo(format!("No repo with URI: {}", uri)))?;

        let repo = self.repos.remove(&id).unwrap();

        // Remove repo directory (includes config.json and state/)
        let repo_dir = crate::repo_dir_for_uri(&repo.uri.to_string());
        if repo_dir.exists() {
            tracing::info!("Removing repo directory at {}", repo_dir.display());
            std::fs::remove_dir_all(&repo_dir)?;
        }

        self.save()?;
        Ok(repo)
    }

    /// List all repos
    pub fn list(&self) -> impl Iterator<Item = &Repo> {
        self.repos.values()
    }

    /// Get repo by path
    pub fn get_by_path(&self, path: &Path) -> Option<&Repo> {
        self.repos.values().find(|r| r.path == path)
    }

    /// Find repo by path (alternative name for consistency with plan)
    pub fn find_by_path(&self, path: &Path) -> Option<&Repo> {
        self.get_by_path(path)
    }

    /// Get repo by path (mutable)
    pub fn get_by_path_mut(&mut self, path: &Path) -> Option<&mut Repo> {
        self.repos.values_mut().find(|r| r.path == path)
    }

    /// Get repos by app_id
    pub fn get_by_app_id(&self, app_id: u32) -> Vec<&Repo> {
        self.repos
            .values()
            .filter(|r| r.uri.app_id == app_id)
            .collect()
    }

    /// Update repo head and save
    pub fn update_head(&mut self, path: &Path, head: u64) -> crate::Result<()> {
        // Find the repo and get its ID and URI first
        let repo_info = self
            .repos
            .values()
            .find(|r| r.path == path)
            .map(|r| (r.id.clone(), r.uri.to_string()));

        if let Some((id, uri)) = repo_info {
            // Now we can mutate
            if let Some(repo) = self.repos.get_mut(&id) {
                repo.head = head;
            }

            // Update metadata file using URI-based path
            let repo_dir = crate::repo_dir_for_uri(&uri);
            let head_path = repo_dir.join("head");
            std::fs::write(head_path, head.to_string())?;

            self.save()?;
        }
        Ok(())
    }

    /// Get all unique app_ids being followed
    pub fn followed_app_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.repos.values().map(|r| r.uri.app_id).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Update a repo's resolved URI (for DNS relink)
    pub fn update_uri(&mut self, id: &str, display_uri: String, new_uri: SboUri) -> crate::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let repo = self.repos.get_mut(id)
            .ok_or_else(|| crate::DaemonError::Repo(format!("Repo not found: {}", id)))?;

        repo.display_uri = display_uri;
        repo.uri = new_uri;
        repo.head = 0; // Reset to re-sync
        repo.dns_checked_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sbo_uri_with_alias() {
        // Test with sbo+raw:// (correct format)
        let uri = SboUri::parse("sbo+raw://avail:turing:13/").unwrap();
        assert_eq!(uri.chain.namespace, "avail");
        assert_eq!(uri.chain.reference, "turing");
        assert_eq!(uri.app_id, 13);
        assert!(uri.path_prefix.is_none());

        // Verify alias resolution
        let resolved = uri.chain.resolve();
        assert_eq!(resolved.namespace, "polkadot");
        assert_eq!(resolved.reference, "d3d2f3a3495dc597434a99d7d449ebad");
    }

    #[test]
    fn test_sbo_dns_uri_requires_resolution() {
        // sbo:// URIs are DNS-based and require resolution - they should not parse directly
        let err = SboUri::parse("sbo://myapp.com/path").unwrap_err();
        assert!(err.to_string().contains("DNS-based URI requires resolution"));
    }

    #[test]
    fn test_parse_sbo_uri_with_caip2() {
        let uri = SboUri::parse("sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:42/nft/").unwrap();
        assert_eq!(uri.chain.namespace, "polkadot");
        assert_eq!(uri.chain.reference, "d3d2f3a3495dc597434a99d7d449ebad");
        assert_eq!(uri.app_id, 42);
        assert_eq!(uri.path_prefix, Some("/nft/".to_string()));
    }

    #[test]
    fn test_sbo_uri_roundtrip() {
        // Alias should display as alias with sbo+raw://
        let uri = SboUri::parse("sbo+raw://avail:turing:13/").unwrap();
        assert_eq!(uri.to_string(), "sbo+raw://avail:turing:13/");

        // Full CAIP-2 for known chain should display as alias
        let uri = SboUri::parse("sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:42/").unwrap();
        assert_eq!(uri.to_string(), "sbo+raw://avail:turing:42/");

        // Unknown chain should display as full CAIP-2
        let uri = SboUri::parse("sbo+raw://eip155:1:99/").unwrap();
        assert_eq!(uri.to_string(), "sbo+raw://eip155:1:99/");
    }

    #[test]
    fn test_canonical_string() {
        let uri = SboUri::parse("sbo+raw://avail:turing:13/nft/").unwrap();
        assert_eq!(
            uri.to_canonical_string(),
            "sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:13/nft/"
        );
    }

    #[test]
    fn test_chain_is_avail() {
        let turing = ChainId::parse("avail:turing").unwrap();
        assert!(turing.is_avail());

        let mainnet = ChainId::parse("avail:mainnet").unwrap();
        assert!(mainnet.is_avail());

        let eth = ChainId::parse("eip155:1").unwrap();
        assert!(!eth.is_avail());
    }
}
