//! Local keyring for managing signing keys
//!
//! Keys are stored at `~/.sbo/keys/` with the following structure:
//! - `keyring.json` - Metadata index with public keys and associated identities
//! - `<alias>.key` - Secret key files (algorithm-prefixed hex)
//!
//! Security:
//! - Key files are created with mode 0600 (owner read/write only)
//! - Keys directory is created with mode 0700 (owner only)
//! - No encryption at rest; filesystem permissions provide protection

use crate::crypto::{PublicKey, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Key algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlgorithm {
    Ed25519,
    #[serde(rename = "bls12-381")]
    Bls12381,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Ed25519 => write!(f, "ed25519"),
            KeyAlgorithm::Bls12381 => write!(f, "bls12-381"),
        }
    }
}

/// Metadata entry for a key in the keyring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Algorithm used by this key
    pub algorithm: KeyAlgorithm,
    /// Public key in algorithm:hex format
    pub public_key: String,
    /// ISO 8601 timestamp when key was created/imported
    pub created_at: String,
    /// SBO URIs of identities associated with this key
    #[serde(default)]
    pub identities: Vec<String>,
}

/// Keyring metadata stored in keyring.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringMetadata {
    /// Format version (currently 1)
    pub version: u32,
    /// Default key alias (if set)
    pub default: Option<String>,
    /// Map of alias -> key entry
    pub keys: HashMap<String, KeyEntry>,
    /// Map of email -> SBO URI for identity discovery
    #[serde(default)]
    pub emails: HashMap<String, String>,
}

impl Default for KeyringMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            default: None,
            keys: HashMap::new(),
            emails: HashMap::new(),
        }
    }
}

/// Keyring error types
#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("Key '{0}' not found")]
    KeyNotFound(String),

    #[error("Key '{0}' already exists")]
    KeyExists(String),

    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid alias '{0}': {1}")]
    InvalidAlias(String, String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Local keyring for managing signing keys
pub struct Keyring {
    keys_dir: PathBuf,
    metadata: KeyringMetadata,
}

impl Keyring {
    /// Open or create keyring at default location (~/.sbo/keys/)
    pub fn open() -> Result<Self, KeyringError> {
        let sbo_dir = crate::sbo_dir();
        let keys_dir = sbo_dir.join("keys");
        Self::open_at(keys_dir)
    }

    /// Open or create keyring at custom path
    pub fn open_at(keys_dir: PathBuf) -> Result<Self, KeyringError> {
        // Create directory if needed
        if !keys_dir.exists() {
            std::fs::create_dir_all(&keys_dir)?;
        }

        // Always ensure directory has restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        // Load or create metadata
        let metadata_path = keys_dir.join("keyring.json");
        let metadata = if metadata_path.exists() {
            let content = std::fs::read_to_string(&metadata_path)?;
            serde_json::from_str(&content)?
        } else {
            KeyringMetadata::default()
        };

        Ok(Self { keys_dir, metadata })
    }

    /// Save metadata to keyring.json
    fn save(&self) -> Result<(), KeyringError> {
        let metadata_path = self.keys_dir.join("keyring.json");
        let temp_path = self.keys_dir.join("keyring.json.tmp");

        let content = serde_json::to_string_pretty(&self.metadata)?;
        std::fs::write(&temp_path, &content)?;

        // Set file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&temp_path, &metadata_path)?;
        Ok(())
    }

    /// Get path for a key file
    fn key_path(&self, alias: &str) -> PathBuf {
        self.keys_dir.join(format!("{}.key", alias))
    }

    /// Validate alias (alphanumeric, dash, underscore only)
    fn validate_alias(alias: &str) -> Result<(), KeyringError> {
        if alias.is_empty() {
            return Err(KeyringError::InvalidAlias(
                alias.to_string(),
                "alias cannot be empty".to_string(),
            ));
        }
        if !alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(KeyringError::InvalidAlias(
                alias.to_string(),
                "alias must contain only alphanumeric, dash, or underscore".to_string(),
            ));
        }
        Ok(())
    }

    /// Get current timestamp as ISO 8601 string
    fn now_iso8601() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = duration.as_secs();

        // Convert to datetime components (simplified, assumes UTC)
        let days = secs / 86400;
        let remaining = secs % 86400;
        let hours = remaining / 3600;
        let minutes = (remaining % 3600) / 60;
        let seconds = remaining % 60;

        // Calculate year/month/day from days since epoch (1970-01-01)
        // Simplified calculation that works for dates after 1970
        let mut year = 1970;
        let mut day_of_year = days;

        loop {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if day_of_year < days_in_year {
                break;
            }
            day_of_year -= days_in_year;
            year += 1;
        }

        let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_months: [u64; 12] = if is_leap {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut month = 0;
        for (i, &days_in_month) in days_in_months.iter().enumerate() {
            if day_of_year < days_in_month {
                month = i + 1;
                break;
            }
            day_of_year -= days_in_month;
        }
        let day = day_of_year + 1;

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }

    /// Generate a new Ed25519 key with the given alias
    pub fn generate(&mut self, alias: &str) -> Result<PublicKey, KeyringError> {
        Self::validate_alias(alias)?;

        if self.metadata.keys.contains_key(alias) {
            return Err(KeyringError::KeyExists(alias.to_string()));
        }

        // Generate new key
        let signing_key = SigningKey::generate();
        let public_key = signing_key.public_key();

        // Save secret key to file
        let key_content = format!("ed25519:{}", hex::encode(signing_key.to_bytes()));
        let key_path = self.key_path(alias);
        let temp_path = key_path.with_extension("key.tmp");

        std::fs::write(&temp_path, &key_content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&temp_path, &key_path)?;

        // Update metadata
        let entry = KeyEntry {
            algorithm: KeyAlgorithm::Ed25519,
            public_key: public_key.to_string(),
            created_at: Self::now_iso8601(),
            identities: Vec::new(),
        };
        self.metadata.keys.insert(alias.to_string(), entry);

        // Set as default if this is the first key
        if self.metadata.default.is_none() {
            self.metadata.default = Some(alias.to_string());
        }

        self.save()?;
        Ok(public_key)
    }

    /// Import a key from hex string (with algorithm prefix like "ed25519:...")
    pub fn import_hex(&mut self, alias: &str, hex_str: &str) -> Result<PublicKey, KeyringError> {
        Self::validate_alias(alias)?;

        if self.metadata.keys.contains_key(alias) {
            return Err(KeyringError::KeyExists(alias.to_string()));
        }

        // Parse algorithm prefix
        let (algorithm, key_hex) = if let Some(rest) = hex_str.strip_prefix("ed25519:") {
            (KeyAlgorithm::Ed25519, rest)
        } else if let Some(rest) = hex_str.strip_prefix("bls12-381:") {
            (KeyAlgorithm::Bls12381, rest)
        } else {
            // Assume ed25519 if no prefix (for backwards compatibility)
            (KeyAlgorithm::Ed25519, hex_str)
        };

        // Currently only Ed25519 signing is supported
        if algorithm != KeyAlgorithm::Ed25519 {
            return Err(KeyringError::UnsupportedAlgorithm(format!(
                "{} signing not yet implemented",
                algorithm
            )));
        }

        // Validate and parse key
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| KeyringError::InvalidFormat(format!("invalid hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(KeyringError::InvalidFormat(format!(
                "expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.public_key();

        // Save key file
        let key_content = format!("{}:{}", algorithm, key_hex);
        let key_path = self.key_path(alias);
        let temp_path = key_path.with_extension("key.tmp");

        std::fs::write(&temp_path, &key_content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&temp_path, &key_path)?;

        // Update metadata
        let entry = KeyEntry {
            algorithm,
            public_key: public_key.to_string(),
            created_at: Self::now_iso8601(),
            identities: Vec::new(),
        };
        self.metadata.keys.insert(alias.to_string(), entry);

        // Set as default if this is the first key
        if self.metadata.default.is_none() {
            self.metadata.default = Some(alias.to_string());
        }

        self.save()?;
        Ok(public_key)
    }

    /// Import a key from file
    pub fn import_file(&mut self, alias: &str, path: &Path) -> Result<PublicKey, KeyringError> {
        let content = std::fs::read_to_string(path)?;
        self.import_hex(alias, content.trim())
    }

    /// Export a key as hex string (with algorithm prefix)
    pub fn export(&self, alias: &str) -> Result<String, KeyringError> {
        if !self.metadata.keys.contains_key(alias) {
            return Err(KeyringError::KeyNotFound(alias.to_string()));
        }

        let key_path = self.key_path(alias);
        let content = std::fs::read_to_string(&key_path)?;
        Ok(content.trim().to_string())
    }

    /// Delete a key by alias
    pub fn delete(&mut self, alias: &str) -> Result<(), KeyringError> {
        if !self.metadata.keys.contains_key(alias) {
            return Err(KeyringError::KeyNotFound(alias.to_string()));
        }

        // Remove key file
        let key_path = self.key_path(alias);
        if key_path.exists() {
            std::fs::remove_file(&key_path)?;
        }

        // Remove from metadata
        self.metadata.keys.remove(alias);

        // Update default if we deleted it
        if self.metadata.default.as_deref() == Some(alias) {
            self.metadata.default = self.metadata.keys.keys().next().cloned();
        }

        self.save()?;
        Ok(())
    }

    /// List all keys in the keyring
    pub fn list(&self) -> &HashMap<String, KeyEntry> {
        &self.metadata.keys
    }

    /// Get SigningKey by alias (Ed25519 only for now)
    pub fn get_signing_key(&self, alias: &str) -> Result<SigningKey, KeyringError> {
        let entry = self
            .metadata
            .keys
            .get(alias)
            .ok_or_else(|| KeyringError::KeyNotFound(alias.to_string()))?;

        if entry.algorithm != KeyAlgorithm::Ed25519 {
            return Err(KeyringError::UnsupportedAlgorithm(format!(
                "{} signing not yet implemented",
                entry.algorithm
            )));
        }

        let key_content = self.export(alias)?;
        let key_hex = key_content
            .strip_prefix("ed25519:")
            .ok_or_else(|| KeyringError::InvalidFormat("missing ed25519: prefix".to_string()))?;

        let key_bytes = hex::decode(key_hex)
            .map_err(|e| KeyringError::InvalidFormat(format!("invalid hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(KeyringError::InvalidFormat(format!(
                "expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Get the default key alias
    pub fn default_key(&self) -> Option<&str> {
        self.metadata.default.as_deref()
    }

    /// Set the default key alias
    pub fn set_default(&mut self, alias: &str) -> Result<(), KeyringError> {
        if !self.metadata.keys.contains_key(alias) {
            return Err(KeyringError::KeyNotFound(alias.to_string()));
        }

        self.metadata.default = Some(alias.to_string());
        self.save()?;
        Ok(())
    }

    /// Associate an identity URI with a key
    pub fn add_identity(&mut self, alias: &str, uri: &str) -> Result<(), KeyringError> {
        let entry = self
            .metadata
            .keys
            .get_mut(alias)
            .ok_or_else(|| KeyringError::KeyNotFound(alias.to_string()))?;

        if !entry.identities.contains(&uri.to_string()) {
            entry.identities.push(uri.to_string());
            self.save()?;
        }

        Ok(())
    }

    /// Remove an identity URI from a key
    pub fn remove_identity(&mut self, alias: &str, uri: &str) -> Result<(), KeyringError> {
        let entry = self
            .metadata
            .keys
            .get_mut(alias)
            .ok_or_else(|| KeyringError::KeyNotFound(alias.to_string()))?;

        entry.identities.retain(|id| id != uri);
        self.save()?;

        Ok(())
    }

    /// Associate an email address with an SBO URI
    pub fn add_email(&mut self, email: &str, sbo_uri: &str) -> Result<(), KeyringError> {
        self.metadata.emails.insert(email.to_lowercase(), sbo_uri.to_string());
        self.save()?;
        Ok(())
    }

    /// Remove an email association
    pub fn remove_email(&mut self, email: &str) -> Result<(), KeyringError> {
        self.metadata.emails.remove(&email.to_lowercase());
        self.save()?;
        Ok(())
    }

    /// Look up SBO URI by email address
    pub fn get_email(&self, email: &str) -> Option<&str> {
        self.metadata.emails.get(&email.to_lowercase()).map(|s| s.as_str())
    }

    /// List all email -> SBO URI associations
    pub fn list_emails(&self) -> &HashMap<String, String> {
        &self.metadata.emails
    }

    /// Find the key alias that controls an identity URI
    pub fn find_key_for_identity(&self, identity_uri: &str) -> Option<&str> {
        for (alias, entry) in &self.metadata.keys {
            if entry.identities.iter().any(|uri| uri == identity_uri) {
                return Some(alias);
            }
        }
        None
    }

    /// Get or resolve the key alias (use default if None provided)
    /// Returns a String since the input lifetime may differ from self
    pub fn resolve_alias(&self, alias: Option<&str>) -> Result<String, KeyringError> {
        match alias {
            Some(a) => {
                if self.metadata.keys.contains_key(a) {
                    Ok(a.to_string())
                } else {
                    Err(KeyringError::KeyNotFound(a.to_string()))
                }
            }
            None => self
                .metadata
                .default
                .clone()
                .ok_or_else(|| KeyringError::KeyNotFound("no default key set".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_list() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        // Generate a key
        let pubkey = keyring.generate("test").unwrap();
        assert!(pubkey.to_string().starts_with("ed25519:"));

        // List should show the key
        let keys = keyring.list();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("test"));

        // Default should be set
        assert_eq!(keyring.default_key(), Some("test"));
    }

    #[test]
    fn test_import_export() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        // Generate and export
        keyring.generate("original").unwrap();
        let exported = keyring.export("original").unwrap();

        // Import to new alias
        keyring.import_hex("copy", &exported).unwrap();

        // Both should have same public key
        let keys = keyring.list();
        assert_eq!(
            keys.get("original").unwrap().public_key,
            keys.get("copy").unwrap().public_key
        );
    }

    #[test]
    fn test_delete() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        keyring.generate("test").unwrap();
        assert_eq!(keyring.list().len(), 1);

        keyring.delete("test").unwrap();
        assert_eq!(keyring.list().len(), 0);
        assert_eq!(keyring.default_key(), None);
    }

    #[test]
    fn test_set_default() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        keyring.generate("first").unwrap();
        keyring.generate("second").unwrap();

        assert_eq!(keyring.default_key(), Some("first"));

        keyring.set_default("second").unwrap();
        assert_eq!(keyring.default_key(), Some("second"));
    }

    #[test]
    fn test_identities() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        keyring.generate("test").unwrap();

        keyring
            .add_identity("test", "sbo+raw://avail:turing:506/sys/names/alice")
            .unwrap();

        let keys = keyring.list();
        let entry = keys.get("test").unwrap();
        assert_eq!(entry.identities.len(), 1);
        assert_eq!(
            entry.identities[0],
            "sbo+raw://avail:turing:506/sys/names/alice"
        );

        keyring
            .remove_identity("test", "sbo+raw://avail:turing:506/sys/names/alice")
            .unwrap();
        let keys = keyring.list();
        assert!(keys.get("test").unwrap().identities.is_empty());
    }

    #[test]
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();

        // Generate key in one instance
        {
            let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();
            keyring.generate("persistent").unwrap();
        }

        // Open again and verify it's still there
        {
            let keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();
            assert!(keyring.list().contains_key("persistent"));
        }
    }

    #[test]
    fn test_invalid_alias() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        assert!(keyring.generate("").is_err());
        assert!(keyring.generate("has space").is_err());
        assert!(keyring.generate("has/slash").is_err());
    }

    #[test]
    fn test_duplicate_key() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        keyring.generate("test").unwrap();
        assert!(keyring.generate("test").is_err());
    }

    #[test]
    fn test_emails() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        // Add email association
        keyring
            .add_email("alice@example.com", "sbo://example.com/sys/names/alice")
            .unwrap();

        // Lookup works (case insensitive)
        assert_eq!(
            keyring.get_email("alice@example.com"),
            Some("sbo://example.com/sys/names/alice")
        );
        assert_eq!(
            keyring.get_email("ALICE@Example.COM"),
            Some("sbo://example.com/sys/names/alice")
        );

        // List returns emails
        assert_eq!(keyring.list_emails().len(), 1);

        // Remove email
        keyring.remove_email("alice@example.com").unwrap();
        assert_eq!(keyring.get_email("alice@example.com"), None);
    }

    #[test]
    fn test_find_key_for_identity() {
        let temp_dir = TempDir::new().unwrap();
        let mut keyring = Keyring::open_at(temp_dir.path().to_path_buf()).unwrap();

        keyring.generate("mykey").unwrap();
        keyring
            .add_identity("mykey", "sbo://example.com/sys/names/alice")
            .unwrap();

        assert_eq!(
            keyring.find_key_for_identity("sbo://example.com/sys/names/alice"),
            Some("mykey")
        );
        assert_eq!(
            keyring.find_key_for_identity("sbo://other.com/sys/names/bob"),
            None
        );
    }
}
