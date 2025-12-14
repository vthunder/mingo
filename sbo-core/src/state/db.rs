//! RocksDB state storage

use std::path::Path;
use crate::error::DbError;
use super::objects::StoredObject;
use crate::policy::Policy;

/// State database backed by RocksDB
pub struct StateDb {
    db: rocksdb::DB,
}

// Column family names
const CF_OBJECTS: &str = "objects";
const CF_BY_OWNER: &str = "by_owner";
const CF_POLICIES: &str = "policies";
const CF_NAMES: &str = "names";
const CF_META: &str = "meta";
const CF_STATE_ROOTS: &str = "state_roots";
const CF_PROOFS: &str = "proofs";

/// A verified proof stored in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProof {
    /// Block range start
    pub block_from: u64,
    /// Block range end
    pub block_to: u64,
    /// Receipt kind (composite, succinct, groth16)
    pub receipt_kind: String,
    /// The raw receipt bytes
    pub receipt_bytes: Vec<u8>,
    /// Block number where this proof was received
    pub received_at_block: u64,
    /// Whether this proof was verified
    pub verified: bool,
}

impl StateDb {
    /// Open or create the database at the given path
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_OBJECTS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_BY_OWNER, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_POLICIES, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_NAMES, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_META, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_STATE_ROOTS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_PROOFS, rocksdb::Options::default()),
        ];

        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| DbError::RocksDb(e.to_string()))?;

        Ok(Self { db })
    }

    /// Get an object by path and ID
    pub fn get_object(
        &self,
        path: &crate::message::Path,
        creator: &crate::message::Id,
        id: &crate::message::Id,
    ) -> Result<Option<StoredObject>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = encode_object_key(path, creator, id);

        match self.db.get_cf(&cf, &key) {
            Ok(Some(bytes)) => {
                let obj: StoredObject = serde_json::from_slice(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(obj))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Store an object
    pub fn put_object(&self, obj: &StoredObject) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = encode_object_key(&obj.path, &obj.creator, &obj.id);
        let value = serde_json::to_vec(obj)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        self.db.put_cf(&cf, &key, &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Delete an object
    pub fn delete_object(
        &self,
        path: &crate::message::Path,
        creator: &crate::message::Id,
        id: &crate::message::Id,
    ) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = encode_object_key(path, creator, id);

        self.db.delete_cf(&cf, &key)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Check if any object exists at a given path and id (regardless of creator)
    /// This is used for enforcing uniqueness on name claims
    pub fn object_exists_at_path_id(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<bool, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Prefix is "path:" to find all objects at this path
        let prefix = format!("{}:", path);
        let suffix = format!(":{}", id);

        let iter = self.db.prefix_iterator_cf(&cf, prefix.as_bytes());
        for item in iter {
            match item {
                Ok((key, _value)) => {
                    // Check if the key ends with our ID
                    let key_str = String::from_utf8_lossy(&key);
                    if key_str.ends_with(&suffix) {
                        return Ok(true);
                    }
                    // Stop if we've moved past our prefix
                    if !key_str.starts_with(&prefix) {
                        break;
                    }
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }

        Ok(false)
    }

    /// Get the first object at a given path and id (regardless of creator)
    /// Returns the StoredObject if found
    pub fn get_first_object_at_path_id(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<Option<StoredObject>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let prefix = format!("{}:", path);
        let suffix = format!(":{}", id);

        let iter = self.db.prefix_iterator_cf(&cf, prefix.as_bytes());
        for item in iter {
            match item {
                Ok((key, value)) => {
                    let key_str = String::from_utf8_lossy(&key);
                    if key_str.ends_with(&suffix) {
                        let obj: StoredObject = serde_json::from_slice(&value)
                            .map_err(|e| DbError::Serialization(e.to_string()))?;
                        return Ok(Some(obj));
                    }
                    if !key_str.starts_with(&prefix) {
                        break;
                    }
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }

        Ok(None)
    }

    /// Store a policy at a path
    /// The policy applies to the given path and all descendants
    pub fn put_policy(&self, path: &crate::message::Path, policy: &Policy) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_POLICIES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = path.to_string();
        let value = serde_json::to_vec(policy)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        self.db.put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Resolve policy by walking up the path hierarchy
    /// Falls back to root policy at /sys/policies/ if no path-specific policy found
    pub fn resolve_policy(&self, path: &crate::message::Path) -> Result<Option<Policy>, DbError> {
        let cf = self.db.cf_handle(CF_POLICIES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // First, walk up the path hierarchy for path-specific policies
        for ancestor in path.ancestors() {
            let key = ancestor.to_string();
            if let Some(bytes) = self.db.get_cf(&cf, key.as_bytes())
                .map_err(|e| DbError::RocksDb(e.to_string()))? {
                let policy: Policy = serde_json::from_slice(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                return Ok(Some(policy));
            }
        }

        // Fall back to root policy at /sys/policies/
        // This is where the genesis root policy is stored
        if let Some(bytes) = self.db.get_cf(&cf, b"/sys/policies/")
            .map_err(|e| DbError::RocksDb(e.to_string()))? {
            let policy: Policy = serde_json::from_slice(&bytes)
                .map_err(|e| DbError::Serialization(e.to_string()))?;
            return Ok(Some(policy));
        }

        Ok(None)
    }

    /// Get the last processed block number
    pub fn get_last_block(&self) -> Result<Option<u64>, DbError> {
        let cf = self.db.cf_handle(CF_META).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, b"last_block") {
            Ok(Some(bytes)) => {
                let block = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Set the last processed block number
    pub fn set_last_block(&self, block: u64) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_META).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.put_cf(&cf, b"last_block", &block.to_le_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Store a name claim mapping: pubkey -> name
    /// This is called when a name claim object is stored at /sys/names/<name>
    pub fn put_name_claim(&self, pubkey: &str, name: &str) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_NAMES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Store pubkey -> name mapping
        self.db.put_cf(&cf, pubkey.as_bytes(), name.as_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Look up a name for a public key
    /// Returns the claimed name if this pubkey has one, None otherwise
    pub fn get_name_for_pubkey(&self, pubkey: &str) -> Result<Option<String>, DbError> {
        let cf = self.db.cf_handle(CF_NAMES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, pubkey.as_bytes()) {
            Ok(Some(bytes)) => {
                let name = String::from_utf8(bytes.to_vec())
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(name))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Delete a name claim mapping
    pub fn delete_name_claim(&self, pubkey: &str) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_NAMES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.delete_cf(&cf, pubkey.as_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    // ========== State Root Tracking ==========

    /// Record the state root after processing a block
    pub fn record_state_root(&self, block: u64, state_root: [u8; 32]) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.put_cf(&cf, &block.to_be_bytes(), &state_root)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Get the state root at a specific block
    pub fn get_state_root_at_block(&self, block: u64) -> Result<Option<[u8; 32]>, DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, &block.to_be_bytes()) {
            Ok(Some(bytes)) => {
                let root: [u8; 32] = bytes.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid state root length".to_string()))?;
                Ok(Some(root))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Get the latest recorded state root and its block number
    pub fn get_latest_state_root(&self) -> Result<Option<(u64, [u8; 32])>, DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Iterate in reverse to find latest
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_last();

        if iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                let block = u64::from_be_bytes(key.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid block key".to_string()))?);
                let root: [u8; 32] = value.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid state root".to_string()))?;
                return Ok(Some((block, root)));
            }
        }

        Ok(None)
    }

    /// Get the state root at or before a specific block
    /// Returns the most recent state root recorded at or before the given block.
    /// This handles the case where a state root was recorded at block N,
    /// and we're verifying a proof for block N+k where nothing changed.
    pub fn get_state_root_at_or_before(&self, block: u64) -> Result<Option<(u64, [u8; 32])>, DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut iter = self.db.raw_iterator_cf(&cf);

        // seek_for_prev finds the largest key <= target
        // This handles both exact matches and "nothing after" cases correctly
        iter.seek_for_prev(&block.to_be_bytes());

        if iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if let Ok(found_block_bytes) = <[u8; 8]>::try_from(key) {
                    let found_block = u64::from_be_bytes(found_block_bytes);
                    // Verify this is actually <= the requested block
                    if found_block <= block {
                        if let Ok(root) = <[u8; 32]>::try_from(value) {
                            return Ok(Some((found_block, root)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    // ========== Proof Storage ==========

    /// Store a verified proof
    /// Key is block_from:block_to for easy range queries
    pub fn put_proof(&self, proof: &StoredProof) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let key = format!("{}:{}", proof.block_from, proof.block_to);
        let value = serde_json::to_vec(proof)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        self.db.put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Get a proof by block range
    pub fn get_proof(&self, block_from: u64, block_to: u64) -> Result<Option<StoredProof>, DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let key = format!("{}:{}", block_from, block_to);

        match self.db.get_cf(&cf, key.as_bytes()) {
            Ok(Some(bytes)) => {
                let proof: StoredProof = serde_json::from_slice(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Get a proof that covers a specific block number
    pub fn get_proof_for_block(&self, block: u64) -> Result<Option<StoredProof>, DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Iterate through all proofs to find one covering this block
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            match item {
                Ok((_key, value)) => {
                    let proof: StoredProof = serde_json::from_slice(&value)
                        .map_err(|e| DbError::Serialization(e.to_string()))?;
                    if proof.block_from <= block && block <= proof.block_to {
                        return Ok(Some(proof));
                    }
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }
        Ok(None)
    }

    // ========== Trie State Root ==========

    /// Convert an object's path, creator, and id to trie path segments
    /// E.g., path="/sys/names/", creator="user123", id="alice" -> ["sys", "names", "user123", "alice"]
    pub fn object_to_segments(
        path: &crate::message::Path,
        creator: &crate::message::Id,
        id: &crate::message::Id,
    ) -> Vec<String> {
        let mut segments: Vec<String> = path.segments()
            .iter()
            .map(|id| id.as_str().to_string())
            .collect();
        segments.push(creator.as_str().to_string());
        segments.push(id.as_str().to_string());
        segments
    }

    /// Get all objects for computing trie state root
    /// Returns list of (path_segments, object_hash) tuples
    pub fn get_all_objects_for_trie(&self) -> Result<Vec<(Vec<String>, [u8; 32])>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut objects: Vec<(Vec<String>, [u8; 32])> = Vec::new();

        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            match item {
                Ok((_key, value)) => {
                    let obj: StoredObject = serde_json::from_slice(&value)
                        .map_err(|e| DbError::Serialization(e.to_string()))?;

                    let segments = Self::object_to_segments(&obj.path, &obj.creator, &obj.id);
                    objects.push((segments, obj.object_hash));
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }

        Ok(objects)
    }

    /// Compute trie state root from all objects
    /// Returns [0u8; 32] if no objects exist
    pub fn compute_trie_state_root(&self) -> Result<[u8; 32], DbError> {
        let objects = self.get_all_objects_for_trie()?;
        if objects.is_empty() {
            return Ok([0u8; 32]);
        }
        Ok(sbo_crypto::compute_trie_root(&objects))
    }

    /// Generate a trie proof for a specific object
    /// Returns TrieProof or None if object doesn't exist
    pub fn generate_trie_proof(
        &self,
        path: &crate::message::Path,
        creator: &crate::message::Id,
        id: &crate::message::Id,
    ) -> Result<Option<sbo_crypto::TrieProof>, DbError> {
        // Get the object first to verify it exists
        if self.get_object(path, creator, id)?.is_none() {
            return Ok(None);
        }

        // Build trie from all objects
        let all_objects = self.get_all_objects_for_trie()?;
        let mut trie = sbo_crypto::SparseTrie::new();
        for (segments, object_hash) in &all_objects {
            trie.insert(segments.clone(), *object_hash);
        }

        // Generate proof for target object
        let target_segments = Self::object_to_segments(path, creator, id);
        match trie.generate_proof(&target_segments) {
            Ok(proof) => Ok(Some(proof)),
            Err(_) => Ok(None),
        }
    }

    /// Generate a trie proof for an object by path and id, auto-detecting creator
    /// Returns (creator, TrieProof) or None if object doesn't exist
    pub fn generate_trie_proof_auto(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<Option<(crate::message::Id, sbo_crypto::TrieProof)>, DbError> {
        // Find the object (auto-detects creator)
        let obj = match self.get_first_object_at_path_id(path, id)? {
            Some(o) => o,
            None => return Ok(None),
        };

        // Now generate the proof using the found creator
        match self.generate_trie_proof(path, &obj.creator, id)? {
            Some(proof) => Ok(Some((obj.creator, proof))),
            None => Ok(None),
        }
    }
}

fn encode_object_key(
    path: &crate::message::Path,
    creator: &crate::message::Id,
    id: &crate::message::Id,
) -> Vec<u8> {
    format!("{}:{}:{}", path, creator, id).into_bytes()
}
