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
}

fn encode_object_key(
    path: &crate::message::Path,
    creator: &crate::message::Id,
    id: &crate::message::Id,
) -> Vec<u8> {
    format!("{}:{}:{}", path, creator, id).into_bytes()
}
