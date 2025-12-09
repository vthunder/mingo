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

    /// Resolve policy by walking up the path hierarchy
    pub fn resolve_policy(&self, path: &crate::message::Path) -> Result<Option<Policy>, DbError> {
        let cf = self.db.cf_handle(CF_POLICIES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        for ancestor in path.ancestors() {
            let key = ancestor.to_string();
            if let Some(bytes) = self.db.get_cf(&cf, key.as_bytes())
                .map_err(|e| DbError::RocksDb(e.to_string()))? {
                let policy: Policy = serde_json::from_slice(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                return Ok(Some(policy));
            }
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
}

fn encode_object_key(
    path: &crate::message::Path,
    creator: &crate::message::Id,
    id: &crate::message::Id,
) -> Vec<u8> {
    format!("{}:{}:{}", path, creator, id).into_bytes()
}
