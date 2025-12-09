//! Stored object type

use serde::{Deserialize, Serialize};
use crate::crypto::ContentHash;
use crate::message::{Id, Path};

/// An object stored in state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    pub path: Path,
    pub id: Id,
    pub creator: Id,
    pub owner: Id,
    pub content_type: String,
    pub content_hash: ContentHash,
    pub payload: Vec<u8>,
    pub policy_ref: Option<String>,
    pub block_number: u64,
}

// Custom serialization for Path and Id
impl Serialize for Path {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Path {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Path::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Id::new(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ContentHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ContentHash::parse(&s).map_err(serde::de::Error::custom)
    }
}
