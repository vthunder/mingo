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
    /// The object's `Content-Schema` header, if any. Persisted so the resolver
    /// can distinguish a key-rooted `identity.v1` name record from an
    /// email-rooted `identity.email.v1` one without re-parsing the payload blind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_schema: Option<String>,
    /// The object's `Owner` header (the controller reference: a bare email or a
    /// local name), if any. Distinct from `owner` (the signer's public key under
    /// the legacy key-rooted model). This is what L2 attribution authorizes
    /// against for email-rooted objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    pub block_number: u64,
    /// SHA-256 hash of the complete raw SBO object bytes (headers + payload)
    /// Used for merkle tree leaf computation in the proof system
    #[serde(default, skip_serializing_if = "is_zero_hash")]
    pub object_hash: [u8; 32],
}

fn is_zero_hash(h: &[u8; 32]) -> bool {
    h == &[0u8; 32]
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
