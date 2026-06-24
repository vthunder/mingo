//! `collection.v1` descriptor — declares **how** a collection's writes reach
//! durability and its content-layer parameters (see the SBO Content Specification
//! §Durability Tiers). It lives at the collection root with `ID: _config`.
//!
//! The descriptor is a **submission/read concern, not a validity rule**: a write
//! is a perfectly valid envelope regardless of tier. The one place it touches
//! validity is `max_authoring_lag_s` — the collection's `W`, the back-dating
//! bound the daemon feeds into the HLC validity check. Absent a descriptor a
//! collection defaults to **on-chain** with a small `W`.

use serde::Deserialize;

use super::{SchemaError, SchemaResult};
use crate::message::Message;

/// The conventional object `ID` of a collection descriptor at its root path.
pub const COLLECTION_CONFIG_ID: &str = "_config";

/// Durability tier (Content Spec §Durability Tiers). `on-chain` and `batched`
/// differ only in submission cadence — their guarantees are identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Durability {
    /// One write per DA submission (lowest latency, highest cost). The default.
    OnChain,
    /// Many writes per periodic DA submission (amortized cost, identical
    /// guarantees).
    Batched,
}

impl Default for Durability {
    fn default() -> Self {
        Durability::OnChain
    }
}

/// A parsed `collection.v1` descriptor.
#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    /// `on-chain` (default) or `batched`.
    #[serde(default)]
    pub durability: Durability,
    /// Target flush interval (seconds) for `batched`.
    #[serde(default)]
    pub batch_interval_s: Option<i64>,
    /// The collection's `W` (max authoring lag, seconds); default small.
    #[serde(default)]
    pub max_authoring_lag_s: Option<i64>,
    /// Expected content schema for objects in the collection.
    #[serde(default)]
    pub schema: Option<String>,
}

/// Parse a `collection.v1` payload.
pub fn parse_collection(payload: &[u8]) -> SchemaResult<Collection> {
    Ok(serde_json::from_slice(payload)?)
}

/// Validate a `collection.v1` message's payload. All fields are optional; the
/// only constraints are types (enforced by serde — an unknown `durability` value
/// is rejected) and that numeric fields, when present, are non-negative.
pub fn validate_collection(msg: &Message) -> SchemaResult<()> {
    let payload = msg.payload.as_ref().ok_or(SchemaError::EmptyPayload)?;
    let collection = parse_collection(payload)?;
    for (field, value) in [
        ("batch_interval_s", collection.batch_interval_s),
        ("max_authoring_lag_s", collection.max_authoring_lag_s),
    ] {
        if let Some(v) = value {
            if v < 0 {
                return Err(SchemaError::InvalidField {
                    field: field.into(),
                    reason: format!("{field} ({v}) must be non-negative"),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_on_chain() {
        let c = parse_collection(br#"{}"#).unwrap();
        assert_eq!(c.durability, Durability::OnChain);
        assert!(c.max_authoring_lag_s.is_none());
    }

    #[test]
    fn parses_batched_descriptor() {
        let c = parse_collection(
            br#"{"durability":"batched","batch_interval_s":5,"max_authoring_lag_s":3600,"schema":"post.v1"}"#,
        )
        .unwrap();
        assert_eq!(c.durability, Durability::Batched);
        assert_eq!(c.batch_interval_s, Some(5));
        assert_eq!(c.max_authoring_lag_s, Some(3600));
        assert_eq!(c.schema.as_deref(), Some("post.v1"));
    }

    #[test]
    fn rejects_unknown_durability() {
        assert!(parse_collection(br#"{"durability":"off-chain"}"#).is_err());
    }
}
