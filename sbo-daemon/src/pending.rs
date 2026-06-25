//! In-memory mempool overlay — the shared optimistic tip.
//!
//! Holds **validated-but-unconfirmed** writes that have been accepted at submit
//! time but have not yet landed in a confirmed Avail block. The overlay is
//! served on top of confirmed state to **all** clients of the daemon, hiding
//! Avail's block latency (~20s) behind a ~1s perceived latency.
//!
//! Honest about trust: entries here are a *mempool*, never proof-backed. The
//! `state-root` always reflects the last confirmed block; overlay objects are
//! flagged `confirmed: false` so the UI can render them as pending.
//!
//! Eviction is **TTL-only** (no dependency-cascade handling): an entry is
//! dropped when its write confirms (reconciliation) or when its TTL elapses
//! (failed submission / lost an LWW race). The pool is transient — lost on
//! restart, which is acceptable.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use sbo_core::message::{Id, Path};
use sbo_core::state::StoredObject;

/// Default time-to-live for a pending entry (~3 Avail blocks). A write that
/// never confirms within this window is swept.
pub const DEFAULT_TTL_SECS: i64 = 60;

/// A shared handle to the pending pool. Uses `std::sync::RwLock` (not the async
/// tokio one) so it can be locked from the synchronous read helpers and from
/// `write_object` in the sync task without crossing an await point.
pub type SharedPending = Arc<RwLock<PendingPool>>;

/// A single validated-but-unconfirmed write held in the overlay.
struct PendingEntry {
    /// Pre-rendered stored object, ready for read-merge / `build_object_view`.
    obj: StoredObject,
    /// SHA-256 of the full re-serialized wire bytes — matches the `object_hash`
    /// the sync task computes when the write confirms (used for reconciliation).
    object_hash: [u8; 32],
    /// Unix seconds when the write was accepted (for TTL sweeping).
    submitted_at: i64,
}

/// In-memory pool of pending writes, keyed by `(path, id)`.
///
/// A `(path, id)` holds at most one entry (last-writer-wins by HLC), matching
/// the `(path, id)` dedup the read views already apply over confirmed state.
#[derive(Default)]
pub struct PendingPool {
    entries: HashMap<(String, String), PendingEntry>,
}

impl PendingPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a validated write into the overlay. A later submit at
    /// the same `(path, id)` replaces the earlier one — the user's most recent
    /// action is what the optimistic tip should show.
    pub fn insert(&mut self, obj: StoredObject, object_hash: [u8; 32], now: i64) {
        let key = (obj.path.to_string(), obj.id.as_str().to_string());
        self.entries.insert(
            key,
            PendingEntry {
                obj,
                object_hash,
                submitted_at: now,
            },
        );
    }

    /// Reconcile against a write that just **confirmed** in a block. Drop the
    /// shadow if the exact write landed (hash match) or if the confirmed value
    /// supersedes it by HLC (we lost an LWW race / a newer write won).
    pub fn reconcile_applied(&mut self, confirmed: &StoredObject) {
        let key = (
            confirmed.path.to_string(),
            confirmed.id.as_str().to_string(),
        );
        let Some(entry) = self.entries.get(&key) else {
            return;
        };
        if entry.object_hash == confirmed.object_hash || !pending_still_wins(&entry.obj, confirmed) {
            self.entries.remove(&key);
        }
    }

    /// Evict entries older than `ttl` seconds (writes that never confirmed).
    /// Returns the number swept.
    pub fn sweep_expired(&mut self, now: i64, ttl: i64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now.saturating_sub(e.submitted_at) < ttl);
        before - self.entries.len()
    }

    /// The pending object at `(path, id)`, if any.
    pub fn object_at(&self, path: &Path, id: &Id) -> Option<&StoredObject> {
        self.entries
            .get(&(path.to_string(), id.as_str().to_string()))
            .map(|e| &e.obj)
    }

    /// All pending objects whose path starts with `prefix`.
    pub fn objects_under_prefix(&self, prefix: &str) -> Vec<&StoredObject> {
        self.entries
            .values()
            .map(|e| &e.obj)
            .filter(|o| o.path.to_string().starts_with(prefix))
            .collect()
    }

    /// All pending objects carrying the given `Content-Schema`.
    pub fn objects_by_schema(&self, schema: &str) -> Vec<&StoredObject> {
        self.entries
            .values()
            .map(|e| &e.obj)
            .filter(|o| o.content_schema.as_deref() == Some(schema))
            .collect()
    }

    /// An owned snapshot of every pending object, for building a read overlay
    /// without holding the pool lock across validation.
    pub fn snapshot(&self) -> Vec<StoredObject> {
        self.entries.values().map(|e| e.obj.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Whether a pending object still wins the LWW order against a confirmed value
/// at the same `(path, id)`. Mirrors `validate::lww_admits` but compares two
/// `StoredObject`s. If either side lacks a parseable `HLC`, the confirmed value
/// is treated as authoritative (pending no longer wins) — the safe default for
/// reconciliation, since the write is now on-chain.
fn pending_still_wins(pending: &StoredObject, confirmed: &StoredObject) -> bool {
    let (Some(p_hlc), Some(c_hlc)) = (&pending.hlc, &confirmed.hlc) else {
        return false;
    };
    let (Ok(p_hlc), Ok(c_hlc)) = (
        sbo_core::hlc::Hlc::parse(p_hlc),
        sbo_core::hlc::Hlc::parse(c_hlc),
    ) else {
        return false;
    };
    let p_key = sbo_core::hlc::LwwKey {
        hlc: p_hlc,
        signer: pending.owner.as_str(),
        object_hash: &pending.object_hash,
    };
    let c_key = sbo_core::hlc::LwwKey {
        hlc: c_hlc,
        signer: confirmed.owner.as_str(),
        object_hash: &confirmed.object_hash,
    };
    sbo_core::hlc::lww_wins(p_key, c_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbo_core::crypto::ContentHash;

    fn obj(path: &str, id: &str, hlc: Option<&str>, hash: u8) -> StoredObject {
        StoredObject {
            path: Path::parse(path).unwrap(),
            id: Id::new(id).unwrap(),
            creator: Id::new("alice@mingo.place").unwrap(),
            owner: Id::new("ed25519:00").unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(b"{}"),
            payload: b"{}".to_vec(),
            policy_ref: None,
            content_schema: Some("post.v1".to_string()),
            owner_ref: Some("alice@mingo.place".to_string()),
            block_number: 1,
            object_hash: [hash; 32],
            hlc: hlc.map(|s| s.to_string()),
            prev: None,
        }
    }

    #[test]
    fn insert_and_object_at_roundtrip() {
        let mut pool = PendingPool::new();
        let o = obj("/c/x/", "p1", None, 1);
        pool.insert(o.clone(), [1; 32], 100);
        let got = pool.object_at(&o.path, &o.id).unwrap();
        assert_eq!(got.id.as_str(), "p1");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn sweep_evicts_only_expired() {
        let mut pool = PendingPool::new();
        pool.insert(obj("/c/x/", "old", None, 1), [1; 32], 0);
        pool.insert(obj("/c/x/", "new", None, 2), [2; 32], 100);
        let swept = pool.sweep_expired(120, DEFAULT_TTL_SECS);
        assert_eq!(swept, 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn reconcile_drops_shadow_on_hash_match() {
        let mut pool = PendingPool::new();
        let o = obj("/c/x/", "p1", None, 7);
        pool.insert(o.clone(), [7; 32], 100);
        // Same write confirms (hash matches) → shadow evicted.
        pool.reconcile_applied(&o);
        assert!(pool.is_empty());
    }

    #[test]
    fn reconcile_keeps_newer_pending_on_hlc() {
        let mut pool = PendingPool::new();
        // Pending has a higher HLC than the confirmed write at the same key.
        pool.insert(obj("/c/x/", "p1", Some("100.0"), 9), [9; 32], 100);
        let confirmed = obj("/c/x/", "p1", Some("50.0"), 1);
        pool.reconcile_applied(&confirmed);
        // Pending still wins LWW → kept (a newer write hasn't confirmed yet).
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn prefix_and_schema_selectors() {
        let mut pool = PendingPool::new();
        pool.insert(obj("/c/x/", "p1", None, 1), [1; 32], 100);
        pool.insert(obj("/d/y/", "p2", None, 2), [2; 32], 100);
        assert_eq!(pool.objects_under_prefix("/c/").len(), 1);
        assert_eq!(pool.objects_by_schema("post.v1").len(), 2);
        assert_eq!(pool.objects_by_schema("comment.v1").len(), 0);
    }
}

/// Whether a pending object should overlay (win against) a confirmed value at
/// the same `(path, id)` for read-merge. If the pending side carries a
/// parseable `HLC` newer than the confirmed one it wins; if HLCs are missing or
/// unparseable, the pending (more recently submitted) value wins so the
/// optimistic tip reflects the latest user action.
pub fn overlay_wins(pending: &StoredObject, confirmed: &StoredObject) -> bool {
    let (Some(p_hlc), Some(c_hlc)) = (&pending.hlc, &confirmed.hlc) else {
        return true;
    };
    let (Ok(p_hlc), Ok(c_hlc)) = (
        sbo_core::hlc::Hlc::parse(p_hlc),
        sbo_core::hlc::Hlc::parse(c_hlc),
    ) else {
        return true;
    };
    let p_key = sbo_core::hlc::LwwKey {
        hlc: p_hlc,
        signer: pending.owner.as_str(),
        object_hash: &pending.object_hash,
    };
    let c_key = sbo_core::hlc::LwwKey {
        hlc: c_hlc,
        signer: confirmed.owner.as_str(),
        object_hash: &confirmed.object_hash,
    };
    sbo_core::hlc::lww_wins(p_key, c_key)
}
