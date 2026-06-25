//! Read-side abstraction over confirmed (and optionally pending) state.
//!
//! Phase A validated submits against **confirmed** state only (`&StateDb`).
//! Phase B introduces [`StateView`] — the small read surface the validator
//! actually needs — so validation can run against either confirmed state
//! ([`StateDb`]) or confirmed **+ pending** state ([`Overlay`]).
//!
//! The overlay merges the mempool's optimistic tip on top of confirmed state,
//! enabling chained optimistic writes (e.g. `join` → `post` in the same window)
//! to validate before the earlier write has landed in a block. Pending entries
//! win against confirmed values at the same `(path, id)` by the same LWW rule
//! the read-merge uses ([`crate::pending::overlay_wins`]).

use std::collections::HashMap;

use sbo_core::error::DbError;
use sbo_core::message::{Id, Path};
use sbo_core::policy::Policy;
use sbo_core::state::{StateDb, StoredObject};

use crate::pending::overlay_wins;

/// The read surface validation depends on. Implemented by [`StateDb`]
/// (confirmed-only) and [`Overlay`] (confirmed + pending).
pub trait StateView {
    /// Fetch the object at `(path, creator, id)`.
    fn get_object(
        &self,
        path: &Path,
        creator: &Id,
        id: &Id,
    ) -> Result<Option<StoredObject>, DbError>;

    /// Fetch the first object at `(path, id)`, regardless of creator.
    fn get_first_object_at_path_id(
        &self,
        path: &Path,
        id: &Id,
    ) -> Result<Option<StoredObject>, DbError>;

    /// Resolve the effective policy governing `path` (nearest ancestor, then root).
    fn resolve_policy(&self, path: &Path) -> Result<Option<Policy>, DbError>;

    /// All objects whose path begins with `path_prefix`.
    fn list_objects_by_path_prefix(&self, path_prefix: &str)
        -> Result<Vec<StoredObject>, DbError>;

    /// All objects carrying the given `Content-Schema`.
    fn list_objects_by_schema(&self, schema: &str) -> Result<Vec<StoredObject>, DbError>;

    /// The name claimed by `pubkey`, if any.
    fn get_name_for_pubkey(&self, pubkey: &str) -> Result<Option<String>, DbError>;
}

impl StateView for StateDb {
    fn get_object(
        &self,
        path: &Path,
        creator: &Id,
        id: &Id,
    ) -> Result<Option<StoredObject>, DbError> {
        StateDb::get_object(self, path, creator, id)
    }

    fn get_first_object_at_path_id(
        &self,
        path: &Path,
        id: &Id,
    ) -> Result<Option<StoredObject>, DbError> {
        StateDb::get_first_object_at_path_id(self, path, id)
    }

    fn resolve_policy(&self, path: &Path) -> Result<Option<Policy>, DbError> {
        StateDb::resolve_policy(self, path)
    }

    fn list_objects_by_path_prefix(
        &self,
        path_prefix: &str,
    ) -> Result<Vec<StoredObject>, DbError> {
        StateDb::list_objects_by_path_prefix(self, path_prefix)
    }

    fn list_objects_by_schema(&self, schema: &str) -> Result<Vec<StoredObject>, DbError> {
        StateDb::list_objects_by_schema(self, schema)
    }

    fn get_name_for_pubkey(&self, pubkey: &str) -> Result<Option<String>, DbError> {
        StateDb::get_name_for_pubkey(self, pubkey)
    }
}

/// Confirmed state ([`StateDb`]) with the mempool's pending writes overlaid on
/// top. Built from an owned snapshot of the pending pool so it never holds the
/// pool lock across validation. Additional writes can be [`stage`](Self::stage)d
/// in (used to chain messages within a single submit batch before the pool is
/// mutated).
pub struct Overlay<'a> {
    db: &'a StateDb,
    /// Pending objects keyed by `(path, id)` — at most one per key, matching the
    /// dedup the pool and read views apply.
    pending: HashMap<(String, String), StoredObject>,
}

impl<'a> Overlay<'a> {
    /// Build an overlay over `db` seeded with a snapshot of pending objects.
    pub fn new(db: &'a StateDb, snapshot: Vec<StoredObject>) -> Self {
        let pending = snapshot
            .into_iter()
            .map(|o| ((o.path.to_string(), o.id.as_str().to_string()), o))
            .collect();
        Self { db, pending }
    }

    /// Add (or replace) a pending object, so subsequent reads in the same batch
    /// observe it. A later write at the same `(path, id)` supersedes the earlier.
    pub fn stage(&mut self, obj: StoredObject) {
        let key = (obj.path.to_string(), obj.id.as_str().to_string());
        self.pending.insert(key, obj);
    }

    /// The pending object at `(path, id)`, if any.
    fn pending_at(&self, path: &Path, id: &Id) -> Option<&StoredObject> {
        self.pending
            .get(&(path.to_string(), id.as_str().to_string()))
    }
}

/// Pick the value that wins between a pending candidate and a confirmed value at
/// the same `(path, id)`: the pending one if it overlays (LWW), else confirmed.
fn merge(pending: Option<&StoredObject>, confirmed: Option<StoredObject>) -> Option<StoredObject> {
    match (pending, confirmed) {
        (Some(p), Some(c)) => {
            if overlay_wins(p, &c) {
                Some(p.clone())
            } else {
                Some(c)
            }
        }
        (Some(p), None) => Some(p.clone()),
        (None, c) => c,
    }
}

impl<'a> StateView for Overlay<'a> {
    fn get_object(
        &self,
        path: &Path,
        creator: &Id,
        id: &Id,
    ) -> Result<Option<StoredObject>, DbError> {
        // The pending entry only participates when it was written by the same
        // creator the caller is asking about (get_object is creator-keyed).
        let pending = self
            .pending_at(path, id)
            .filter(|o| o.creator.as_str() == creator.as_str());
        let confirmed = self.db.get_object(path, creator, id)?;
        Ok(merge(pending, confirmed))
    }

    fn get_first_object_at_path_id(
        &self,
        path: &Path,
        id: &Id,
    ) -> Result<Option<StoredObject>, DbError> {
        let pending = self.pending_at(path, id);
        let confirmed = self.db.get_first_object_at_path_id(path, id)?;
        Ok(merge(pending, confirmed))
    }

    fn resolve_policy(&self, path: &Path) -> Result<Option<Policy>, DbError> {
        // Policies live in a dedicated column family, not the object mempool, so
        // there is nothing pending to overlay — delegate to confirmed state.
        self.db.resolve_policy(path)
    }

    fn list_objects_by_path_prefix(
        &self,
        path_prefix: &str,
    ) -> Result<Vec<StoredObject>, DbError> {
        let confirmed = self.db.list_objects_by_path_prefix(path_prefix)?;
        Ok(merge_list(
            confirmed,
            self.pending
                .values()
                .filter(|o| o.path.to_string().starts_with(path_prefix)),
        ))
    }

    fn list_objects_by_schema(&self, schema: &str) -> Result<Vec<StoredObject>, DbError> {
        let confirmed = self.db.list_objects_by_schema(schema)?;
        Ok(merge_list(
            confirmed,
            self.pending
                .values()
                .filter(|o| o.content_schema.as_deref() == Some(schema)),
        ))
    }

    fn get_name_for_pubkey(&self, pubkey: &str) -> Result<Option<String>, DbError> {
        // Name records live in the names column family, not the object mempool.
        self.db.get_name_for_pubkey(pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbo_core::crypto::ContentHash;
    use tempfile::tempdir;

    fn obj(path: &str, id: &str, creator: &str, hlc: Option<&str>, hash: u8) -> StoredObject {
        StoredObject {
            path: Path::parse(path).unwrap(),
            id: Id::new(id).unwrap(),
            creator: Id::new(creator).unwrap(),
            owner: Id::new("ed25519:00").unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(b"{}"),
            payload: b"{}".to_vec(),
            policy_ref: None,
            content_schema: Some("post.v1".to_string()),
            owner_ref: Some(creator.to_string()),
            block_number: 1,
            object_hash: [hash; 32],
            hlc: hlc.map(|s| s.to_string()),
            prev: None,
        }
    }

    fn open_db() -> (tempfile::TempDir, StateDb) {
        let dir = tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        (dir, db)
    }

    #[test]
    fn reads_through_to_confirmed_when_no_pending() {
        let (_dir, db) = open_db();
        let confirmed = obj("/c/x/", "p1", "alice@mingo.place", Some("10.0"), 1);
        db.put_object(&confirmed).unwrap();

        let overlay = Overlay::new(&db, vec![]);
        let got = overlay
            .get_first_object_at_path_id(&confirmed.path, &confirmed.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.object_hash, [1; 32]);
    }

    #[test]
    fn pending_only_object_is_visible() {
        let (_dir, db) = open_db();
        let pending = obj("/c/x/", "p1", "alice@mingo.place", Some("10.0"), 2);

        let overlay = Overlay::new(&db, vec![pending.clone()]);
        let got = overlay
            .get_first_object_at_path_id(&pending.path, &pending.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.object_hash, [2; 32]);
    }

    #[test]
    fn pending_wins_over_confirmed_by_lww() {
        let (_dir, db) = open_db();
        let confirmed = obj("/c/x/", "p1", "alice@mingo.place", Some("10.0"), 1);
        db.put_object(&confirmed).unwrap();
        // Pending carries a higher HLC → overlays the confirmed value.
        let pending = obj("/c/x/", "p1", "alice@mingo.place", Some("20.0"), 2);

        let overlay = Overlay::new(&db, vec![pending]);
        let got = overlay
            .get_first_object_at_path_id(&confirmed.path, &confirmed.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.object_hash, [2; 32], "pending should overlay confirmed");
    }

    #[test]
    fn get_object_filters_pending_by_creator() {
        let (_dir, db) = open_db();
        // Pending write at the same (path, id) but by a different creator must
        // not satisfy a creator-keyed get_object for `alice`.
        let pending = obj("/c/x/", "p1", "bob@mingo.place", Some("20.0"), 2);
        let overlay = Overlay::new(&db, vec![pending]);

        let alice = Id::new("alice@mingo.place").unwrap();
        let path = Path::parse("/c/x/").unwrap();
        let id = Id::new("p1").unwrap();
        assert!(overlay.get_object(&path, &alice, &id).unwrap().is_none());

        let bob = Id::new("bob@mingo.place").unwrap();
        assert!(overlay.get_object(&path, &bob, &id).unwrap().is_some());
    }

    #[test]
    fn list_by_schema_merges_confirmed_and_pending() {
        let (_dir, db) = open_db();
        db.put_object(&obj("/c/x/", "p1", "alice@mingo.place", Some("10.0"), 1))
            .unwrap();
        let pending = obj("/c/y/", "p2", "alice@mingo.place", Some("10.0"), 2);

        let overlay = Overlay::new(&db, vec![pending]);
        let listed = overlay.list_objects_by_schema("post.v1").unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn staged_object_chains_within_batch() {
        let (_dir, db) = open_db();
        let mut overlay = Overlay::new(&db, vec![]);

        let path = Path::parse("/c/x/").unwrap();
        let id = Id::new("p1").unwrap();
        assert!(overlay
            .get_first_object_at_path_id(&path, &id)
            .unwrap()
            .is_none());

        // Stage a write (as the submit loop does between batch messages) — the
        // next read observes it before it ever reaches the pool or a block.
        overlay.stage(obj("/c/x/", "p1", "alice@mingo.place", Some("10.0"), 5));
        let got = overlay
            .get_first_object_at_path_id(&path, &id)
            .unwrap()
            .unwrap();
        assert_eq!(got.object_hash, [5; 32]);
    }
}

/// Merge pending objects into a confirmed list, keyed by `(path, id)`: a pending
/// object replaces a confirmed one at the same key when it overlays (LWW), and a
/// pending-only object is appended.
fn merge_list<'p, I>(confirmed: Vec<StoredObject>, pending: I) -> Vec<StoredObject>
where
    I: IntoIterator<Item = &'p StoredObject>,
{
    let mut by_key: HashMap<(String, String), StoredObject> = confirmed
        .into_iter()
        .map(|o| ((o.path.to_string(), o.id.as_str().to_string()), o))
        .collect();
    for p in pending {
        let key = (p.path.to_string(), p.id.as_str().to_string());
        match by_key.get(&key) {
            Some(c) if !overlay_wins(p, c) => {}
            _ => {
                by_key.insert(key, p.clone());
            }
        }
    }
    by_key.into_values().collect()
}
