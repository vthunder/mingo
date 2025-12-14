use sbo_core::state::{StateDb, StoredObject};
use sbo_core::message::{Id, Path};
use sbo_core::crypto::ContentHash;
use tempfile::tempdir;

#[test]
fn test_store_and_retrieve_object() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let obj = StoredObject {
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        creator: Id::new("alice").unwrap(),
        owner: Id::new("alice").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        block_number: 1,
        object_hash: [0u8; 32], // Placeholder - in production, this is sha256(raw_sbo_bytes)
    };

    db.put_object(&obj).unwrap();

    let retrieved = db.get_object(
        &Path::parse("/test/").unwrap(),
        &Id::new("alice").unwrap(),
        &Id::new("hello").unwrap(),
    ).unwrap();

    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id.as_str(), "hello");
    assert_eq!(retrieved.block_number, 1);
}
