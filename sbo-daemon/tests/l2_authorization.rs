//! Phase 1.5 integration tests: L1/L2 validity wired into daemon validation.
//!
//! These exercise the L2 attribution gate in `validate::validate_message`:
//! a write that declares an `Owner` controller must have a signer that speaks
//! for it. Key-rooted owners authorize by direct signature; email-rooted owners
//! require a valid browserid+DNSSEC attribution (the positive email path needs
//! real DNSSEC, so it is covered by `sbo-core`'s `authorize`/`attribution` unit
//! tests and the `#[ignore]`d live test — here we verify the carry-but-filter
//! behavior for the absent/invalid attribution cases).

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::validate::{validate_message, L2Context, ValidationResult, ValidationStage};
use tempfile::tempdir;

/// Build and sign a Post message with the given owner / auth fields.
fn signed_post(
    key: &SigningKey,
    path: &str,
    id: &str,
    owner: Option<&str>,
    auth_cert: Option<&str>,
    auth_evidence: Option<&str>,
) -> Message {
    let payload = b"{}".to_vec();
    let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: placeholder_sig,
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: owner.map(|o| Id::new(o).unwrap()),
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: auth_cert.map(|s| s.to_string()),
        auth_evidence: auth_evidence.map(|s| s.to_string()),
    };
    msg.sign(key);
    msg
}

/// Store a key-rooted `identity.v1` name record under `/sys/names/<name>`.
fn put_key_rooted_name(db: &StateDb, name: &str, key: &SigningKey) {
    let jwt = sbo_core::jwt::create_self_signed_identity(key, name, None).unwrap();
    let payload = jwt.into_bytes();
    let obj = StoredObject {
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        creator: Id::new(name).unwrap(),
        owner: Id::new(name).unwrap(),
        content_type: "application/jwt".to_string(),
        content_hash: ContentHash::sha256(&payload),
        payload,
        policy_ref: None,
        content_schema: Some("identity.v1".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
    };
    db.put_object(&obj).unwrap();
}

fn ctx(db: &StateDb) -> L2Context {
    // No block timestamp in tests; email-rooted owners fail closed accordingly.
    L2Context::for_block(None, db)
}

#[test]
fn key_rooted_owner_authorized_by_direct_signature() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();
    put_key_rooted_name(&db, "alice", &key);

    let msg = signed_post(&key, "/space/", "post1", Some("alice"), None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Valid { .. }),
        "key-rooted owner with matching signer should be authorized, got {result:?}"
    );
}

#[test]
fn key_rooted_owner_rejects_wrong_signer() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    put_key_rooted_name(&db, "alice", &alice);

    // A different key signs a write claiming Owner = alice.
    let mallory = SigningKey::generate();
    let msg = signed_post(&mallory, "/space/", "post1", Some("alice"), None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }),
        "wrong signer for key-rooted owner should fail L2, got {result:?}"
    );
}

#[test]
fn email_rooted_owner_without_attribution_is_filtered() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Bare-email owner, no Auth-Cert / Auth-Evidence → cannot attribute.
    let msg = signed_post(&key, "/space/", "post1", Some("alice@example.com"), None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }),
        "email-rooted owner without attribution should be carried-but-filtered, got {result:?}"
    );
}

#[test]
fn email_rooted_owner_with_malformed_attribution_is_filtered() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    let msg = signed_post(
        &key,
        "/space/",
        "post1",
        Some("alice@example.com"),
        Some("not-a-real-cert"),
        Some("inline:AAAA"),
    );
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }),
        "email-rooted owner with bad attribution should be filtered, got {result:?}"
    );
}

#[test]
fn unresolvable_owner_is_filtered() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Owner references a name with no /sys/names record.
    let msg = signed_post(&key, "/space/", "post1", Some("ghost"), None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }),
        "unresolvable owner should be filtered, got {result:?}"
    );
}

#[test]
fn ownerless_write_bypasses_l2_gate() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // No Owner header → legacy key-rooted path, gate skipped, genesis-allowed.
    let msg = signed_post(&key, "/space/", "post1", None, None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Valid { .. }),
        "ownerless write should bypass the L2 gate, got {result:?}"
    );
}
