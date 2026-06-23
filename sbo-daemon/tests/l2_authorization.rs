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
use sbo_daemon::validate::{
    message_to_stored_object, resolve_creator, validate_message, L2Context, ValidationResult,
    ValidationStage,
};
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
fn same_key_owner_can_update_own_object_via_controller_check() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Create then persist an object the way the daemon would (owner_ref records
    // the signer-key effective owner).
    let create = signed_post(&key, "/space/", "post1", None, None, None);
    let stored = sbo_daemon::validate::message_to_stored_object(&create, 1, Some(&db), [0u8; 32], &ctx(&db))
        .expect("create should produce a stored object");
    db.put_object(&stored).unwrap();

    // The same key updates it — reaches the update branch (same resolved
    // creator) and authorizes against the stored key controller.
    let update = signed_post(&key, "/space/", "post1", None, None, None);
    let result = validate_message(&update, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Valid { .. }),
        "owner updating own key-rooted object should be allowed, got {result:?}"
    );
}

#[test]
fn evidence_ref_resolves_to_inline_payload() {
    use sbo_core::authorize::encode_auth_evidence_inline;
    use sbo_daemon::validate::resolve_evidence;

    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // A self-authenticating dnssec.v1 evidence object at /sys/dnssec/<issuer>;
    // its payload is the (here, stand-in) RFC 9102 chain.
    let proof = b"\x00\x01dnssec-chain-bytes\xff".to_vec();
    let obj = StoredObject {
        path: Path::parse("/sys/dnssec/").unwrap(),
        id: Id::new("id.sandmill.org").unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/octet-stream".to_string(),
        content_hash: ContentHash::sha256(&proof),
        payload: proof.clone(),
        policy_ref: None,
        content_schema: Some("dnssec.v1".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
    };
    db.put_object(&obj).unwrap();

    // ref: resolves to the inline-encoded payload.
    let msg = signed_post(
        &key,
        "/space/",
        "post1",
        Some("alice@example.com"),
        Some("CERT"),
        Some("ref:/sys/dnssec/id.sandmill.org"),
    );
    assert_eq!(
        resolve_evidence(&msg, &db),
        Some(encode_auth_evidence_inline(&proof))
    );

    // A ref to a missing object resolves to nothing (signer stays unattributed).
    let missing = signed_post(
        &key,
        "/space/",
        "post1",
        Some("alice@example.com"),
        Some("CERT"),
        Some("ref:/sys/dnssec/absent.example"),
    );
    assert_eq!(resolve_evidence(&missing, &db), None);

    // inline passes through unchanged.
    let inline = signed_post(
        &key,
        "/space/",
        "post1",
        Some("alice@example.com"),
        Some("CERT"),
        Some("inline:AAAA"),
    );
    assert_eq!(resolve_evidence(&inline, &db), Some("inline:AAAA".to_string()));
}

#[test]
fn resolve_creator_prefers_explicit_creator_then_key_hex() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Explicit Creator header wins outright.
    let mut with_creator = signed_post(&key, "/space/", "p1", None, None, None);
    with_creator.creator = Some(Id::new("alice").unwrap());
    with_creator.sign(&key);
    assert_eq!(
        resolve_creator(&with_creator, Some(&db), &ctx(&db)).as_str(),
        "alice"
    );

    // No Creator, no valid attribution → key-hex fallback (the attributed-email
    // tier is skipped because the signer carries no cert). The email tier is
    // exercised only on the live DNSSEC path.
    let bare = signed_post(&key, "/space/", "p1", None, None, None);
    assert!(
        resolve_creator(&bare, Some(&db), &ctx(&db)).as_str().starts_with("e_"),
        "nameless keyed author should fall back to key-hex"
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

/// Store an email-rooted (identity.email.v1) name record at /sys/names/<name>,
/// controlled by `email`, with an arbitrary (already-rotated) stored signer.
fn put_email_rooted_name(db: &StateDb, name: &str, email: &str) {
    let payload = serde_json::to_vec(&serde_json::json!({"iat": 1})).unwrap();
    let obj = StoredObject {
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        creator: Id::new(name).unwrap(),
        owner: Id::new("oldkey").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(&payload),
        payload,
        policy_ref: None,
        content_schema: Some("identity.email.v1".to_string()),
        owner_ref: Some(email.to_string()),
        block_number: 1,
        object_hash: [0u8; 32],
    };
    db.put_object(&obj).unwrap();
}

// Regression: an email-rooted name record must re-authorize updates via L2
// (the ephemeral signer key rotates), NOT via a direct key match — otherwise a
// rotation locks the owner out. A rotated-key update without attribution must
// be rejected at the *Attribution* stage (proving the L2 path), not "already
// claimed" at the State stage.
#[test]
fn email_rooted_name_update_routes_through_l2() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_email_rooted_name(&db, "alice", "alice@example.com");

    // A fresh (rotated) key re-asserts the name, no Owner header (so the top
    // gate is skipped) and no attribution.
    let rotated = SigningKey::generate();
    let msg = signed_post(&rotated, "/sys/names/", "alice", None, None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    match result {
        ValidationResult::Invalid { stage, .. } => assert_eq!(
            stage,
            ValidationStage::Attribution,
            "email-rooted name update must be filtered by L2, not key-match"
        ),
        other => panic!("expected L2 rejection, got {other:?}"),
    }
}

// Carry-but-filter on canonical state: an L1-valid but L2-failing write is
// disregarded on replay — it must not mutate state. This mirrors the daemon's
// validate→(continue|write) decision and asserts the trie state root is
// unchanged by the filtered write, while a valid write does change it.
#[test]
fn filtered_write_does_not_mutate_canonical_state() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Helper: apply a message exactly as the sync loop does — store only on Valid.
    let apply = |db: &StateDb, msg: &Message| -> bool {
        match validate_message(msg, db, dir.path(), &ctx(db)) {
            ValidationResult::Valid { .. } => {
                let obj = message_to_stored_object(msg, 1, Some(db), [1u8; 32], &ctx(db))
                    .expect("content message produces a stored object");
                db.put_object(&obj).unwrap();
                true
            }
            ValidationResult::Invalid { .. } => false,
        }
    };

    let root_empty = db.compute_trie_state_root().unwrap();

    // A valid (ownerless, key-controller) write is applied and changes the root.
    let valid = signed_post(&key, "/space/", "p1", None, None, None);
    assert!(apply(&db, &valid), "ownerless key write should be valid");
    let root_after_valid = db.compute_trie_state_root().unwrap();
    assert_ne!(root_after_valid, root_empty, "valid write must change the state root");

    // An L2-failing write (email owner, no attribution) is filtered: the daemon
    // would `continue` without storing. The canonical state root is unchanged.
    let filtered = signed_post(&key, "/space/", "p2", Some("alice@example.com"), None, None);
    assert!(!apply(&db, &filtered), "email owner without attribution must be filtered");
    let root_after_filtered = db.compute_trie_state_root().unwrap();
    assert_eq!(
        root_after_filtered, root_after_valid,
        "a carried-but-filtered write must not mutate canonical state"
    );
}

// The pinned /sys/trust/brokers object must be loaded into the L2 trust anchors
// (on-chain, so replay converges). Without it, broker-path attribution can't
// be authorized.
#[test]
fn trust_brokers_object_loads_into_anchors() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let payload = serde_json::to_vec(&vec!["id.sandmill.org"]).unwrap();
    let obj = StoredObject {
        path: Path::parse("/sys/trust/").unwrap(),
        id: Id::new("brokers").unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(&payload),
        payload,
        policy_ref: None,
        content_schema: Some("trust.brokers.v1".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
    };
    db.put_object(&obj).unwrap();

    let ctx = L2Context::for_block(None, &db);
    assert!(
        ctx.anchors.brokers.iter().any(|b| b == "id.sandmill.org"),
        "expected /sys/trust/brokers to be loaded, got {:?}",
        ctx.anchors.brokers
    );
}

// Sanity: the preset that produces the /sys/trust/brokers object round-trips
// into anchors the daemon can read.
#[test]
fn set_trust_brokers_preset_roundtrips() {
    let key = SigningKey::generate();
    let wire = sbo_core::presets::set_trust_brokers(&key, &["id.sandmill.org", "broker.example"]);
    let msg = sbo_core::wire::parse(&wire).unwrap();
    assert_eq!(msg.path.to_string(), "/sys/trust/");
    assert_eq!(msg.id.as_str(), "brokers");
    let brokers: Vec<String> = serde_json::from_slice(msg.payload.as_ref().unwrap()).unwrap();
    assert_eq!(brokers, vec!["id.sandmill.org", "broker.example"]);
}

// The production write-path (message -> StoredObject) must persist the
// Owner-header controller reference and schema, since L2 resolution depends on
// them. The other tests hand-seed StoredObjects and bypass this population.
#[test]
fn message_to_stored_object_persists_owner_ref_and_schema() {
    let key = SigningKey::generate();
    let wire = sbo_core::presets::claim_email_identity(
        &key,
        "alice",
        "alice@example.com",
        "CERT.JWT.SIG",
        "inline:AAAA",
        1_700_000_000,
    );
    let msg = sbo_core::wire::parse(&wire).unwrap();
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let stored = message_to_stored_object(&msg, 7, None, [0u8; 32], &ctx(&db))
        .expect("email-identity message should produce a stored object");

    assert_eq!(stored.content_schema.as_deref(), Some("identity.email.v1"));
    assert_eq!(stored.owner_ref.as_deref(), Some("alice@example.com"));
}

// End-to-end through the *real* production path: a key-rooted name registered
// via the preset -> message_to_stored_object -> put_object, then resolved by
// the L2 gate's name_lookup (decoding the public key from the stored JWT). This
// exercises population + lookup together, not hand-seeded objects.
#[test]
fn key_rooted_name_registered_via_real_path_authorizes() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Register /sys/names/alice (identity.v1) the way the daemon actually would.
    let wire = sbo_core::presets::claim_name(&key, "alice");
    let id_msg = sbo_core::wire::parse(&wire).unwrap();
    let stored = message_to_stored_object(&id_msg, 1, Some(&db), [0u8; 32], &ctx(&db)).unwrap();
    db.put_object(&stored).unwrap();

    // A write owned by "alice", signed by the same key, must be authorized.
    let post = signed_post(&key, "/space/", "p1", Some("alice"), None, None);
    let result = validate_message(&post, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Valid { .. }),
        "name registered via the real write-path should resolve + authorize, got {result:?}"
    );
}

#[test]
fn ownerless_write_authorized_via_signer_key_controller() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // No Owner/Creator header → effective owner is the signing key, which
    // resolves to a key controller and is authorized by the L1 signature. The
    // gate runs (not bypassed) but passes; genesis-allowed downstream.
    let msg = signed_post(&key, "/space/", "post1", None, None, None);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Valid { .. }),
        "ownerless write should authorize via the signer-key controller, got {result:?}"
    );
}

#[test]
fn creator_email_fallback_without_attribution_is_filtered() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // No Owner, but a Creator that grounds to an email controller. The effective
    // owner falls back to Creator (Owner → else Creator → else signer), so the
    // signer must be attributed to that email; absent attribution, filtered.
    let mut msg = signed_post(&key, "/space/", "post1", None, None, None);
    msg.creator = Some(Id::new("alice@example.com").unwrap());
    msg.sign(&key);
    let result = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        matches!(result, ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }),
        "creator-email fallback without attribution should be filtered, got {result:?}"
    );
}
