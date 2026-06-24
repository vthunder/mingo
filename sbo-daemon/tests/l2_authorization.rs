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
fn attestation_schema_gated_in_validate_message() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // A well-formed attestation issued by the signing key (no Owner → effective
    // owner is the signer, a key controller) passes schema + L2 in genesis mode.
    let good = br#"{"subject":"bob","type":"vouch","value":true,"issued_at":100}"#.to_vec();
    let mut msg = signed_post(&key, "/alice/attestations/bob/", "vouch", None, None, None);
    msg.content_schema = Some("attestation.v1".to_string());
    msg.payload = Some(good.clone());
    msg.content_hash = Some(ContentHash::sha256(&good));
    msg.sign(&key);
    assert!(
        matches!(validate_message(&msg, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "well-formed attestation should validate"
    );

    // A malformed type is rejected at the Schema stage.
    let bad = br#"{"subject":"bob","type":"BAD/Type","value":true,"issued_at":100}"#.to_vec();
    msg.payload = Some(bad.clone());
    msg.content_hash = Some(ContentHash::sha256(&bad));
    msg.sign(&key);
    assert!(
        matches!(
            validate_message(&msg, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Schema, .. }
        ),
        "malformed attestation type should be rejected at the schema stage"
    );
}

// End-to-end attestation-defined role: a root policy grants `create` on
// /space/** to anyone holding an in-force `role:moderator` attestation by a
// given issuer. A key-rooted subject who holds it may post; one who doesn't is
// denied. Exercises the daemon's attestation enumeration + subject resolution.
#[test]
fn attestation_defined_role_gates_policy() {
    use sbo_core::schema::storage_path;

    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let issuer = SigningKey::generate();
    let moderator = SigningKey::generate();
    let stranger = SigningKey::generate();
    // Issuer and subject are registered key-rooted names (raw keys aren't valid
    // path segments; real subjects/issuers are names or emails).
    put_key_rooted_name(&db, "mods", &issuer);
    put_key_rooted_name(&db, "alice", &moderator);
    let issuer_ref = "mods";
    let subject_ref = "alice";

    // Root policy: only the moderator role may create under /space/**.
    let policy: sbo_core::policy::Policy = serde_json::from_value(serde_json::json!({
        "roles": { "mod": [{"attested": {"type": "role:moderator", "by": issuer_ref}}] },
        "grants": [{"to": {"role": "mod"}, "can": ["create"], "on": "/space/**"}]
    }))
    .unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
    // The genesis check looks for the root-policy object itself.
    db.put_object(&StoredObject {
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        content_schema: Some("policy.v2".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
    }).unwrap();

    // An in-force role:moderator attestation by the issuer about the moderator.
    let att_payload = serde_json::json!({
        "subject": subject_ref,
        "type": "role:moderator",
        "value": true,
        "issued_at": 0
    });
    let att_bytes = serde_json::to_vec(&att_payload).unwrap();
    db.put_object(&StoredObject {
        path: Path::parse(&storage_path(issuer_ref, subject_ref)).unwrap(),
        id: Id::new("role:moderator").unwrap(),
        creator: Id::new(issuer_ref).unwrap(),
        owner: Id::new(issuer_ref).unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(&att_bytes),
        payload: att_bytes,
        policy_ref: None,
        content_schema: Some("attestation.v1".to_string()),
        owner_ref: Some(issuer_ref.to_string()),
        block_number: 1,
        object_hash: [0u8; 32],
    }).unwrap();

    // The attested moderator may create under /space/**.
    let post = signed_post(&moderator, "/space/posts/", "p1", None, None, None);
    assert!(
        matches!(validate_message(&post, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "attested moderator should be granted create"
    );

    // A stranger (no attestation) is denied at the policy stage.
    let denied = signed_post(&stranger, "/space/posts/", "p2", None, None, None);
    assert!(
        matches!(
            validate_message(&denied, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Policy, .. }
        ),
        "non-attested stranger should be denied"
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

// HLC ordering-integrity gate (Content Spec §Validity bound). A write carrying
// an `HLC` must parse and, when the block timestamp is known, fall within
// `T_b − W ≤ physical ≤ T_b + ε`. Genesis mode (no root policy) isolates the
// Ordering stage from policy.
#[test]
fn hlc_bound_gates_writes() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();

    // Block inclusion time 1_000_000s → 1_000_000_000ms. W = ε = 5min = 300_000ms.
    let t_b_secs = 1_000_000i64;
    let l2 = L2Context::for_block(Some(t_b_secs), &db);
    let t_b_ms = t_b_secs * 1000;

    let with_hlc = |hlc: &str| {
        let mut m = signed_post(&key, "/spaces/general/", "p1", None, None, None);
        m.hlc = Some(hlc.to_string());
        m.sign(&key);
        m
    };

    // In-bound (exactly T_b) → valid.
    let ok = with_hlc(&format!("{t_b_ms}.0"));
    assert!(matches!(validate_message(&ok, &db, dir.path(), &l2), ValidationResult::Valid { .. }));

    // Future-dated beyond ε → rejected at Ordering.
    let future = with_hlc(&format!("{}.0", t_b_ms + 300_001));
    assert!(matches!(
        validate_message(&future, &db, dir.path(), &l2),
        ValidationResult::Invalid { stage: ValidationStage::Ordering, .. }
    ));

    // Back-dated beyond W → rejected at Ordering.
    let stale = with_hlc(&format!("{}.0", t_b_ms - 300_001));
    assert!(matches!(
        validate_message(&stale, &db, dir.path(), &l2),
        ValidationResult::Invalid { stage: ValidationStage::Ordering, .. }
    ));

    // Malformed HLC → rejected at Ordering regardless of timestamp.
    let bad = with_hlc("not-an-hlc");
    assert!(matches!(
        validate_message(&bad, &db, dir.path(), &l2),
        ValidationResult::Invalid { stage: ValidationStage::Ordering, .. }
    ));

    // No timestamp → bound cannot be evaluated; a well-formed HLC still passes.
    let no_ts = L2Context::for_block(None, &db);
    let ok2 = with_hlc(&format!("{}.0", t_b_ms + 300_001));
    assert!(matches!(validate_message(&ok2, &db, dir.path(), &no_ts), ValidationResult::Valid { .. }));
    // ...but a malformed HLC is rejected even without a timestamp.
    let bad2 = with_hlc("1.2.3");
    assert!(matches!(
        validate_message(&bad2, &db, dir.path(), &no_ts),
        ValidationResult::Invalid { stage: ValidationStage::Ordering, .. }
    ));
}

/// Store an in-force `attestation.v1` issued by `issuer` about `subject`.
fn put_attestation(db: &StateDb, issuer: &str, subject: &str, type_: &str) {
    use sbo_core::schema::storage_path;
    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": subject,
        "type": type_,
        "value": true,
        "issued_at": 0
    }))
    .unwrap();
    db.put_object(&StoredObject {
        path: Path::parse(&storage_path(issuer, subject)).unwrap(),
        id: Id::new(type_).unwrap(),
        creator: Id::new(issuer).unwrap(),
        owner: Id::new(issuer).unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(&payload),
        payload,
        policy_ref: None,
        content_schema: Some("attestation.v1".to_string()),
        owner_ref: Some(issuer.to_string()),
        block_number: 1,
        object_hash: [0u8; 32],
    })
    .unwrap();
}

// End-to-end open community (Community Spec §Worked Example): a `community.v1`
// descriptor plus a root policy where the `member` role is an in-force
// `membership` attestation (open / self-issued, no `by`), `post` is granted on
// /spaces/**, and a `ban` by the issuer is excluded via `not_attested`. Shows
// join → post (post⇒create), ban → denied, and stranger → denied, composing
// Phase 3 (attestations), Phase 4 (attested roles/conditions) and Phase 5.0/5.1.
#[test]
fn open_community_membership_post_and_ban_end_to_end() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let issuer = SigningKey::generate(); // the community's authoritative issuer
    let alice = SigningKey::generate(); // a joining member
    let carol = SigningKey::generate(); // a member who gets banned
    let stranger = SigningKey::generate(); // never joined
    put_key_rooted_name(&db, "cooks", &issuer);
    put_key_rooted_name(&db, "alice", &alice);
    put_key_rooted_name(&db, "carol", &carol);
    let issuer_ref = "cooks";

    // The community.v1 descriptor at /sys/community, signed by the issuer (who
    // controls the `sys` namespace here — genesis owner). It must validate.
    let descriptor = serde_json::to_vec(&serde_json::json!({
        "name": "Cooks",
        "issuer": issuer_ref,
        "policy": "/sys/policies/root",
        "open": true
    }))
    .unwrap();
    let mut desc_msg = signed_post(&issuer, "/sys/", "community", None, None, None);
    desc_msg.content_schema = Some("community.v1".to_string());
    desc_msg.payload = Some(descriptor.clone());
    desc_msg.content_hash = Some(ContentHash::sha256(&descriptor));
    desc_msg.sign(&issuer);
    // Validated in genesis mode (before the root policy exists), as it is when a
    // community is bootstrapped: schema + L2 attribution pass.
    assert!(
        matches!(
            validate_message(&desc_msg, &db, dir.path(), &ctx(&db)),
            ValidationResult::Valid { .. }
        ),
        "community descriptor must pass schema + attribution at genesis"
    );

    // Open-community root policy: members (anyone with an in-force membership)
    // may post in spaces, but banned subjects are excluded.
    let policy: sbo_core::policy::Policy = serde_json::from_value(serde_json::json!({
        "roles": { "member": [{"attested": {"type": "membership"}}] },
        "grants": [{"to": {"role": "member"}, "can": ["post"], "on": "/spaces/**"}],
        "restrictions": [
            {"on": "/spaces/**", "require": {"not_attested": {"type": "ban", "by": issuer_ref}}}
        ]
    }))
    .unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
    db.put_object(&StoredObject {
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        content_schema: Some("policy.v2".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
    })
    .unwrap();

    // Join: alice self-issues membership in her own namespace (open mode).
    put_attestation(&db, "alice", "alice", "membership");
    // She may now post in spaces (post grant ⇒ create).
    let post = signed_post(&alice, "/spaces/general/", "p1", None, None, None);
    assert!(
        matches!(validate_message(&post, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "joined member should be allowed to post (post⇒create)"
    );

    // A stranger who never joined has no membership → no grant → denied.
    let denied = signed_post(&stranger, "/spaces/general/", "p2", None, None, None);
    assert!(
        matches!(
            validate_message(&denied, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Policy, .. }
        ),
        "stranger without membership should be denied"
    );

    // Carol joins, then the community bans her. The ban (in the issuer's
    // namespace) overrides her membership via the not_attested restriction.
    put_attestation(&db, "carol", "carol", "membership");
    let carol_post = signed_post(&carol, "/spaces/general/", "p3", None, None, None);
    assert!(
        matches!(validate_message(&carol_post, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "carol should be able to post before the ban"
    );
    put_attestation(&db, issuer_ref, "carol", "ban");
    let carol_banned = signed_post(&carol, "/spaces/general/", "p4", None, None, None);
    assert!(
        matches!(
            validate_message(&carol_banned, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Policy, .. }
        ),
        "banned member should be denied by the not_attested restriction"
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
