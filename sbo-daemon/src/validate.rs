//! Message validation against state
//!
//! Validates SBO messages before they are applied to the repo.

use sbo_core::authorize::{authorize_message, encode_auth_evidence_inline, message_attribution, AuthzOutcome};
use sbo_core::attribution::TrustAnchors;
use sbo_core::message::{Message, Action, Id, Path as SboPath};
use sbo_core::policy::{evaluate, ActionType, AttestedSource, PolicyResult};
use sbo_core::resolve::{resolve_controller, Controller, NameRecord, DEFAULT_HOP_LIMIT};
use sbo_core::schema::{parse_attestation, validate_schema, SchemaError};
use sbo_core::state::StoredObject;

use crate::state_view::StateView;
use std::path::Path;

/// Validation stage that failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    Signature,
    Schema,
    /// HLC ordering-integrity: the write's `HLC` is malformed or falls outside
    /// the validity bound `T_b − W ≤ physical ≤ T_b + ε` (Content Spec).
    Ordering,
    /// L2 attribution: the signer does not speak for the object's owner.
    Attribution,
    State,
    Policy,
}

impl std::fmt::Display for ValidationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStage::Signature => write!(f, "sig"),
            ValidationStage::Schema => write!(f, "schema"),
            ValidationStage::Ordering => write!(f, "ordering"),
            ValidationStage::Attribution => write!(f, "attr"),
            ValidationStage::State => write!(f, "state"),
            ValidationStage::Policy => write!(f, "policy"),
        }
    }
}

/// Context for the L2 attribution layer: the write's DA inclusion time and the
/// pinned trust anchors. Threaded from the block being replayed.
pub struct L2Context {
    /// The DA block's inclusion time (UNIX seconds), if known. `None` means the
    /// block carried no usable timestamp — email-rooted owners then cannot be
    /// attributed and their writes are carried-but-filtered.
    pub inclusion_time: Option<i64>,
    /// Pinned trust anchors (authorized brokers + informational root KSK).
    pub anchors: TrustAnchors,
}

impl L2Context {
    /// Build the L2 context for a block, sourcing trust anchors from state.
    pub fn for_block(inclusion_time: Option<i64>, state: &dyn StateView) -> Self {
        Self {
            inclusion_time,
            anchors: load_trust_anchors(state),
        }
    }
}

/// Trust-anchor path: the pinned authorized-broker list.
const TRUST_BROKERS_PATH: &str = "/sys/trust/";
const TRUST_BROKERS_ID: &str = "brokers";

/// Load the pinned trust anchors from `/sys/trust/brokers`.
///
/// The object payload is expected to be a JSON array of authorized broker
/// provider domains. Absent or unparseable → an empty broker set (only
/// primary-IdP attribution will succeed). The DNS root KSK is hardcoded inside
/// `dnssec-prover`, so `/sys/trust/dns-root` is not consulted here.
fn load_trust_anchors(state: &dyn StateView) -> TrustAnchors {
    let brokers = (|| {
        let path = SboPath::parse(TRUST_BROKERS_PATH).ok()?;
        let id = Id::new(TRUST_BROKERS_ID).ok()?;
        let obj = state.get_first_object_at_path_id(&path, &id).ok()??;
        serde_json::from_slice::<Vec<String>>(&obj.payload).ok()
    })()
    .unwrap_or_default();
    // TODO: also surface /sys/trust/dns-root for out-of-band auditing.
    TrustAnchors::with_brokers(brokers)
}

/// Build a `/sys/names/<name>` resolver closure over the state DB, mapping each
/// name record to its [`NameRecord`] kind (key-rooted `identity.v1` vs
/// email-rooted `identity.email.v1`) for [`resolve_controller`] indirection.
fn name_lookup(state: &dyn StateView) -> impl Fn(&str) -> Option<NameRecord> + '_ {
    move |name: &str| {
        let path = SboPath::parse("/sys/names/").ok()?;
        let id = Id::new(name).ok()?;
        let obj = state.get_first_object_at_path_id(&path, &id).ok()??;
        match obj.content_schema.as_deref() {
            Some("identity.email.v1") => {
                // Email-rooted: recurse on the stored Owner reference.
                obj.owner_ref.map(NameRecord::EmailRooted)
            }
            Some("identity.v1") => {
                // Key-rooted: the durable public key lives in the identity JWT
                // payload (it carries ':' and cannot be an `Id`/`owner`).
                let token = std::str::from_utf8(&obj.payload).ok()?;
                let claims = sbo_core::jwt::decode_identity_claims(token).ok()?;
                Some(NameRecord::KeyRooted(claims.public_key))
            }
            // Unknown/legacy name records are not resolvable controllers.
            _ => None,
        }
    }
}

/// Run the L2 attribution check: does the message's signer speak for
/// `owner_ref` at the block's inclusion time? Returns `Ok(())` if authorized,
/// `Err(reason)` if the write must be carried-but-filtered.
fn l2_authorize(msg: &Message, state: &dyn StateView, l2: &L2Context, owner_ref: &str) -> Result<(), String> {
    let signer = msg.signing_key.to_string();
    let lookup = name_lookup(state);
    // Resolve referenced / conventional evidence to inline bytes the pure
    // verifier can consume (the pure path can't reach state).
    let evidence = resolve_evidence(msg, state);
    // An unknown block time cannot satisfy any cert/RRSig window, so email-rooted
    // owners fail closed; key-rooted owners are time-independent.
    let inclusion_time = l2.inclusion_time.unwrap_or(0);
    match authorize_message(
        owner_ref,
        &signer,
        msg.auth_cert.as_deref(),
        evidence.as_deref(),
        inclusion_time,
        &l2.anchors,
        &lookup,
        DEFAULT_HOP_LIMIT,
    ) {
        AuthzOutcome::Authorized => Ok(()),
        AuthzOutcome::Unauthorized(reason) => Err(reason),
    }
}

/// Resolve a message's `Auth-Evidence` to an `inline:<base64url>` value the pure
/// verifier accepts. Three carriage forms (Authorization Spec §DNSSEC Evidence):
/// - `inline:…` passes through unchanged;
/// - `ref:<sbo-path>` is fetched from the referenced on-chain `dnssec.v1`
///   object (its payload IS the RFC 9102 chain);
/// - absent evidence, but an `Auth-Cert` is present → the conventional
///   `/sys/dnssec/<issuer>` object is consulted (line 140, a MAY).
///
/// Returns `None` when nothing resolves; the signer is then simply unattributed
/// (carried-but-filtered for an email-rooted owner). Because a referenced
/// `dnssec.v1` object is self-authenticating (re-validated against the pinned
/// root KSK by the verifier), resolving it is not a trusted read.
pub fn resolve_evidence(msg: &Message, state: &dyn StateView) -> Option<String> {
    match msg.auth_evidence.as_deref() {
        Some(inline) if inline.starts_with("inline:") => Some(inline.to_string()),
        Some(reference) if reference.starts_with("ref:") => {
            let target = reference.trim_start_matches("ref:");
            let bytes = fetch_evidence_object(state, target)?;
            Some(encode_auth_evidence_inline(&bytes))
        }
        Some(_) => None, // unrecognized form
        None => {
            // Absent evidence: try the conventional /sys/dnssec/<issuer> object.
            let issuer = sbo_core::authorize::cert_issuer(msg.auth_cert.as_deref()?)?;
            let bytes = fetch_evidence_object(state, &format!("/sys/dnssec/{issuer}"))?;
            Some(encode_auth_evidence_inline(&bytes))
        }
    }
}

/// Fetch a referenced evidence object's payload (the RFC 9102 DNSSEC chain) by
/// an `sbo-path` ref like `/sys/dnssec/<issuer>`: the final segment is the
/// object id, the rest the path. Creator-independent (the object is
/// self-authenticating, so any creator's copy is equivalent).
fn fetch_evidence_object(state: &dyn StateView, ref_path: &str) -> Option<Vec<u8>> {
    let (path_str, id_str) = ref_path.trim_end_matches('/').rsplit_once('/')?;
    let path = SboPath::parse(&format!("{path_str}/")).ok()?;
    let id = Id::new(id_str).ok()?;
    let obj = state.get_first_object_at_path_id(&path, &id).ok()??;
    Some(obj.payload)
}

/// Validation result with stage information
#[derive(Debug)]
pub enum ValidationResult {
    /// Message is valid, proceed with write
    Valid {
        /// Resolved creator name (for logging)
        creator: String,
    },
    /// Message is invalid, skip with reason
    Invalid {
        stage: ValidationStage,
        reason: String,
    },
}

/// Root policy path constant
const ROOT_POLICY_PATH: &str = "/sys/policies/";
const ROOT_POLICY_ID: &str = "root";

/// The email the message's signer is *proven* to speak for at the block's
/// inclusion time (valid `Auth-Cert` + DNSSEC evidence), or `None` if the
/// signer carries no valid attribution. Deterministic given the message and
/// chain state — the same inclusion-time-pinned check the L2 gate uses.
fn attributed_email(msg: &Message, state: Option<&dyn StateView>, l2: &L2Context) -> Option<String> {
    let signer = msg.signing_key.to_string();
    // Evidence resolution (ref:/dnssec) needs state; inline works without it.
    let evidence = state.and_then(|db| resolve_evidence(msg, db));
    let inclusion_time = l2.inclusion_time.unwrap_or(0);
    message_attribution(
        &signer,
        msg.auth_cert.as_deref(),
        evidence.as_deref(),
        inclusion_time,
        &l2.anchors,
    )
    .map(|a| a.email)
}

/// Resolve the creator ID for a message — the durable identity of its author.
///
/// Order (Identity/State-Commitment specs): explicit `Creator` header → the
/// **attributed email** (so an email author's writes share a stable creator
/// across browserid key rotation, instead of fragmenting under each ephemeral
/// key) → the signer's claimed name → truncated key hex.
pub fn resolve_creator(msg: &Message, state: Option<&dyn StateView>, l2: &L2Context) -> Id {
    // If message has explicit creator, use it
    if let Some(creator) = &msg.creator {
        return creator.clone();
    }

    // An attributed email is the author's stable, rotation-independent identity.
    if let Some(email) = attributed_email(msg, state, l2) {
        if let Ok(id) = Id::new(&email) {
            return id;
        }
    }

    let pubkey = msg.signing_key.to_string();

    // Try to look up the signer's claimed name
    if let Some(db) = state {
        match db.get_name_for_pubkey(&pubkey) {
            Ok(Some(name)) => {
                if let Ok(id) = Id::new(&name) {
                    return id;
                }
            }
            Ok(None) => {} // No name claim, fall through
            Err(e) => {
                tracing::debug!("Error looking up name for pubkey: {}", e);
            }
        }
    }

    // Fall back to truncated key hex with type disambiguation
    // 16 hex chars of key material + 2 char prefix = 18 chars total
    let (prefix, key_hex) = if let Some(hex) = pubkey.strip_prefix("ed25519:") {
        ("e_", hex)
    } else if let Some(hex) = pubkey.strip_prefix("bls12-381:") {
        ("b_", hex)
    } else {
        ("", pubkey.as_str())
    };
    let key_part = &key_hex[..std::cmp::min(16, key_hex.len())];
    let creator_str = format!("{}{}", prefix, key_part);
    Id::new(&creator_str).unwrap_or_else(|_| Id::new("unknown").unwrap())
}

/// Enforce the HLC ordering-integrity rule (Content Spec §Validity bound) for a
/// write that carries an `HLC` header. A malformed `HLC` is always rejected. The
/// `T_b − W ≤ physical ≤ T_b + ε` bound is enforced only when the block's
/// inclusion time is known; absent a timestamp the bound cannot be evaluated and
/// we fail open on it (the write is still carried, matching the attribution
/// carry semantics). Returns `Err(reason)` if the write must be filtered.
///
/// `W` (max authoring lag) defaults to [`sbo_core::hlc::DEFAULT_MAX_AUTHORING_LAG_MS`];
/// per-collection `W` from a `collection.v1` descriptor is wired in a later step.
fn check_hlc_bound(msg: &Message, state: &dyn StateView, l2: &L2Context) -> Result<(), String> {
    let hlc_str = match &msg.hlc {
        Some(h) => h,
        None => return Ok(()), // no HLC → base inclusion-order semantics
    };
    let hlc = sbo_core::hlc::Hlc::parse(hlc_str).map_err(|e| format!("malformed HLC: {e}"))?;

    if let Some(t_b_secs) = l2.inclusion_time {
        let t_b_ms = t_b_secs.saturating_mul(1000);
        let max_lag = collection_max_lag_ms(msg, state);
        let skew = sbo_core::hlc::DEFAULT_SKEW_TOLERANCE_MS;
        if !hlc.within_bound(t_b_ms, max_lag, skew) {
            return Err(format!(
                "HLC physical {} outside validity bound [{}, {}] (T_b={}ms, W={}ms, ε={}ms)",
                hlc.physical,
                t_b_ms - max_lag,
                t_b_ms + skew,
                t_b_ms,
                max_lag,
                skew
            ));
        }
    }
    Ok(())
}

/// Resolve the collection's `W` (max authoring lag) in **milliseconds** for a
/// write, from a `collection.v1` descriptor at the write's collection root
/// (`<path>/_config`). Absent a descriptor (or its `max_authoring_lag_s`), the
/// collection defaults to a small `W` ([`sbo_core::hlc::DEFAULT_MAX_AUTHORING_LAG_MS`]).
/// The descriptor is looked up at the write's own path; deeper ancestor
/// resolution is a later refinement.
fn collection_max_lag_ms(msg: &Message, state: &dyn StateView) -> i64 {
    let descriptor = state
        .get_first_object_at_path_id(&msg.path, &Id::new(sbo_core::schema::COLLECTION_CONFIG_ID).unwrap())
        .ok()
        .flatten();
    if let Some(obj) = descriptor {
        if obj.content_schema.as_deref() == Some("collection.v1") {
            if let Ok(collection) = sbo_core::schema::parse_collection(&obj.payload) {
                if let Some(lag_s) = collection.max_authoring_lag_s {
                    return lag_s.saturating_mul(1000);
                }
            }
        }
    }
    sbo_core::hlc::DEFAULT_MAX_AUTHORING_LAG_MS
}

/// Validate the `Prev` causal-link header (Content Spec §Causal Links), if
/// present: it must be the hex encoding of a 32-byte `object_hash`. `Prev` points
/// at the version a mutable write was based on; the chain of links is a
/// verifiable per-object history. We validate only its *form* here — that the
/// referenced version actually exists is a read-side/indexer concern, not a
/// validity rule (a write may legitimately reference a version not yet seen).
fn check_prev(msg: &Message) -> Result<(), String> {
    let prev = match &msg.prev {
        Some(p) => p,
        None => return Ok(()), // a create sets no Prev
    };
    if prev.len() != 64 || !prev.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "malformed Prev '{prev}': expected 64 hex chars (a 32-byte object_hash)"
        ));
    }
    Ok(())
}

/// Last-writer-wins admission check (Content Spec §Conflict Resolution): whether
/// an incoming write should overwrite the current value at its key. When both the
/// incoming write and the existing object carry an `HLC`, the incoming one is
/// admitted only if it **wins** the total order (HLC, then signer public key,
/// then `object_hash`) — making LWW independent of inclusion order so a
/// back-dated write included later cannot clobber a higher-HLC value. If either
/// side lacks an `HLC` (or the `HLC` fails to parse), base inclusion-order
/// semantics apply and the write is admitted. `object_hash` is the incoming
/// write's hash (the full raw bytes).
pub fn lww_admits(msg: &Message, existing: Option<&StoredObject>, object_hash: &[u8; 32]) -> bool {
    let (Some(new_hlc_str), Some(old)) = (&msg.hlc, existing) else {
        return true;
    };
    let Some(old_hlc_str) = &old.hlc else {
        return true;
    };
    let (Ok(new_hlc), Ok(old_hlc)) = (
        sbo_core::hlc::Hlc::parse(new_hlc_str),
        sbo_core::hlc::Hlc::parse(old_hlc_str),
    ) else {
        return true;
    };
    let new_signer = msg.signing_key.to_string();
    let new_key = sbo_core::hlc::LwwKey { hlc: new_hlc, signer: &new_signer, object_hash };
    let old_key = sbo_core::hlc::LwwKey {
        hlc: old_hlc,
        signer: old.owner.as_str(),
        object_hash: &old.object_hash,
    };
    sbo_core::hlc::lww_wins(new_key, old_key)
}

/// The effective owner reference for a message, per the Authorization Spec
/// verification algorithm: the `Owner` header, else the `Creator` header, else
/// the signing key. The L2 gate authorizes the signer against this reference.
fn effective_owner_ref(msg: &Message) -> String {
    if let Some(owner) = &msg.owner {
        owner.as_str().to_string()
    } else if let Some(creator) = &msg.creator {
        creator.as_str().to_string()
    } else {
        msg.signing_key.to_string()
    }
}

/// Validate a message against the current state
pub fn validate_message(
    msg: &Message,
    state: &dyn StateView,
    _repo_path: &Path,
    l2: &L2Context,
) -> ValidationResult {
    // 1. Verify cryptographic signature
    if let Err(e) = sbo_core::message::verify_message(msg) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Signature,
            reason: e.to_string(),
        };
    }

    // 2. Validate payload against Content-Schema (if specified)
    if let Err(e) = validate_schema(msg) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Schema,
            reason: format_schema_error(&e),
        };
    }

    // 2.25. HLC ordering-integrity gate. A write that carries an `HLC` header
    // must parse and satisfy the validity bound against the block's inclusion
    // time (`T_b − W ≤ physical ≤ T_b + ε`). This bounds future-dating and
    // back-dated insertion; it is an ordering rule only and does not touch
    // attribution. Writes without an `HLC` use base inclusion-order semantics and
    // skip this gate. When the block carries no usable timestamp we cannot
    // evaluate the bound, so we only enforce the parse (fail-open on the bound,
    // matching the carry semantics elsewhere).
    if let Err(reason) = check_hlc_bound(msg, state, l2) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Ordering,
            reason,
        };
    }
    if let Err(reason) = check_prev(msg) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Ordering,
            reason,
        };
    }

    // 2.5. L2 attribution gate. The signer must speak for the write's
    // *effective owner* — `Owner`, else `Creator`, else the signing key
    // (Authorization Spec §Verification Algorithm) — at the block's inclusion
    // time. For key-rooted effective owners (including the signer-fallback case)
    // this is a direct key match the L1 signature already guarantees; for
    // email-rooted owners it requires valid browserid+DNSSEC attribution.
    // L1-valid but L2-unauthorized writes are carried by the DA layer but
    // disregarded here — they never reach state mutation.
    let effective_owner = effective_owner_ref(msg);
    if let Err(reason) = l2_authorize(msg, state, l2, &effective_owner) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Attribution,
            reason,
        };
    }

    // 3. Check if root policy exists (genesis check)
    // SECURITY: Fail closed if we can't determine root policy state
    let root_policy_status = check_root_policy_exists(state);
    if let RootPolicyCheck::Error(e) = &root_policy_status {
        tracing::error!("Cannot verify root policy state: {}", e);
        return ValidationResult::Invalid {
            stage: ValidationStage::State,
            reason: format!("Cannot verify root policy state: {}", e),
        };
    }
    let root_policy_exists = matches!(root_policy_status, RootPolicyCheck::Exists);

    // 4. Handle based on action
    match &msg.action {
        Action::Post => validate_post(msg, state, root_policy_exists, l2),
        Action::Transfer { .. } => validate_transfer(msg, state, root_policy_exists, l2),
        Action::Delete => validate_delete(msg, state, root_policy_exists, l2),
        Action::Import { .. } => {
            ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: "Import action not yet implemented".to_string(),
            }
        }
    }
}

/// Result of checking root policy existence
enum RootPolicyCheck {
    Exists,
    DoesNotExist,
    Error(String),
}

/// Check if the root policy (/sys/policies/root) exists
/// SECURITY: Returns explicit error on DB failure (fail closed)
fn check_root_policy_exists(state: &dyn StateView) -> RootPolicyCheck {
    let path = match SboPath::parse(ROOT_POLICY_PATH) {
        Ok(p) => p,
        Err(e) => return RootPolicyCheck::Error(format!("Invalid root policy path: {}", e)),
    };
    let id = match Id::new(ROOT_POLICY_ID) {
        Ok(id) => id,
        Err(e) => return RootPolicyCheck::Error(format!("Invalid root policy id: {}", e)),
    };
    // Use a default creator for system objects
    let creator = match Id::new("sys") {
        Ok(id) => id,
        Err(e) => return RootPolicyCheck::Error(format!("Invalid sys creator id: {}", e)),
    };

    match state.get_object(&path, &creator, &id) {
        Ok(Some(_)) => RootPolicyCheck::Exists,
        Ok(None) => RootPolicyCheck::DoesNotExist,
        Err(e) => RootPolicyCheck::Error(format!("DB error checking root policy: {}", e)),
    }
}

/// Validate a post action
fn validate_post(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Special handling for name claims: enforce uniqueness by (path, id)
    // Names under /sys/names/ and other name paths should only be claimed once
    if is_name_claim_path(&msg.path) {
        return validate_name_claim(msg, state, root_policy_exists, l2);
    }

    // Get the creator (use name resolution if available)
    let creator = resolve_creator(msg, Some(state), l2);

    // Check if object already exists
    // SECURITY: Fail closed - if we can't verify state, we must deny
    let existing = match state.get_object(&msg.path, &creator, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            tracing::error!("State DB error checking object existence: {}", e);
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("Cannot verify object state (DB error): {}", e),
            };
        }
    };

    if let Some(existing_obj) = existing {
        // Object exists - this is an update. Authorize the signer against the
        // object's *resolved controller* (its stored `owner_ref`), not the
        // legacy signer-key `owner`: a direct key match for key-rooted owners,
        // browserid attribution for email-rooted owners. The controller can
        // always update their own object.
        let owner_ref = stored_owner_ref(&existing_obj);
        if l2_authorize(msg, state, l2, owner_ref).is_ok() {
            tracing::debug!("Controller updating object {}:{}", msg.path, msg.id);
        } else {
            // Signer is not the controller - must check policy for update.
            if let Err(reason) = check_policy(state, msg, ActionType::Update, Some(owner_ref), l2) {
                return ValidationResult::Invalid {
                    stage: ValidationStage::Policy,
                    reason,
                };
            }
        }
    } else if !root_policy_exists {
        // No root policy yet - this might be genesis
        // Allow any post since we're bootstrapping
        tracing::debug!("Allowing post without root policy (genesis mode)");
    } else {
        // New object creation - must check policy
        if let Err(reason) = check_policy(state, msg, ActionType::Create, None, l2) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason,
            };
        }
    }

    ValidationResult::Valid { creator: creator.to_string() }
}

/// Check if a path is a name claim path (requires uniqueness by path/id)
fn is_name_claim_path(path: &SboPath) -> bool {
    let path_str = path.to_string();
    // /sys/names/ is for name claims
    path_str.starts_with("/sys/names/")
}

/// Validate a name claim (enforces uniqueness by path/id, not path/creator/id)
fn validate_name_claim(
    msg: &Message,
    state: &dyn StateView,
    _root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Check if ANY object exists at this path/id (regardless of creator)
    // SECURITY: Fail closed - if we can't verify state, we must deny
    let existing = match state.get_first_object_at_path_id(&msg.path, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            tracing::error!("State DB error checking name claim: {}", e);
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("Cannot verify name claim state (DB error): {}", e),
            };
        }
    };

    // The claimed name is the ID
    let claimed_name = msg.id.as_str().to_string();

    if let Some(existing_obj) = existing {
        // Name already claimed - the updater must be the current controller.
        // Authorize against the stored controller (`owner_ref`): a direct key
        // match for key-rooted name records, browserid attribution for
        // email-rooted ones (whose ephemeral signer key rotates, so a direct
        // key match would lock the owner out after a cert rotation).
        let owner_ref = stored_owner_ref(&existing_obj);
        if let Err(reason) = l2_authorize(msg, state, l2, owner_ref) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Attribution,
                reason: format!("Name '{}' already claimed by {}: {}", msg.id.as_str(), owner_ref, reason),
            };
        }
        tracing::debug!("Controller updating name claim: {}", msg.id.as_str());
    } else {
        // New name claim - allowed
        tracing::debug!("New name claim: {}", msg.id.as_str());
    }

    ValidationResult::Valid { creator: claimed_name }
}

/// Validate a transfer action
fn validate_transfer(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    if !root_policy_exists {
        return ValidationResult::Invalid {
            stage: ValidationStage::State,
            reason: "Cannot transfer before genesis".to_string(),
        };
    }

    // Get the creator (use name resolution if available)
    let creator = resolve_creator(msg, Some(state), l2);

    // Object must exist for transfer
    let existing = match state.get_object(&msg.path, &creator, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("State DB error: {}", e),
            };
        }
    };

    match existing {
        Some(obj) => {
            // Only the object's resolved controller may transfer/delete it.
            let owner_ref = stored_owner_ref(&obj);
            if let Err(reason) = l2_authorize(msg, state, l2, owner_ref) {
                return ValidationResult::Invalid {
                    stage: ValidationStage::Attribution,
                    reason: format!("Signer does not control owner {}: {}", owner_ref, reason),
                };
            }
            ValidationResult::Valid { creator: creator.to_string() }
        }
        None => {
            ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: "Cannot transfer non-existent object".to_string(),
            }
        }
    }
}

/// Validate a delete action
fn validate_delete(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Same rules as transfer
    validate_transfer(msg, state, root_policy_exists, l2)
}

/// The controller reference an existing object is owned by: its stored
/// `owner_ref` (the resolved effective owner recorded at write time), falling
/// back to the legacy signer-key `owner` for objects written before `owner_ref`
/// was recorded. This is what ownership checks authorize the signer against.
fn stored_owner_ref(obj: &StoredObject) -> &str {
    obj.owner_ref.as_deref().unwrap_or_else(|| obj.owner.as_str())
}

/// Check if an action is allowed by policy
/// Returns Ok(()) if allowed, Err(reason) if denied
fn check_policy(
    state: &dyn StateView,
    msg: &Message,
    action: ActionType,
    owner: Option<&str>,
    l2: &L2Context,
) -> Result<(), String> {
    // Resolve the applicable policy by walking up the path hierarchy
    let policy = match state.resolve_policy(&msg.path) {
        Ok(Some(p)) => p,
        Ok(None) => {
            // No policy found - deny by default
            // This shouldn't happen if root policy exists, but fail closed
            return Err("No applicable policy found".to_string());
        }
        Err(e) => {
            tracing::error!("Error resolving policy: {}", e);
            return Err(format!("Error resolving policy: {}", e));
        }
    };

    // Resolve the actor's identity (name if available, otherwise key-based)
    let actor = resolve_creator(msg, Some(state), l2);
    let target_path = msg.path.to_string();

    // The owner reference the `owner` policy identity authorizes against: an
    // explicit owner (the existing object's resolved controller, for updates),
    // else the namespace owner derived from the target path (for creates).
    let owner_ref: Option<String> = owner.map(|s| s.to_string()).or_else(|| {
        if action == ActionType::Create {
            sbo_core::policy::extract_namespace_owner(&target_path)
        } else {
            None
        }
    });
    // Whether the signer speaks for that owner's resolved controller (a direct
    // key match for key-rooted owners, browserid attribution for email-rooted
    // owners). This is what satisfies a `to: owner` grant.
    let signer_is_owner = owner_ref
        .as_deref()
        .map(|o| l2_authorize(msg, state, l2, o).is_ok())
        .unwrap_or(false);

    // The acting user's controller, for attestation-defined roles/conditions:
    // the attributed email if the signer carries valid attribution, else the
    // signing key. Matches an `attested` source whose subject resolves to it.
    let requester = match attributed_email(msg, Some(state), l2) {
        Some(email) => Controller::Email(email),
        None => Controller::Key(msg.signing_key.to_string()),
    };
    let is_attested = |source: &AttestedSource| attested_subject_matches(state, l2, &requester, source);

    // Evaluate the policy
    match evaluate(&policy, &actor, action, &target_path, owner, signer_is_owner, &is_attested, msg) {
        PolicyResult::Allowed => {
            tracing::debug!(
                "Policy allowed {:?} on {} by {}",
                action,
                target_path,
                actor
            );
            Ok(())
        }
        PolicyResult::Denied(reason) => {
            tracing::info!(
                "Policy denied {:?} on {} by {}: {}",
                action,
                target_path,
                actor,
                reason
            );
            Err(reason)
        }
    }
}

/// Whether an in-force `attestation.v1` exists matching `source` whose subject
/// resolves to `requester` (the acting user's controller), per the Policy Spec
/// §Attestation-Defined Roles: `type` equals `source.type_`, the issuer matches
/// `source.by` (when given), and the attestation is in force at the block's
/// inclusion time.
///
/// When `by` is given we prefix-scan that issuer's namespace
/// (`/<by>/attestations/`); otherwise we scan all `attestation.v1` objects (any
/// issuer, including a self-attestation). All inputs are on-chain and
/// inclusion-time-pinned, so the decision is deterministic on replay.
fn attested_subject_matches(
    state: &dyn StateView,
    l2: &L2Context,
    requester: &Controller,
    source: &AttestedSource,
) -> bool {
    let lookup = name_lookup(state);
    let t = l2.inclusion_time.unwrap_or(0);
    let candidates = match &source.by {
        Some(by) => state
            .list_objects_by_path_prefix(&format!("/{by}/attestations/"))
            .unwrap_or_default(),
        None => state
            .list_objects_by_schema("attestation.v1")
            .unwrap_or_default(),
    };
    candidates.into_iter().any(|obj| {
        if obj.content_schema.as_deref() != Some("attestation.v1") {
            return false;
        }
        let att = match parse_attestation(&obj.payload) {
            Ok(a) => a,
            Err(_) => return false,
        };
        if att.type_ != source.type_ || !att.is_in_force(t) {
            return false;
        }
        // When `by` is given, confirm the issuer (the attestation's controller)
        // resolves to the same party — the prefix is just the writer's literal
        // issuer string.
        if let Some(by) = &source.by {
            let issuer_ctrl = resolve_controller(stored_owner_ref(&obj), &lookup, DEFAULT_HOP_LIMIT);
            // Must resolve to the same, *grounded* controller — two unresolvable
            // references must not match each other.
            if matches!(issuer_ctrl, Controller::Unresolved | Controller::None)
                || issuer_ctrl != resolve_controller(by, &lookup, DEFAULT_HOP_LIMIT)
            {
                return false;
            }
        }
        resolve_controller(&att.subject, &lookup, DEFAULT_HOP_LIMIT) == *requester
    })
}

/// Create a StoredObject from a Message
/// If state is provided, uses name resolution for the creator field
/// object_hash should be sha256(raw_sbo_bytes) - the hash of the complete serialized message
pub fn message_to_stored_object(
    msg: &Message,
    block_number: u64,
    state: Option<&dyn StateView>,
    object_hash: [u8; 32],
    l2: &L2Context,
) -> Option<StoredObject> {
    // Only objects with content can be stored
    let payload = msg.payload.as_ref()?;
    let content_hash = msg.content_hash.as_ref()?;
    let content_type = msg.content_type.as_ref()?;

    // Resolve the author's durable identity (attributed email for email-rooted
    // writes, so the creator segment is stable across browserid key rotation).
    let creator = resolve_creator(msg, state, l2);

    // Legacy signer-key owner record (retained for objects/proofs that still
    // read it). Ownership checks key off `owner_ref` (the resolved controller).
    let owner = Id::new(&msg.signing_key.to_string())
        .unwrap_or_else(|_| Id::new("unknown").unwrap());

    Some(StoredObject {
        path: msg.path.clone(),
        id: msg.id.clone(),
        creator,
        owner,
        content_type: content_type.clone(),
        content_hash: content_hash.clone(),
        payload: payload.clone(),
        policy_ref: msg.policy_ref.clone(),
        content_schema: msg.content_schema.clone(),
        // Record the resolved effective owner (Owner → else Creator → else
        // signer) so later ownership checks authorize against the controller,
        // not the ephemeral signer key. Always set (never None for new writes).
        owner_ref: Some(effective_owner_ref(msg)),
        block_number,
        object_hash,
        hlc: msg.hlc.clone(),
        prev: msg.prev.clone(),
    })
}

/// Format a schema error for display
fn format_schema_error(e: &SchemaError) -> String {
    match e {
        SchemaError::UnknownSchema(schema) => {
            format!("Unknown Content-Schema: {}", schema)
        }
        SchemaError::InvalidJson(err) => {
            format!("Invalid JSON payload: {}", err)
        }
        SchemaError::MissingField(field) => {
            format!("Missing required field: {}", field)
        }
        SchemaError::InvalidField { field, reason } => {
            format!("Invalid field '{}': {}", field, reason)
        }
        SchemaError::KeyMismatch { payload_key, header_key } => {
            format!(
                "Key mismatch: public_key in payload ({}) does not match Public-Key header ({})",
                payload_key, header_key
            )
        }
        SchemaError::EmptyPayload => {
            "Payload is empty but Content-Schema requires validation".to_string()
        }
    }
}
