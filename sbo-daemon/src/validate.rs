//! Message validation against state
//!
//! Validates SBO messages before they are applied to the repo.

use sbo_core::authorize::{authorize_message, AuthzOutcome};
use sbo_core::attribution::TrustAnchors;
use sbo_core::message::{Message, Action, Id, Path as SboPath};
use sbo_core::policy::{evaluate, ActionType, PolicyResult};
use sbo_core::resolve::{NameRecord, DEFAULT_HOP_LIMIT};
use sbo_core::schema::{validate_schema, SchemaError};
use sbo_core::state::{StateDb, StoredObject};
use std::path::Path;

/// Validation stage that failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    Signature,
    Schema,
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
    pub fn for_block(inclusion_time: Option<i64>, state: &StateDb) -> Self {
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
fn load_trust_anchors(state: &StateDb) -> TrustAnchors {
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
fn name_lookup(state: &StateDb) -> impl Fn(&str) -> Option<NameRecord> + '_ {
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
fn l2_authorize(msg: &Message, state: &StateDb, l2: &L2Context, owner_ref: &str) -> Result<(), String> {
    let signer = msg.signing_key.to_string();
    let lookup = name_lookup(state);
    // An unknown block time cannot satisfy any cert/RRSig window, so email-rooted
    // owners fail closed; key-rooted owners are time-independent.
    let inclusion_time = l2.inclusion_time.unwrap_or(0);
    match authorize_message(
        owner_ref,
        &signer,
        msg.auth_cert.as_deref(),
        msg.auth_evidence.as_deref(),
        inclusion_time,
        &l2.anchors,
        &lookup,
        DEFAULT_HOP_LIMIT,
    ) {
        AuthzOutcome::Authorized => Ok(()),
        AuthzOutcome::Unauthorized(reason) => Err(reason),
    }
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

/// Resolve the creator ID for a message.
/// If the message has an explicit creator, use it.
/// Otherwise, look up the signer's claimed name, or fall back to truncated key hex.
pub fn resolve_creator(msg: &Message, state: Option<&StateDb>) -> Id {
    // If message has explicit creator, use it
    if let Some(creator) = &msg.creator {
        return creator.clone();
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

/// Validate a message against the current state
pub fn validate_message(
    msg: &Message,
    state: &StateDb,
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

    // 2.5. L2 attribution gate. When a write declares an Owner controller
    // reference, the signer must speak for it (direct key match for key-rooted
    // owners, valid browserid+DNSSEC attribution for email-rooted owners) at the
    // block's inclusion time. L1-valid but L2-unauthorized writes are carried by
    // the DA layer but disregarded here — they never reach state mutation.
    if let Some(owner) = &msg.owner {
        if let Err(reason) = l2_authorize(msg, state, l2, owner.as_str()) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Attribution,
                reason,
            };
        }
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
fn check_root_policy_exists(state: &StateDb) -> RootPolicyCheck {
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
    state: &StateDb,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Special handling for name claims: enforce uniqueness by (path, id)
    // Names under /sys/names/ and other name paths should only be claimed once
    if is_name_claim_path(&msg.path) {
        return validate_name_claim(msg, state, root_policy_exists, l2);
    }

    // Get the creator (use name resolution if available)
    let creator = resolve_creator(msg, Some(state));

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
        // Object exists - this is an update
        let signer_key = msg.signing_key.to_string();
        let owner_key = existing_obj.owner.as_str();

        // Email-rooted objects carry a controller reference in `owner_ref`; the
        // signer's durable key rotates, so authorize via L2 against the stored
        // controller rather than a direct key match.
        if let Some(owner_ref) = &existing_obj.owner_ref {
            if existing_obj.content_schema.as_deref() == Some("identity.email.v1")
                || owner_ref.contains('@')
            {
                if let Err(reason) = l2_authorize(msg, state, l2, owner_ref) {
                    return ValidationResult::Invalid {
                        stage: ValidationStage::Attribution,
                        reason,
                    };
                }
                return ValidationResult::Valid { creator: creator.to_string() };
            }
        }

        // Check if signer is the owner (owners can always update their objects)
        if keys_match(&signer_key, owner_key) {
            // Owner updating their own object - allowed
            tracing::debug!("Owner updating object {}:{}", msg.path, msg.id);
        } else {
            // Not the owner - must check policy for update permission
            if let Err(reason) = check_policy(state, msg, ActionType::Update, Some(owner_key)) {
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
        if let Err(reason) = check_policy(state, msg, ActionType::Create, None) {
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
    state: &StateDb,
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
        let signer_key = msg.signing_key.to_string();
        let owner_key = existing_obj.owner.as_str();

        // Email-rooted name records have an ephemeral, rotating signer key, so
        // re-authorize via L2 against the stored controller (the email) rather
        // than a direct key match — otherwise a key rotation locks the owner out.
        if let Some(owner_ref) = &existing_obj.owner_ref {
            if existing_obj.content_schema.as_deref() == Some("identity.email.v1")
                || owner_ref.contains('@')
            {
                if let Err(reason) = l2_authorize(msg, state, l2, owner_ref) {
                    return ValidationResult::Invalid {
                        stage: ValidationStage::Attribution,
                        reason: format!("Name '{}' is controlled by {}: {}", msg.id.as_str(), owner_ref, reason),
                    };
                }
                tracing::debug!("Email owner updating name claim: {}", msg.id.as_str());
                return ValidationResult::Valid { creator: claimed_name };
            }
        }

        if !keys_match(&signer_key, owner_key) {
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("Name '{}' already claimed by {}", msg.id.as_str(), owner_key),
            };
        }
        // Same owner can update their name claim
        tracing::debug!("Owner updating name claim: {}", msg.id.as_str());
    } else {
        // New name claim - allowed
        tracing::debug!("New name claim: {}", msg.id.as_str());
    }

    ValidationResult::Valid { creator: claimed_name }
}

/// Validate a transfer action
fn validate_transfer(
    msg: &Message,
    state: &StateDb,
    root_policy_exists: bool,
    _l2: &L2Context,
) -> ValidationResult {
    if !root_policy_exists {
        return ValidationResult::Invalid {
            stage: ValidationStage::State,
            reason: "Cannot transfer before genesis".to_string(),
        };
    }

    // Get the creator (use name resolution if available)
    let creator = resolve_creator(msg, Some(state));

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
            let signer_key = msg.signing_key.to_string();
            if !keys_match(&signer_key, obj.owner.as_str()) {
                return ValidationResult::Invalid {
                    stage: ValidationStage::State,
                    reason: format!("Signer {} does not match owner {}", signer_key, obj.owner),
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
    state: &StateDb,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Same rules as transfer
    validate_transfer(msg, state, root_policy_exists, l2)
}

/// Compare keys, handling different formats
fn keys_match(signer_key: &str, stored_owner: &str) -> bool {
    // Strip algorithm prefix if present
    let signer_clean = signer_key.strip_prefix("ed25519:").unwrap_or(signer_key);
    let owner_clean = stored_owner.strip_prefix("ed25519:").unwrap_or(stored_owner);

    signer_clean == owner_clean
}

/// Check if an action is allowed by policy
/// Returns Ok(()) if allowed, Err(reason) if denied
fn check_policy(
    state: &StateDb,
    msg: &Message,
    action: ActionType,
    owner: Option<&str>,
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
    let actor = resolve_creator(msg, Some(state));
    let target_path = msg.path.to_string();

    // Evaluate the policy
    match evaluate(&policy, &actor, action, &target_path, owner, msg) {
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

/// Create a StoredObject from a Message
/// If state is provided, uses name resolution for the creator field
/// object_hash should be sha256(raw_sbo_bytes) - the hash of the complete serialized message
pub fn message_to_stored_object(
    msg: &Message,
    block_number: u64,
    state: Option<&StateDb>,
    object_hash: [u8; 32],
) -> Option<StoredObject> {
    // Only objects with content can be stored
    let payload = msg.payload.as_ref()?;
    let content_hash = msg.content_hash.as_ref()?;
    let content_type = msg.content_type.as_ref()?;

    // Use name resolution for creator if state is available
    let creator = resolve_creator(msg, state);

    // Owner is the signing key (used for ownership verification)
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
        owner_ref: msg.owner.as_ref().map(|o| o.as_str().to_string()),
        block_number,
        object_hash,
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
