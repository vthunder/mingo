//! Message validation against state
//!
//! Validates SBO messages before they are applied to the repo.

use sbo_core::message::{Message, Action, Id, Path as SboPath};
use sbo_core::policy::{evaluate, ActionType, PolicyResult};
use sbo_core::state::{StateDb, StoredObject};
use std::path::Path;

/// Validation stage that failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    Signature,
    State,
    Policy,
}

impl std::fmt::Display for ValidationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStage::Signature => write!(f, "sig"),
            ValidationStage::State => write!(f, "state"),
            ValidationStage::Policy => write!(f, "policy"),
        }
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
fn resolve_creator(msg: &Message, state: Option<&StateDb>) -> Id {
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

    // Fall back to truncated key hex (without ed25519: prefix)
    let key_hex = pubkey.strip_prefix("ed25519:").unwrap_or(&pubkey);
    let truncated = &key_hex[..std::cmp::min(16, key_hex.len())];
    Id::new(truncated).unwrap_or_else(|_| Id::new("unknown").unwrap())
}

/// Validate a message against the current state
pub fn validate_message(
    msg: &Message,
    state: &StateDb,
    _repo_path: &Path,
) -> ValidationResult {
    // 1. Verify cryptographic signature
    if let Err(e) = sbo_core::message::verify_message(msg) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Signature,
            reason: e.to_string(),
        };
    }

    // 2. Check if root policy exists (genesis check)
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

    // 3. Handle based on action
    match &msg.action {
        Action::Post => validate_post(msg, state, root_policy_exists),
        Action::Transfer { .. } => validate_transfer(msg, state, root_policy_exists),
        Action::Delete => validate_delete(msg, state, root_policy_exists),
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
) -> ValidationResult {
    // Special handling for name claims: enforce uniqueness by (path, id)
    // Names under /sys/names/ and other name paths should only be claimed once
    if is_name_claim_path(&msg.path) {
        return validate_name_claim(msg, state, root_policy_exists);
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
        // Name already claimed - verify signer matches owner
        let signer_key = msg.signing_key.to_string();
        let owner_key = existing_obj.owner.as_str();

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
) -> ValidationResult {
    // Same rules as transfer
    validate_transfer(msg, state, root_policy_exists)
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
pub fn message_to_stored_object(
    msg: &Message,
    block_number: u64,
    state: Option<&StateDb>,
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
        block_number,
    })
}
