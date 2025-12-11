//! Message validation against state
//!
//! Validates SBO messages before they are applied to the repo.

use sbo_core::message::{Message, Action, Id, Path as SboPath};
use sbo_core::state::{StateDb, StoredObject};
use std::path::Path;

/// Validation result
#[derive(Debug)]
pub enum ValidationResult {
    /// Message is valid, proceed with write
    Valid,
    /// Message is invalid, skip with reason
    Invalid(String),
}

/// Root policy path constant
const ROOT_POLICY_PATH: &str = "/sys/policies/";
const ROOT_POLICY_ID: &str = "root";

/// Validate a message against the current state
pub fn validate_message(
    msg: &Message,
    state: &StateDb,
    _repo_path: &Path,
) -> ValidationResult {
    // 1. Verify cryptographic signature
    if let Err(e) = sbo_core::message::verify_message(msg) {
        return ValidationResult::Invalid(format!("Signature verification failed: {}", e));
    }

    // 2. Check if root policy exists (genesis check)
    let root_policy_exists = check_root_policy_exists(state);

    // 3. Handle based on action
    match &msg.action {
        Action::Post => validate_post(msg, state, root_policy_exists),
        Action::Transfer { .. } => validate_transfer(msg, state, root_policy_exists),
        Action::Delete => validate_delete(msg, state, root_policy_exists),
        Action::Import { .. } => {
            // TODO: Implement import validation
            ValidationResult::Invalid("Import action not yet implemented".to_string())
        }
    }
}

/// Check if the root policy (/sys/policies/root) exists
fn check_root_policy_exists(state: &StateDb) -> bool {
    let path = match SboPath::parse(ROOT_POLICY_PATH) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let id = match Id::new(ROOT_POLICY_ID) {
        Ok(id) => id,
        Err(_) => return false,
    };
    // Use a default creator for system objects
    let creator = match Id::new("sys") {
        Ok(id) => id,
        Err(_) => return false,
    };

    match state.get_object(&path, &creator, &id) {
        Ok(Some(_)) => true,
        _ => false,
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

    // Get the creator (defaults to signer's public key as ID)
    let creator = msg.creator.clone().unwrap_or_else(|| {
        // Use signing key hex as creator if not specified
        Id::new(&msg.signing_key.to_string().replace("ed25519:", "")[..16])
            .unwrap_or_else(|_| Id::new("unknown").unwrap())
    });

    // Check if object already exists
    let existing = match state.get_object(&msg.path, &creator, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            // Database error - log and allow (fail open for now)
            tracing::warn!("State DB error checking object: {}", e);
            None
        }
    };

    if let Some(existing_obj) = existing {
        // Object exists - verify signer matches owner
        let signer_key = msg.signing_key.to_string();
        let owner_key = existing_obj.owner.as_str();

        // For now, we store the signing key in the owner field
        // So we compare signing key to stored owner
        if !keys_match(&signer_key, owner_key) {
            return ValidationResult::Invalid(format!(
                "Signer {} does not match owner {}",
                signer_key, owner_key
            ));
        }
    } else if !root_policy_exists {
        // No root policy yet - this might be genesis
        // Allow any post since we're bootstrapping
        tracing::debug!("Allowing post without root policy (genesis mode)");
    } else {
        // New object creation - check policy allows it
        // TODO: Implement full policy evaluation
        // For now, allow all new object creation
    }

    ValidationResult::Valid
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
    let existing = match state.get_first_object_at_path_id(&msg.path, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            tracing::warn!("State DB error checking name claim: {}", e);
            None
        }
    };

    if let Some(existing_obj) = existing {
        // Name already claimed - verify signer matches owner
        let signer_key = msg.signing_key.to_string();
        let owner_key = existing_obj.owner.as_str();

        if !keys_match(&signer_key, owner_key) {
            return ValidationResult::Invalid(format!(
                "Name '{}' already claimed by {}",
                msg.id.as_str(), owner_key
            ));
        }
        // Same owner can update their name claim
        tracing::debug!("Owner updating name claim: {}", msg.id.as_str());
    } else {
        // New name claim - allowed
        tracing::debug!("New name claim: {}", msg.id.as_str());
    }

    ValidationResult::Valid
}

/// Validate a transfer action
fn validate_transfer(
    msg: &Message,
    state: &StateDb,
    root_policy_exists: bool,
) -> ValidationResult {
    if !root_policy_exists {
        return ValidationResult::Invalid("Cannot transfer before genesis".to_string());
    }

    let creator = msg.creator.clone().unwrap_or_else(|| {
        Id::new(&msg.signing_key.to_string().replace("ed25519:", "")[..16])
            .unwrap_or_else(|_| Id::new("unknown").unwrap())
    });

    // Object must exist for transfer
    let existing = match state.get_object(&msg.path, &creator, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            return ValidationResult::Invalid(format!("State DB error: {}", e));
        }
    };

    match existing {
        Some(obj) => {
            let signer_key = msg.signing_key.to_string();
            if !keys_match(&signer_key, obj.owner.as_str()) {
                return ValidationResult::Invalid(format!(
                    "Signer {} does not match owner {}",
                    signer_key, obj.owner
                ));
            }
            ValidationResult::Valid
        }
        None => {
            ValidationResult::Invalid("Cannot transfer non-existent object".to_string())
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

/// Create a StoredObject from a Message
pub fn message_to_stored_object(
    msg: &Message,
    block_number: u64,
) -> Option<StoredObject> {
    // Only objects with content can be stored
    let payload = msg.payload.as_ref()?;
    let content_hash = msg.content_hash.as_ref()?;
    let content_type = msg.content_type.as_ref()?;

    let creator = msg.creator.clone().unwrap_or_else(|| {
        Id::new(&msg.signing_key.to_string().replace("ed25519:", "")[..16])
            .unwrap_or_else(|_| Id::new("unknown").unwrap())
    });

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
