//! Policy evaluation

use crate::message::{Message, Id};
use super::types::{Policy, ActionType, Identity};

/// Result of policy evaluation
#[derive(Debug)]
pub enum PolicyResult {
    Allowed,
    Denied(String),
}

/// Evaluate a policy for an action
///
/// For CREATE actions, `owner` is None (no existing object). In this case,
/// we derive the "effective owner" from the target path's first component
/// (the namespace owner) for `$owner` variable resolution and identity matching.
pub fn evaluate(
    policy: &Policy,
    actor: &Id,
    action: ActionType,
    target_path: &str,
    owner: Option<&str>,
    message: &Message,
) -> PolicyResult {
    // For CREATE actions without an owner, derive effective owner from path
    // e.g., /alice/nfts/ -> alice is the namespace owner
    let effective_owner: Option<String> = owner.map(|s| s.to_string()).or_else(|| {
        if action == ActionType::Create {
            extract_namespace_owner(target_path)
        } else {
            None
        }
    });
    let effective_owner_ref = effective_owner.as_deref();

    tracing::debug!(
        "Policy eval: actor={}, action={:?}, path={}, owner={:?}, effective_owner={:?}",
        actor, action, target_path, owner, effective_owner_ref
    );

    // 1. Check deny list first
    for pattern in &policy.deny {
        if pattern.matches(&crate::message::Path::parse(target_path).unwrap(), effective_owner_ref) {
            return PolicyResult::Denied(format!("Path denied by pattern: {:?}", pattern));
        }
    }

    // Get actor's signing key for key-based identity matching
    let actor_key = message.signing_key.to_string();

    // 2. Find matching grant
    let mut grant_debug = Vec::new();
    let granted = policy.grants.iter().any(|grant| {
        let path_parsed = crate::message::Path::parse(target_path).unwrap();
        let path_matches = grant.on.matches(&path_parsed, effective_owner_ref);
        let action_matches = grant.can.contains(&action) || grant.can.contains(&ActionType::All);
        let identity_match = identity_matches(&grant.to, actor, &actor_key, effective_owner_ref, &policy.roles);

        grant_debug.push(format!(
            "  grant to={:?} can={:?} on={:?} -> path:{} action:{} identity:{}",
            grant.to, grant.can, grant.on,
            path_matches, action_matches, identity_match
        ));

        path_matches && action_matches && identity_match
    });

    if !granted {
        tracing::debug!("Grant evaluation:\n{}", grant_debug.join("\n"));
        return PolicyResult::Denied("No matching grant".to_string());
    }

    // 3. Check restrictions
    for restriction in &policy.restrictions {
        if restriction.on.matches(&crate::message::Path::parse(target_path).unwrap(), effective_owner_ref) {
            if let Some(reason) = check_requirements(&restriction.require, message) {
                return PolicyResult::Denied(reason);
            }
        }
    }

    PolicyResult::Allowed
}

/// Extract namespace owner from path (first component)
/// e.g., "/alice/nfts/" -> Some("alice"), "/sys/names/" -> Some("sys")
fn extract_namespace_owner(path: &str) -> Option<String> {
    path.trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Check if message satisfies requirements, returns Some(reason) if not satisfied
fn check_requirements(
    require: &super::types::Requirements,
    message: &Message,
) -> Option<String> {
    // Check max_size
    if let Some(max_size) = require.max_size {
        if let Some(ref payload) = message.payload {
            if payload.len() > max_size {
                return Some(format!(
                    "Payload size {} exceeds max_size {}",
                    payload.len(),
                    max_size
                ));
            }
        }
    }

    // Check content_type
    if let Some(ref required_type) = require.content_type {
        match &message.content_type {
            Some(actual_type) if actual_type == required_type => {}
            Some(actual_type) => {
                return Some(format!(
                    "Content type '{}' does not match required '{}'",
                    actual_type, required_type
                ));
            }
            None => {
                return Some(format!("Missing content type, required '{}'", required_type));
            }
        }
    }

    // Check schema
    if let Some(ref required_schema) = require.schema {
        let actual_schema = message.content_schema.as_deref();

        let matches = match required_schema {
            super::types::SchemaRequirement::Single(s) => {
                actual_schema == Some(s.as_str())
            }
            super::types::SchemaRequirement::Any { any } => {
                actual_schema.map_or(false, |a| any.iter().any(|s| s == a))
            }
        };

        if !matches {
            return Some(format!(
                "Schema {:?} does not match required {:?}",
                actual_schema, required_schema
            ));
        }
    }

    // Check require_payload_signed_by
    // This verifies the JWT issuer maps to an object at the required path pattern.
    // Note: Cryptographic signature verification happens in the daemon's validation layer.
    if let Some(ref signed_by) = require.require_payload_signed_by {
        if let Some(reason) = check_payload_signed_by(signed_by, message) {
            return Some(reason);
        }
    }

    None
}

/// Check if the payload's JWT issuer maps to an object at the required path pattern
fn check_payload_signed_by(
    signed_by: &super::types::RequirePayloadSignedBy,
    message: &Message,
) -> Option<String> {
    // Get payload
    let payload = message.payload.as_ref()?;

    // Try to parse as JWT (UTF-8 string)
    let token = match std::str::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => return Some("Payload is not valid UTF-8 (expected JWT)".to_string()),
    };

    // Decode JWT claims to get issuer
    let claims = match crate::jwt::decode_identity_claims(token) {
        Ok(c) => c,
        Err(e) => return Some(format!("Failed to decode JWT: {}", e)),
    };

    // Map issuer to object path
    let issuer_path = match issuer_to_path(&claims.iss) {
        Some(p) => p,
        None => {
            return Some(format!(
                "Issuer '{}' does not reference an external signing object",
                claims.iss
            ));
        }
    };

    // Check if issuer path matches the required pattern
    let pattern = super::path::PathPattern::new(&signed_by.path);
    let issuer_path_parsed = match crate::message::Path::parse(&issuer_path) {
        Ok(p) => p,
        Err(_) => return Some(format!("Invalid issuer path: {}", issuer_path)),
    };

    if !pattern.matches(&issuer_path_parsed, None) {
        return Some(format!(
            "Issuer path '{}' does not match required pattern '{}'",
            issuer_path, signed_by.path
        ));
    }

    None
}

/// Map a JWT issuer to an object path
///
/// - "domain:example.com" -> "/sys/domains/example.com"
/// - "self" -> None (no external object)
fn issuer_to_path(issuer: &str) -> Option<String> {
    if let Some(domain) = issuer.strip_prefix("domain:") {
        Some(format!("/sys/domains/{}", domain))
    } else if issuer == "self" {
        None // Self-signed, no external signing object
    } else {
        // Unknown issuer format - could extend in future
        None
    }
}

fn identity_matches(
    identity: &Identity,
    actor: &Id,
    actor_key: &str,
    owner: Option<&str>,
    roles: &std::collections::HashMap<String, Vec<Identity>>,
) -> bool {
    match identity {
        Identity::Name(name) => {
            match name.as_str() {
                "*" => true,
                "owner" => owner.map_or(false, |o| o == actor.as_str()),
                _ => name == actor.as_str(),
            }
        }
        Identity::Key { key } => {
            // Compare public keys, stripping algorithm prefix if present
            let key_clean = key.strip_prefix("ed25519:").unwrap_or(key);
            let actor_clean = actor_key.strip_prefix("ed25519:").unwrap_or(actor_key);
            key_clean == actor_clean
        }
        Identity::Role { role } => {
            if let Some(members) = roles.get(role) {
                members.iter().any(|m| identity_matches(m, actor, actor_key, owner, roles))
            } else {
                false
            }
        }
        Identity::Any { any } => {
            any.iter().any(|id| identity_matches(id, actor, actor_key, owner, roles))
        }
    }
}
