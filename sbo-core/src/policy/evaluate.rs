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
pub fn evaluate(
    policy: &Policy,
    actor: &Id,
    action: ActionType,
    target_path: &str,
    owner: Option<&str>,
    _message: &Message,
) -> PolicyResult {
    // 1. Check deny list first
    for pattern in &policy.deny {
        if pattern.matches(&crate::message::Path::parse(target_path).unwrap(), owner) {
            return PolicyResult::Denied(format!("Path denied by pattern: {:?}", pattern));
        }
    }

    // 2. Find matching grant
    let granted = policy.grants.iter().any(|grant| {
        // Check path matches
        if !grant.on.matches(&crate::message::Path::parse(target_path).unwrap(), owner) {
            return false;
        }

        // Check action allowed
        if !grant.can.contains(&action) && !grant.can.contains(&ActionType::All) {
            return false;
        }

        // Check identity matches
        identity_matches(&grant.to, actor, owner, &policy.roles)
    });

    if !granted {
        return PolicyResult::Denied("No matching grant".to_string());
    }

    // 3. Check restrictions
    for restriction in &policy.restrictions {
        if restriction.on.matches(&crate::message::Path::parse(target_path).unwrap(), owner) {
            // TODO: Check requirements (max_size, schema, content_type)
        }
    }

    PolicyResult::Allowed
}

fn identity_matches(
    identity: &Identity,
    actor: &Id,
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
            // TODO: Compare public key
            false
        }
        Identity::Role { role } => {
            if let Some(members) = roles.get(role) {
                members.iter().any(|m| identity_matches(m, actor, owner, roles))
            } else {
                false
            }
        }
        Identity::Any { any } => {
            any.iter().any(|id| identity_matches(id, actor, owner, roles))
        }
    }
}
