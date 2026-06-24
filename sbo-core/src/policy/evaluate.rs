//! Policy evaluation

use crate::message::{Message, Id};
use super::types::{Policy, ActionType, AttestedSource, Identity};

/// Resolves an [`AttestedSource`] against on-chain attestations for the acting
/// user: returns `true` when an in-force `attestation.v1` of `type` (by `by`,
/// when given) exists whose subject resolves to the requester's controller.
/// Supplied by the caller (the daemon, with state + inclusion time); pure
/// tests pass a stub.
pub type AttestedCheck<'a> = dyn Fn(&AttestedSource) -> bool + 'a;

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
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    policy: &Policy,
    actor: &Id,
    action: ActionType,
    target_path: &str,
    owner: Option<&str>,
    signer_is_owner: bool,
    is_attested: &AttestedCheck,
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
        let action_matches = grant.can.iter().any(|granted| action_covered_by(*granted, action));
        let identity_match = identity_matches(&grant.to, actor, &actor_key, effective_owner_ref, signer_is_owner, is_attested, &policy.roles);

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
            if let Some(reason) = check_requirements(&restriction.require, message, is_attested) {
                return PolicyResult::Denied(reason);
            }
        }
    }

    PolicyResult::Allowed
}

/// Whether a granted action covers a requested action. `post` is shorthand for
/// `create` + `update` (Policy Spec §Actions), so a `post` grant authorizes both
/// `create` and `update` requests; `*` covers everything. The daemon only ever
/// requests `Create`/`Update`/`Delete`/`Transfer` (it maps a `post` envelope to
/// `create` or `update` by object existence), so the `post`⇒{create,update}
/// expansion is what makes community `can: ["post"]` grants work.
fn action_covered_by(granted: ActionType, requested: ActionType) -> bool {
    granted == ActionType::All
        || granted == requested
        || (granted == ActionType::Post
            && matches!(requested, ActionType::Create | ActionType::Update))
}

/// Extract namespace owner from path (first component)
/// e.g., "/alice/nfts/" -> Some("alice"), "/sys/names/" -> Some("sys")
pub fn extract_namespace_owner(path: &str) -> Option<String> {
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
    is_attested: &AttestedCheck,
) -> Option<String> {
    // Attestation conditions: the acting user must (not) be the in-force
    // subject of the named attestation.
    if let Some(source) = &require.attested {
        if !is_attested(source) {
            return Some(format!(
                "Acting user is not the in-force subject of attestation '{}'{}",
                source.type_,
                source.by.as_deref().map(|b| format!(" by {b}")).unwrap_or_default()
            ));
        }
    }
    if let Some(source) = &require.not_attested {
        if is_attested(source) {
            return Some(format!(
                "Acting user is the in-force subject of disallowed attestation '{}'{}",
                source.type_,
                source.by.as_deref().map(|b| format!(" by {b}")).unwrap_or_default()
            ));
        }
    }

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

#[allow(clippy::too_many_arguments)]
fn identity_matches(
    identity: &Identity,
    actor: &Id,
    actor_key: &str,
    owner: Option<&str>,
    signer_is_owner: bool,
    is_attested: &AttestedCheck,
    roles: &std::collections::HashMap<String, Vec<Identity>>,
) -> bool {
    match identity {
        Identity::Name(name) => {
            match name.as_str() {
                "*" => true,
                // The `owner` identity is satisfied when the signer speaks for
                // the object's resolved controller (key match for key-rooted
                // owners, browserid attribution for email-rooted owners),
                // computed by the caller via L2 — not a creator-name string
                // compare, which would never match an email-rooted owner.
                "owner" => signer_is_owner,
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
                members.iter().any(|m| identity_matches(m, actor, actor_key, owner, signer_is_owner, is_attested, roles))
            } else {
                false
            }
        }
        Identity::Attested { attested } => is_attested(attested),
        Identity::Any { any } => {
            any.iter().any(|id| identity_matches(id, actor, actor_key, owner, signer_is_owner, is_attested, roles))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ContentHash, Signature, SigningKey};
    use crate::message::{Action, ObjectType, Path};

    fn signed_msg() -> Message {
        let key = SigningKey::generate();
        let payload = b"{}".to_vec();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/alice/posts/").unwrap(),
            id: Id::new("p1").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature::parse(&"0".repeat(128)).unwrap(),
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: None,
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
        };
        msg.sign(&key);
        msg
    }

    fn owner_grant_policy() -> Policy {
        serde_json::from_value(serde_json::json!({
            "grants": [{"to": "owner", "can": ["*"], "on": "/$owner/**"}]
        }))
        .unwrap()
    }

    #[test]
    fn owner_grant_honors_signer_is_owner_not_actor_string() {
        let policy = owner_grant_policy();
        let msg = signed_msg();
        // The actor (a key-hex creator id) never string-equals the owner
        // "alice"; authorization must come from signer_is_owner.
        let actor = Id::new("e_deadbeef").unwrap();
        let no_attest = |_: &AttestedSource| false;

        // signer_is_owner = true → the `owner` grant applies → allowed.
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", Some("alice"), true, &no_attest, &msg),
            PolicyResult::Allowed
        ));
        // signer_is_owner = false → no matching grant → denied.
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", Some("alice"), false, &no_attest, &msg),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn owner_grant_works_for_email_owner_via_signer_is_owner() {
        // An email-rooted owner: `$owner` substitutes the email into the path
        // pattern, and signer_is_owner carries the attribution result. The old
        // `owner == actor` compare could never match an email owner.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "owner", "can": ["*"], "on": "/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_ephemeral").unwrap();
        let no_attest = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", Some("alice@example.com"), true, &no_attest, &msg),
            PolicyResult::Allowed
        ));
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", Some("alice@example.com"), false, &no_attest, &msg),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn post_grant_covers_create_and_update_not_delete() {
        // `post` is shorthand for create + update; a `post` grant must authorize
        // both (the daemon maps a `post` envelope to Create/Update by existence),
        // but must NOT authorize delete.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["post"], "on": "/public/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no_attest = |_: &AttestedSource| false;

        for action in [ActionType::Create, ActionType::Update, ActionType::Post] {
            assert!(
                matches!(
                    evaluate(&policy, &actor, action, "/public/p1/", None, false, &no_attest, &msg),
                    PolicyResult::Allowed
                ),
                "post grant should cover {action:?}"
            );
        }
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Delete, "/public/p1/", None, false, &no_attest, &msg),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn create_grant_does_not_imply_update() {
        // The create/update split must stay asymmetric: a bare `create` grant
        // (first-come-first-served) must not confer update rights.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/sys/names/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no_attest = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/sys/names/alice/", None, false, &no_attest, &msg),
            PolicyResult::Allowed
        ));
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Update, "/sys/names/alice/", None, false, &no_attest, &msg),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn attested_role_and_conditions_use_the_closure() {
        // A grant to an attestation-defined role.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "roles": { "mod": [{"attested": {"type": "role:moderator", "by": "c@x.org"}}] },
            "grants": [{"to": {"role": "mod"}, "can": ["post"], "on": "/**"}],
            "restrictions": [{"on": "/**", "require": {"not_attested": {"type": "ban"}}}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();

        // Attested as a moderator and not banned → allowed.
        let mod_not_banned = |s: &AttestedSource| s.type_ == "role:moderator";
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Post, "/space/", None, false, &mod_not_banned, &msg),
            PolicyResult::Allowed
        ));

        // Not attested as a moderator → no grant matches → denied.
        let none = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Post, "/space/", None, false, &none, &msg),
            PolicyResult::Denied(_)
        ));

        // Moderator but banned → grant matches but the not_attested restriction blocks.
        let mod_and_banned = |_: &AttestedSource| true;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Post, "/space/", None, false, &mod_and_banned, &msg),
            PolicyResult::Denied(_)
        ));
    }
}
