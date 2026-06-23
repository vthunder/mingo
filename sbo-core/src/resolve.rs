//! Pure identity resolution for SBO.
//!
//! This module implements the resolution rules from the SBO Identity
//! Specification as a self-contained, pure function. It has no dependency on
//! the state DB, the daemon, or attribution; the caller supplies a lookup
//! closure for `/sys/names/<name>` records and (for [`is_authorized`]) the
//! result of any attribution check.

use std::collections::HashSet;

/// The party that controls an object, after resolving its Owner reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Controller {
    /// Email-rooted: authorized via attribution (browserid cert + DNSSEC).
    Email(String),
    /// Key-rooted: authorized by a direct signature from this public key.
    Key(String),
    /// No controller (e.g. the reference was a delete sentinel).
    None,
    /// Could not resolve (cycle, missing record, or hop limit exceeded).
    Unresolved,
}

/// What a `/sys/names/<name>` record resolves to, for the lookup closure.
#[derive(Debug, Clone)]
pub enum NameRecord {
    /// Key-rooted name record (`identity.v1` with a public_key).
    KeyRooted(String), // the public_key string
    /// Email-rooted name record (`identity.email.v1`); carries its Owner
    /// reference to recurse on.
    EmailRooted(String), // the Owner reference (an email or another name)
}

/// Default maximum resolution hops.
pub const DEFAULT_HOP_LIMIT: u32 = 16;

/// Whether a reference is a bare public key (an algorithm-prefixed key string,
/// e.g. `ed25519:<hex>` or `bls12-381:<hex>`) rather than an email or a name.
fn is_key_reference(reference: &str) -> bool {
    reference.starts_with("ed25519:") || reference.starts_with("bls12-381:")
}

/// Resolve an identity reference to its controlling party.
///
/// `lookup` fetches a `/sys/names/<name>` record by name (returns `None` if
/// absent).
///
/// Resolution rules (from the Identity spec):
/// - `"null:"` resolves to [`Controller::None`].
/// - A reference containing `'@'` is a bare email and resolves to
///   [`Controller::Email`] (per spec, `@` always denotes a
///   browserid-attributable identity).
/// - A reference containing `':'` or `'/'` (and not matching the above) is a
///   cross-repo reference, which is out of scope for this single-repo version
///   and resolves to [`Controller::Unresolved`].
/// - Otherwise the reference is a local name and is looked up:
///   - missing record -> [`Controller::Unresolved`];
///   - key-rooted -> [`Controller::Key`];
///   - email-rooted -> recurse on its Owner reference.
///
/// Cycles (a name revisited during resolution) and exceeding `hop_limit`
/// both yield [`Controller::Unresolved`].
pub fn resolve_controller<F>(reference: &str, lookup: &F, hop_limit: u32) -> Controller
where
    F: Fn(&str) -> Option<NameRecord>,
{
    let mut visited: HashSet<String> = HashSet::new();
    let mut current = reference.to_string();
    let mut hops: u32 = 0;

    loop {
        // null sentinel: no controller.
        if current == "null:" {
            return Controller::None;
        }

        // Bare email: a browserid-attributable identity.
        if current.contains('@') {
            return Controller::Email(current);
        }

        // Bare public key (algorithm-prefixed): a key controller, authorized by
        // direct signature. This is the reference `effective_owner` produces
        // when it falls back to the signing key (Authorization Spec
        // §Verification Algorithm: `Owner → else Creator → else signer`). It is
        // checked before the cross-repo `:`/`/` rule because a key string such
        // as `ed25519:<hex>` also contains a colon.
        if is_key_reference(&current) {
            return Controller::Key(current);
        }

        // Cross-repo references are out of scope for this single-repo version.
        // TODO: cross-repo resolution (e.g. `avail:mainnet:13/alice`, `sbo://...`).
        if current.contains(':') || current.contains('/') {
            return Controller::Unresolved;
        }

        // Otherwise it is a local name requiring a lookup hop.
        if hops >= hop_limit {
            return Controller::Unresolved;
        }
        hops += 1;

        // Cycle detection: revisiting a name is unresolvable.
        if !visited.insert(current.clone()) {
            return Controller::Unresolved;
        }

        match lookup(&current) {
            None => return Controller::Unresolved,
            Some(NameRecord::KeyRooted(key)) => return Controller::Key(key),
            Some(NameRecord::EmailRooted(owner_ref)) => {
                // Indirection: continue resolving the owner reference.
                current = owner_ref;
            }
        }
    }
}

/// Whether a message signed by `signer_key`, with `attributed_email` (`Some(email)`
/// if the message carried a valid Auth-Cert attributing `signer_key` to that email
/// at inclusion time, else `None`), is authorized for an object whose Owner resolved
/// to `controller`.
///
/// Rules:
/// - [`Controller::Key`]: authorized iff `signer_key` equals the key.
/// - [`Controller::Email`]: authorized iff `attributed_email == Some(email)`.
/// - [`Controller::None`] / [`Controller::Unresolved`]: not authorized.
///   An object with no resolvable controller is not authorized here; whether a
///   delete/no-owner object should be treated specially is the caller's concern.
pub fn is_authorized(
    controller: &Controller,
    signer_key: &str,
    attributed_email: Option<&str>,
) -> bool {
    match controller {
        Controller::Key(k) => signer_key == k,
        Controller::Email(e) => attributed_email == Some(e.as_str()),
        Controller::None | Controller::Unresolved => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup_from(map: HashMap<String, NameRecord>) -> impl Fn(&str) -> Option<NameRecord> {
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn bare_email_resolves_to_email() {
        let lookup = lookup_from(HashMap::new());
        assert_eq!(
            resolve_controller("alice@example.com", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Email("alice@example.com".to_string())
        );
    }

    #[test]
    fn null_resolves_to_none() {
        let lookup = lookup_from(HashMap::new());
        assert_eq!(
            resolve_controller("null:", &lookup, DEFAULT_HOP_LIMIT),
            Controller::None
        );
    }

    #[test]
    fn name_key_rooted_resolves_to_key() {
        let mut map = HashMap::new();
        map.insert("alice".to_string(), NameRecord::KeyRooted("pk_abc".to_string()));
        let lookup = lookup_from(map);
        assert_eq!(
            resolve_controller("alice", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Key("pk_abc".to_string())
        );
    }

    #[test]
    fn name_email_rooted_recurses_to_email() {
        let mut map = HashMap::new();
        map.insert(
            "alice".to_string(),
            NameRecord::EmailRooted("alice@example.com".to_string()),
        );
        let lookup = lookup_from(map);
        assert_eq!(
            resolve_controller("alice", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Email("alice@example.com".to_string())
        );
    }

    #[test]
    fn multi_hop_indirection_resolves_to_email() {
        let mut map = HashMap::new();
        map.insert(
            "nameA".to_string(),
            NameRecord::EmailRooted("nameB".to_string()),
        );
        map.insert(
            "nameB".to_string(),
            NameRecord::EmailRooted("alice@x".to_string()),
        );
        let lookup = lookup_from(map);
        assert_eq!(
            resolve_controller("nameA", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Email("alice@x".to_string())
        );
    }

    #[test]
    fn missing_name_is_unresolved() {
        let lookup = lookup_from(HashMap::new());
        assert_eq!(
            resolve_controller("ghost", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Unresolved
        );
    }

    #[test]
    fn cycle_is_unresolved() {
        let mut map = HashMap::new();
        map.insert(
            "nameA".to_string(),
            NameRecord::EmailRooted("nameB".to_string()),
        );
        map.insert(
            "nameB".to_string(),
            NameRecord::EmailRooted("nameA".to_string()),
        );
        let lookup = lookup_from(map);
        assert_eq!(
            resolve_controller("nameA", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Unresolved
        );
    }

    #[test]
    fn hop_limit_exceeded_is_unresolved() {
        // Build a long chain n0 -> n1 -> ... -> n9 -> alice@x
        let mut map = HashMap::new();
        for i in 0..9 {
            map.insert(
                format!("n{i}"),
                NameRecord::EmailRooted(format!("n{}", i + 1)),
            );
        }
        map.insert("n9".to_string(), NameRecord::EmailRooted("alice@x".to_string()));
        let lookup = lookup_from(map);

        // Small hop limit cannot reach the email.
        assert_eq!(
            resolve_controller("n0", &lookup, 3),
            Controller::Unresolved
        );
        // Generous hop limit resolves fully.
        assert_eq!(
            resolve_controller("n0", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Email("alice@x".to_string())
        );
    }

    #[test]
    fn bare_key_resolves_to_key_controller() {
        let lookup = lookup_from(HashMap::new());
        // The signer-fallback effective owner: a raw algorithm-prefixed key
        // resolves to a key controller (despite containing a colon), authorized
        // by direct signature.
        assert_eq!(
            resolve_controller("ed25519:deadbeef", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Key("ed25519:deadbeef".to_string())
        );
        assert_eq!(
            resolve_controller("bls12-381:abc", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Key("bls12-381:abc".to_string())
        );
    }

    #[test]
    fn cross_repo_reference_is_unresolved() {
        let lookup = lookup_from(HashMap::new());
        assert_eq!(
            resolve_controller("avail:mainnet:13/alice", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Unresolved
        );
        assert_eq!(
            resolve_controller("repo/alice", &lookup, DEFAULT_HOP_LIMIT),
            Controller::Unresolved
        );
    }

    #[test]
    fn is_authorized_key_match() {
        let c = Controller::Key("pk_abc".to_string());
        assert!(is_authorized(&c, "pk_abc", None));
        assert!(!is_authorized(&c, "pk_other", None));
    }

    #[test]
    fn is_authorized_email_attribution() {
        let c = Controller::Email("alice@x".to_string());
        assert!(is_authorized(&c, "anykey", Some("alice@x")));
        assert!(!is_authorized(&c, "anykey", Some("bob@x")));
        assert!(!is_authorized(&c, "anykey", None));
    }

    #[test]
    fn is_authorized_none_and_unresolved_are_false() {
        assert!(!is_authorized(&Controller::None, "k", Some("alice@x")));
        assert!(!is_authorized(&Controller::Unresolved, "k", Some("alice@x")));
    }
}
