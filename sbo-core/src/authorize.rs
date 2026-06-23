//! L2 owner authorization — the bridge between attribution and ownership.
//!
//! This module composes the two halves of SBO's L2 (attribution) validity
//! layer into a single decision:
//!
//! 1. [`resolve::resolve_controller`] resolves an object's `Owner` reference to
//!    a [`Controller`] (a key, an email, or unresolvable).
//! 2. [`attribution::verify_attribution`] decides which email (if any) the
//!    signing key speaks for at the write's DA inclusion time.
//! 3. [`resolve::is_authorized`] combines the two: a key-rooted owner needs a
//!    direct signature match; an email-rooted owner needs the signer to be
//!    attributed to that email.
//!
//! The result is [`AuthzOutcome::Authorized`] or [`AuthzOutcome::Unauthorized`].
//! Per the Validity-Layers spec, an L1-valid but L2-unauthorized write is
//! *carried* by the DA layer but *disregarded* on replay — it must not mutate
//! owned state. Callers therefore treat [`AuthzOutcome::Unauthorized`] as a
//! skip, not a hard parse error.
//!
//! ## Testability
//!
//! The pure decision — [`authorize_owner`] — takes an already-computed
//! `attributed_email` and a name-lookup closure, so it is fully unit-testable
//! offline. The attribution glue — [`message_attribution`] — wraps
//! [`attribution::verify_attribution`], whose DNSSEC half cannot be exercised
//! with a synthetic offline proof (the IANA root is hardcoded); that path is
//! covered by attribution.rs's `#[ignore]`d live test.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::attribution::{self, Attribution, TrustAnchors};
use crate::resolve::{is_authorized, resolve_controller, Controller, NameRecord};

/// The outcome of an L2 owner-authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzOutcome {
    /// The signer is authorized to act for the object's owner.
    Authorized,
    /// The signer is not authorized. The message is well-formed (L1-valid) but
    /// must be disregarded on replay; the string explains why (for logging).
    Unauthorized(String),
}

impl AuthzOutcome {
    /// Whether the outcome is [`AuthzOutcome::Authorized`].
    pub fn is_authorized(&self) -> bool {
        matches!(self, AuthzOutcome::Authorized)
    }
}

/// Parse an `Auth-Evidence` header value into raw RFC 9102 proof bytes.
///
/// Supported forms:
/// - `inline:<base64url>` — the proof bytes, base64url (no padding), inline.
/// - `ref:<sbo-ref>` — a reference to a self-authenticating `dnssec.v1`
///   object. Resolving it requires state access this pure function does not
///   have, so it returns `Err` here; the caller may resolve the ref and call
///   [`attribution::verify_attribution`] directly with the fetched bytes.
///
/// A bare value with no recognized prefix is rejected.
pub fn parse_auth_evidence(value: &str) -> Result<Vec<u8>, String> {
    if let Some(b64) = value.strip_prefix("inline:") {
        URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("Auth-Evidence inline base64url decode failed: {e}"))
    } else if let Some(reference) = value.strip_prefix("ref:") {
        Err(format!(
            "Auth-Evidence ref '{reference}' cannot be resolved without state access"
        ))
    } else {
        Err("Auth-Evidence must be 'inline:<base64url>' or 'ref:<sbo-ref>'".to_string())
    }
}

/// Compute the [`Attribution`] for a message's signing key, if it carries a
/// valid `Auth-Cert` + `Auth-Evidence` pair verifying at `inclusion_time`.
///
/// Returns `None` when attribution is absent, malformed, or fails verification
/// — i.e. the signer is simply unattributed. (The reason is not surfaced; a
/// caller wanting the error should call [`attribution::verify_attribution`].)
pub fn message_attribution(
    signer_key: &str,
    auth_cert: Option<&str>,
    auth_evidence: Option<&str>,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Option<Attribution> {
    let cert = auth_cert?;
    let evidence_str = auth_evidence?;
    let evidence = parse_auth_evidence(evidence_str).ok()?;
    attribution::verify_attribution(signer_key, cert, &evidence, inclusion_time, anchors).ok()
}

/// Decide whether a write signed by `signer_key`, with optional
/// `attributed_email` (the email the signer was proven to speak for at
/// inclusion time, or `None`), is authorized for an object whose `Owner`
/// reference is `owner_ref`.
///
/// `lookup` resolves `/sys/names/<name>` records; `hop_limit` bounds name
/// indirection (use [`resolve::DEFAULT_HOP_LIMIT`]). Pure and deterministic.
pub fn authorize_owner<F>(
    owner_ref: &str,
    signer_key: &str,
    attributed_email: Option<&str>,
    lookup: &F,
    hop_limit: u32,
) -> AuthzOutcome
where
    F: Fn(&str) -> Option<NameRecord>,
{
    let controller = resolve_controller(owner_ref, lookup, hop_limit);
    if is_authorized(&controller, signer_key, attributed_email) {
        return AuthzOutcome::Authorized;
    }
    let reason = match controller {
        Controller::Key(k) => format!(
            "owner '{owner_ref}' is key-rooted ({k}) but signer is {signer_key}"
        ),
        Controller::Email(e) => match attributed_email {
            Some(att) => format!(
                "owner '{owner_ref}' is email-rooted ({e}) but signer is attributed to {att}"
            ),
            None => format!(
                "owner '{owner_ref}' is email-rooted ({e}) but signer carries no valid attribution"
            ),
        },
        Controller::None => format!("owner '{owner_ref}' resolves to no controller"),
        Controller::Unresolved => format!("owner '{owner_ref}' could not be resolved"),
    };
    AuthzOutcome::Unauthorized(reason)
}

/// Convenience: compute the message's attribution and authorize it against
/// `owner_ref` in one call. The daemon uses this on replay.
#[allow(clippy::too_many_arguments)]
pub fn authorize_message<F>(
    owner_ref: &str,
    signer_key: &str,
    auth_cert: Option<&str>,
    auth_evidence: Option<&str>,
    inclusion_time: i64,
    anchors: &TrustAnchors,
    lookup: &F,
    hop_limit: u32,
) -> AuthzOutcome
where
    F: Fn(&str) -> Option<NameRecord>,
{
    let attribution =
        message_attribution(signer_key, auth_cert, auth_evidence, inclusion_time, anchors);
    let email = attribution.as_ref().map(|a| a.email.as_str());
    authorize_owner(owner_ref, signer_key, email, lookup, hop_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::DEFAULT_HOP_LIMIT;
    use std::collections::HashMap;

    fn lookup_from(map: HashMap<String, NameRecord>) -> impl Fn(&str) -> Option<NameRecord> {
        move |name: &str| map.get(name).cloned()
    }

    fn empty_lookup() -> impl Fn(&str) -> Option<NameRecord> {
        lookup_from(HashMap::new())
    }

    #[test]
    fn key_rooted_owner_authorized_by_direct_signature() {
        let mut map = HashMap::new();
        map.insert("alice".to_string(), NameRecord::KeyRooted("pk_alice".to_string()));
        let lookup = lookup_from(map);
        // Owner resolves to a key; signer matches → authorized, no attribution needed.
        assert_eq!(
            authorize_owner("alice", "pk_alice", None, &lookup, DEFAULT_HOP_LIMIT),
            AuthzOutcome::Authorized
        );
    }

    #[test]
    fn key_rooted_owner_rejects_wrong_signer() {
        let mut map = HashMap::new();
        map.insert("alice".to_string(), NameRecord::KeyRooted("pk_alice".to_string()));
        let lookup = lookup_from(map);
        assert!(matches!(
            authorize_owner("alice", "pk_mallory", None, &lookup, DEFAULT_HOP_LIMIT),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn email_rooted_owner_authorized_by_matching_attribution() {
        let lookup = empty_lookup();
        // Bare-email owner; signer attributed to that email → authorized.
        assert_eq!(
            authorize_owner(
                "alice@example.com",
                "ephemeral_key",
                Some("alice@example.com"),
                &lookup,
                DEFAULT_HOP_LIMIT
            ),
            AuthzOutcome::Authorized
        );
    }

    #[test]
    fn email_rooted_owner_rejects_missing_attribution() {
        let lookup = empty_lookup();
        assert!(matches!(
            authorize_owner(
                "alice@example.com",
                "ephemeral_key",
                None,
                &lookup,
                DEFAULT_HOP_LIMIT
            ),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn email_rooted_owner_rejects_wrong_email_attribution() {
        let lookup = empty_lookup();
        assert!(matches!(
            authorize_owner(
                "alice@example.com",
                "ephemeral_key",
                Some("bob@example.com"),
                &lookup,
                DEFAULT_HOP_LIMIT
            ),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn name_indirection_to_email_authorized() {
        // alice (a name) → identity.email.v1 owned by alice@example.com.
        let mut map = HashMap::new();
        map.insert(
            "alice".to_string(),
            NameRecord::EmailRooted("alice@example.com".to_string()),
        );
        let lookup = lookup_from(map);
        assert_eq!(
            authorize_owner(
                "alice",
                "ephemeral_key",
                Some("alice@example.com"),
                &lookup,
                DEFAULT_HOP_LIMIT
            ),
            AuthzOutcome::Authorized
        );
    }

    #[test]
    fn unresolved_owner_is_unauthorized() {
        let lookup = empty_lookup();
        assert!(matches!(
            authorize_owner("ghost", "k", Some("a@b"), &lookup, DEFAULT_HOP_LIMIT),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn parse_inline_evidence_roundtrips() {
        let bytes = b"\x00\x01\x02proof-bytes\xff";
        let encoded = format!("inline:{}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(parse_auth_evidence(&encoded).unwrap(), bytes);
    }

    #[test]
    fn parse_ref_evidence_is_unsupported_here() {
        assert!(parse_auth_evidence("ref:/sys/dnssec/example.com").is_err());
    }

    #[test]
    fn parse_bare_evidence_rejected() {
        assert!(parse_auth_evidence("deadbeef").is_err());
    }

    #[test]
    fn message_attribution_none_without_cert() {
        let anchors = TrustAnchors::default();
        assert!(message_attribution("k", None, Some("inline:AAAA"), 0, &anchors).is_none());
        assert!(message_attribution("k", Some("cert"), None, 0, &anchors).is_none());
    }
}
