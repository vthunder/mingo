//! Inbound presentation verification (device-cert model), DNSSEC-rooted.
//!
//! The SPA hands us the 4-object access presentation the browserid dialog
//! produced for the user's external identity (audience = the app origin). We
//! verify it to root a mingo session.
//!
//! The issuer's signing key is resolved from its authenticated
//! `_browserid` **DNSSEC** record — the sole root of trust per the spec —
//! never from `.well-known` (a support document carries endpoints, never a
//! key, and a hosted primary serves no key at its own origin). Because the key
//! comes from the record, a hosted primary's `host=` is honored implicitly:
//! we never fetch the identity domain for a key. Shared resolver:
//! `browserid-dnssec`.

use std::collections::HashMap;

use browserid_core::device::AccessPresentation;
use browserid_core::{Error as CoreError, PublicKey};
use browserid_dnssec::{resolve_idp_key, DnsFetcher};

/// A verified external presentation: the certified email, plus the warrant
/// scopes when the presentation is scoped ("agent"-style).
pub struct VerifiedExternal {
    pub email: String,
    /// `Some(scopes)` iff the warrant carried a non-empty scope set — a scoped
    /// (delegated/"agent") grant at exactly this audience. `None` for an
    /// unscoped (plain-login/"user") warrant.
    pub agent: Option<Vec<String>>,
}

/// Verify a device-model access presentation
/// (`access_cert~assertion~warrant~config_cert`) and return the certified
/// external identity.
///
/// Every issuer key is DNSSEC-resolved. Authority (spec §8): each identity's
/// issuer must be that identity's own DNSSEC primary, or — for an identity
/// whose domain is not a DNSSEC primary — the accepted fallback broker. The
/// core join then verifies the four objects against those keys and enforces
/// identity/holder/audience consistency.
pub async fn verify_external_presentation(
    presentation: &str,
    audience: &str,
    trusted_broker: &str,
    fetcher: &DnsFetcher,
) -> Result<VerifiedExternal, String> {
    let pres = AccessPresentation::parse(presentation).map_err(|e| format!("parse: {}", e))?;

    // Resolve the IdP keys (grantee's access-cert issuer, grantor's config-cert
    // issuer) from their authenticated DNSSEC records.
    let access_iss = pres.access_cert.claims().iss.clone();
    let config_iss = pres.config_cert.claims().iss.clone();
    let mut keys: HashMap<String, PublicKey> = HashMap::new();
    for iss in [&access_iss, &config_iss] {
        if !keys.contains_key(iss) {
            let key = resolve_idp_key(fetcher, iss)
                .await
                .map_err(|e| format!("resolve issuer {}: {}", iss, e))?;
            keys.insert(iss.clone(), key);
        }
    }

    let verified = pres
        .verify(audience, |iss| {
            keys.get(iss)
                .cloned()
                .ok_or_else(|| CoreError::DiscoveryFailed {
                    domain: iss.to_string(),
                    reason: "issuer key not DNSSEC-resolved".to_string(),
                })
        })
        .map_err(|e| format!("presentation invalid: {}", e))?;

    // Per-identity issuer authority: the grantor (attributed identity) under
    // its config-cert issuer, and the grantee (actor) under its access-cert
    // issuer, each checked independently.
    for (identity, iss) in [
        (&verified.email, &verified.issuer),
        (&verified.grantee, &verified.grantee_issuer),
    ] {
        let domain = identity.split('@').nth(1).unwrap_or("");
        let is_primary = resolve_idp_key(fetcher, domain).await.is_ok();
        let authorized = if is_primary {
            iss == domain
        } else {
            iss == trusted_broker
        };
        if !authorized {
            return Err(format!("issuer '{}' not authorized for '{}'", iss, identity));
        }
    }

    let agent = (!verified.scopes.is_empty()).then(|| verified.scopes.clone());
    Ok(VerifiedExternal {
        email: verified.email,
        agent,
    })
}
