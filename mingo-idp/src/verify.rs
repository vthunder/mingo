//! Inbound presentation verification (device-cert model).
//!
//! The SPA hands us the 4-object access presentation the browserid dialog
//! produced for the user's external identity (audience = the app origin). We
//! verify it to root a mingo session. This is HTTP-discovery based (fetch the
//! issuer's `.well-known/browserid`), so we depend only on `browserid-core`.
//! The trustless part — the certs *we* issue for `<handle>@mingo.place` — is
//! validated downstream by RPs via DNSSEC; this check only protects the
//! integrity of our own session.

use std::time::Duration;

use browserid_core::discovery::{
    discover, DiscoveryConfig, SupportDocument, SupportDocumentFetcher,
};
use browserid_core::device::AccessPresentation;
use browserid_core::{Error as CoreError, Result as CoreResult};

/// HTTP support-document fetcher (HTTPS, optionally allowing HTTP for local dev).
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
    require_https: bool,
}

impl HttpFetcher {
    pub fn new(require_https: bool) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        Self {
            client,
            require_https,
        }
    }
}

impl SupportDocumentFetcher for HttpFetcher {
    fn fetch(&self, domain: &str) -> CoreResult<SupportDocument> {
        let try_url = |scheme: &str| format!("{}://{}/.well-known/browserid", scheme, domain);
        let resp = self.client.get(try_url("https")).send();
        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            _ if !self.require_https => {
                self.client
                    .get(try_url("http"))
                    .send()
                    .map_err(|e| CoreError::DiscoveryFailed {
                        domain: domain.to_string(),
                        reason: e.to_string(),
                    })?
            }
            Ok(r) => {
                return Err(CoreError::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: format!("HTTP {}", r.status()),
                })
            }
            Err(e) => {
                return Err(CoreError::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: e.to_string(),
                })
            }
        };
        resp.json().map_err(|e| CoreError::DiscoveryFailed {
            domain: domain.to_string(),
            reason: format!("invalid JSON: {}", e),
        })
    }
}

/// Fetch a broker/IdP domain's published signing key via `.well-known/browserid`
/// discovery — used to verify provisioning endorsements from the trusted broker
/// (mingo-ua8w / tdxf). Same HTTP-discovery path as assertion verification.
pub fn fetch_domain_pubkey(
    domain: &str,
    require_https: bool,
) -> Result<browserid_core::PublicKey, String> {
    let fetcher = HttpFetcher::new(require_https);
    let config = DiscoveryConfig::default();
    discover(domain, &fetcher, &config)
        .map_err(|e| format!("discover {}: {}", domain, e))?
        .document
        .public_key
        .ok_or_else(|| format!("{} published no public key", domain))
}

/// A verified external presentation: the certified email, plus the warrant
/// scopes when the presentation is scoped ("agent"-style).
pub struct VerifiedExternal {
    pub email: String,
    /// `Some(scopes)` iff the warrant carried a non-empty scope set — a scoped
    /// (delegated/"agent") grant at exactly this audience. `None` for an
    /// unscoped (plain-login/"user") warrant. The old user/agent subject axis is
    /// gone; the scope set is what distinguishes the two now.
    pub agent: Option<Vec<String>>,
}

/// Verify a device-model access presentation
/// (`access_cert~assertion~warrant~config_cert`) and return the certified
/// external identity.
///
/// Authorization (mirrors Persona / the broker): the issuer (shared by the
/// access cert and config cert — the core join enforces that) must be either
/// the trusted broker, the email's own domain (native primary), or a domain
/// the email's domain delegates to. The core join also verifies the warrant
/// against the config cert and the assertion against the fresh access key —
/// a warrant-less presentation never parses.
pub fn verify_external_presentation(
    presentation: &str,
    audience: &str,
    trusted_broker: &str,
    require_https: bool,
) -> Result<VerifiedExternal, String> {
    let fetcher = HttpFetcher::new(require_https);
    let config = DiscoveryConfig::default();

    let pres = AccessPresentation::parse(presentation).map_err(|e| format!("parse: {}", e))?;
    let ac = pres.access_cert.claims();
    let issuer = ac.iss.clone();
    let email = ac.identity.clone();
    let email_domain = email
        .split('@')
        .nth(1)
        .ok_or_else(|| "invalid email".to_string())?
        .to_string();

    let authorized = issuer == trusted_broker
        || issuer == email_domain
        || matches!(discover(&email_domain, &fetcher, &config), Ok(r) if r.domain == issuer);
    if !authorized {
        return Err(format!(
            "issuer '{}' not authorized for '{}'",
            issuer, email_domain
        ));
    }

    let issuer_key = discover(&issuer, &fetcher, &config)
        .map_err(|e| format!("discover issuer {}: {}", issuer, e))?
        .document
        .public_key
        .ok_or_else(|| format!("issuer {} published no public key", issuer))?;

    // The core join: both certs verify against the issuer key, the assertion
    // against the fresh access key, the warrant against the config cert, and
    // identity/holder/audience must be consistent across all four objects.
    let verified = pres
        .verify(audience, |iss| {
            if iss == issuer {
                Ok(issuer_key.clone())
            } else {
                Err(CoreError::DiscoveryFailed {
                    domain: iss.to_string(),
                    reason: "issuer not authoritative for this presentation".to_string(),
                })
            }
        })
        .map_err(|e| format!("presentation invalid: {}", e))?;

    // The user/agent axis is gone; a non-empty warrant scope set marks a
    // scoped ("agent") grant, an empty one a plain login ("user").
    let agent = (!verified.scopes.is_empty()).then(|| verified.scopes.clone());

    Ok(VerifiedExternal { email: verified.email, agent })
}
