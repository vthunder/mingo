//! Inbound assertion verification.
//!
//! The SPA hands us the assertion the *broker* issued for the user's external
//! identity (audience = the app origin). We verify it to root a mingo session.
//! This is HTTP-discovery based (fetch the issuer's `.well-known/browserid`),
//! ported from the broker's `verifier.rs` so we depend only on `browserid-core`.
//! The trustless part — the cert *we* issue for `<handle>@mingo.place` — is
//! validated downstream by the broker via DNSSEC; this check only protects the
//! integrity of our own session.

use std::time::Duration;

use browserid_core::discovery::{
    discover, DiscoveryConfig, SupportDocument, SupportDocumentFetcher,
};
use browserid_core::{BackedAssertion, Error as CoreError, Result as CoreResult};

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
        Self { client, require_https }
    }
}

impl SupportDocumentFetcher for HttpFetcher {
    fn fetch(&self, domain: &str) -> CoreResult<SupportDocument> {
        let try_url = |scheme: &str| format!("{}://{}/.well-known/browserid", scheme, domain);
        let resp = self.client.get(try_url("https")).send();
        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            _ if !self.require_https => self.client.get(try_url("http")).send().map_err(|e| {
                CoreError::DiscoveryFailed { domain: domain.to_string(), reason: e.to_string() }
            })?,
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
        .map(|r| r.document.public_key)
        .map_err(|e| format!("discover {}: {}", domain, e))
}

/// Verify a backed assertion and return the certified external email on success.
///
/// Authorization (mirrors Persona / the broker): the cert issuer must be either
/// the trusted broker, the email's own domain (native primary), or a domain the
/// email's domain delegates to.
pub fn verify_external_assertion(
    assertion: &str,
    audience: &str,
    trusted_broker: &str,
    require_https: bool,
) -> Result<String, String> {
    let fetcher = HttpFetcher::new(require_https);
    let config = DiscoveryConfig::default();

    let backed = BackedAssertion::parse(assertion).map_err(|e| format!("parse: {}", e))?;
    let cert = backed
        .certificates()
        .first()
        .ok_or_else(|| "no certificate".to_string())?;

    let issuer = cert.issuer().to_string();
    let email = cert.email().ok_or_else(|| "cert has no email".to_string())?.to_string();
    let email_domain = email
        .split('@')
        .nth(1)
        .ok_or_else(|| "invalid email".to_string())?
        .to_string();

    let authorized = issuer == trusted_broker
        || issuer == email_domain
        || matches!(discover(&email_domain, &fetcher, &config), Ok(r) if r.domain == issuer);
    if !authorized {
        return Err(format!("issuer '{}' not authorized for '{}'", issuer, email_domain));
    }

    if backed.assertion().audience() != audience {
        return Err(format!(
            "audience mismatch: expected {}, got {}",
            audience,
            backed.assertion().audience()
        ));
    }
    if backed.assertion().is_expired() {
        return Err("assertion expired".to_string());
    }
    if cert.is_expired() {
        return Err("certificate expired".to_string());
    }
    backed
        .assertion()
        .verify(cert.public_key())
        .map_err(|e| format!("assertion signature invalid: {}", e))?;

    let issuer_key = discover(&issuer, &fetcher, &config)
        .map_err(|e| format!("discover issuer {}: {}", issuer, e))?
        .document
        .public_key;
    cert.verify(&issuer_key)
        .map_err(|e| format!("certificate signature invalid: {}", e))?;

    Ok(email)
}
