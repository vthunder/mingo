//! Client-side **capture** of SBO attribution material.
//!
//! This is the online, once-per-cert counterpart to `sbo-core`'s deterministic
//! attribution *verifier*. It mints the two values an email-rooted SBO write
//! carries:
//!
//! - **`Auth-Cert`** — a browserid certificate binding the SBO `Public-Key`
//!   (ephemeral) ↔ the user's email, obtained from a broker's `/wsapi/cert_key`
//!   endpoint after authenticating.
//! - **`Auth-Evidence`** — an RFC 9102 DNSSEC proof of the broker's
//!   `_browserid.<issuer>` TXT record, gathered live via `dnssec-prover`'s
//!   query feature and serialized as `inline:<base64url>`.
//!
//! The capture path is inherently online (HTTP to the broker, DNS to a
//! resolver). Offline unit tests cover the request/response shapes and the
//! evidence encoding; the network round-trips are exercised by `#[ignore]`d
//! live tests against the real broker (`id.sandmill.org`) — mirroring the
//! verifier's split in `sbo-core::attribution`.

use std::net::SocketAddr;

use browserid_core::discovery::SupportDocument;
use browserid_core::{Certificate, PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use dnssec_prover::query::build_txt_proof_async;
use dnssec_prover::rr::Name;

/// The default DNS resolver to gather DNSSEC evidence from (Cloudflare, TCP).
pub const DEFAULT_RESOLVER: &str = "1.1.1.1:53";

/// Everything an email-rooted SBO write needs to carry for L2 attribution.
#[derive(Debug, Clone)]
pub struct CapturedAttribution {
    /// The `Auth-Cert` header value (browserid certificate, encoded JWT).
    pub auth_cert: String,
    /// The `Auth-Evidence` header value (`inline:<base64url>` DNSSEC proof).
    pub auth_evidence: String,
    /// The certificate's issuer domain (the broker), for reference/logging.
    pub issuer: String,
}

/// Failure modes of the capture flow.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// An HTTP request to the broker failed at the transport level.
    #[error("broker request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The broker authenticated request was rejected.
    #[error("authentication failed{0}")]
    AuthRejected(String),
    /// The broker declined to issue a certificate.
    #[error("certificate provisioning failed{0}")]
    ProvisionRejected(String),
    /// The issued certificate could not be parsed.
    #[error("issued certificate could not be parsed: {0}")]
    BadCertificate(String),
    /// The DNSSEC evidence query failed.
    #[error("DNSSEC evidence capture failed: {0}")]
    Evidence(String),
    /// A domain/name was malformed.
    #[error("invalid name '{0}'")]
    BadName(String),
}

// ---------------------------------------------------------------------------
// Broker wire types (mirror browserid-broker's wsapi shapes).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuthenticateRequest<'a> {
    email: &'a str,
    pass: &'a str,
}

#[derive(Deserialize)]
struct AuthenticateResponse {
    success: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct CertKeyRequest<'a> {
    email: &'a str,
    /// browserid `PublicKey` serializes as `{algorithm, publicKey}` — exactly
    /// the broker's expected `pubkey` shape.
    pubkey: &'a PublicKey,
    ephemeral: bool,
}

#[derive(Deserialize)]
struct CertKeyResponse {
    success: bool,
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// A thin client for a browserid broker. Carries a cookie store so the session
/// established by [`BrokerClient::authenticate`] is reused by
/// [`BrokerClient::provision`].
pub struct BrokerClient {
    base_url: String,
    http: reqwest::Client,
}

impl BrokerClient {
    /// Construct a client for a broker base URL (e.g. `https://id.sandmill.org`).
    pub fn new(base_url: impl Into<String>) -> Result<Self, CaptureError> {
        let http = reqwest::Client::builder().cookie_store(true).build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Fetch the broker's support document (`GET /.well-known/browserid`).
    pub async fn discover(&self) -> Result<SupportDocument, CaptureError> {
        let url = format!("{}/.well-known/browserid", self.base_url);
        let doc = self.http.get(&url).send().await?.error_for_status()?.json().await?;
        Ok(doc)
    }

    /// Authenticate to the broker (`POST /wsapi/authenticate_user`), establishing
    /// a session cookie used by the subsequent provisioning call.
    pub async fn authenticate(&self, email: &str, pass: &str) -> Result<(), CaptureError> {
        let url = format!("{}/wsapi/authenticate_user", self.base_url);
        let resp: AuthenticateResponse = self
            .http
            .post(&url)
            .json(&AuthenticateRequest { email, pass })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(CaptureError::AuthRejected(reason_suffix(resp.reason)));
        }
        Ok(())
    }

    /// Request a certificate binding `user_pubkey` ↔ `email`
    /// (`POST /wsapi/cert_key`). Requires a prior [`authenticate`](Self::authenticate).
    /// Returns the encoded certificate (the `Auth-Cert` value).
    pub async fn provision(
        &self,
        email: &str,
        user_pubkey: &PublicKey,
        ephemeral: bool,
    ) -> Result<String, CaptureError> {
        let url = format!("{}/wsapi/cert_key", self.base_url);
        let resp: CertKeyResponse = self
            .http
            .post(&url)
            .json(&CertKeyRequest { email, pubkey: user_pubkey, ephemeral })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(CaptureError::ProvisionRejected(reason_suffix(resp.reason)));
        }
        resp.cert
            .ok_or_else(|| CaptureError::ProvisionRejected(": broker returned no cert".to_string()))
    }
}

fn reason_suffix(reason: Option<String>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!(": {r}"),
        _ => String::new(),
    }
}

/// The FQDN whose TXT record carries a provider's browserid key:
/// `_browserid.<domain>.` (note the trailing dot required by `dnssec-prover`).
pub fn provider_record_name(domain: &str) -> Result<Name, CaptureError> {
    let fqdn = format!("_browserid.{}.", domain.trim_end_matches('.'));
    Name::try_from(fqdn.as_str()).map_err(|_| CaptureError::BadName(fqdn))
}

/// Capture an RFC 9102 DNSSEC proof of `_browserid.<domain>` from `resolver`,
/// returning the raw proof bytes (consumed by `sbo-core`'s verifier).
pub async fn capture_evidence(resolver: SocketAddr, domain: &str) -> Result<Vec<u8>, CaptureError> {
    let name = provider_record_name(domain)?;
    let (proof, _ttl) = build_txt_proof_async(resolver, &name)
        .await
        .map_err(|e| CaptureError::Evidence(e.to_string()))?;
    Ok(proof)
}

/// Run the full capture: authenticate to the broker, provision a certificate
/// for `user_pubkey` ↔ `email`, then gather DNSSEC evidence for the cert's
/// issuer. Returns the `Auth-Cert` + `Auth-Evidence` pair.
pub async fn capture_attribution(
    broker_base_url: &str,
    email: &str,
    password: &str,
    user_pubkey: &PublicKey,
    resolver: SocketAddr,
) -> Result<CapturedAttribution, CaptureError> {
    let broker = BrokerClient::new(broker_base_url)?;
    broker.authenticate(email, password).await?;
    let auth_cert = broker.provision(email, user_pubkey, true).await?;

    // The evidence must cover the cert's issuer (the provider whose key signed
    // it), since the verifier extracts `_browserid.<iss>` from the proof.
    let cert = Certificate::parse(&auth_cert)
        .map_err(|e| CaptureError::BadCertificate(e.to_string()))?;
    let issuer = cert.issuer().to_string();

    let proof = capture_evidence(resolver, &issuer).await?;
    let auth_evidence = sbo_core::authorize::encode_auth_evidence_inline(&proof);

    Ok(CapturedAttribution { auth_cert, auth_evidence, issuer })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_record_name_is_fqdn() {
        let n = provider_record_name("id.sandmill.org").unwrap();
        assert_eq!(n.as_str(), "_browserid.id.sandmill.org.");
        // A trailing dot on input is tolerated.
        let n2 = provider_record_name("sandmill.org.").unwrap();
        assert_eq!(n2.as_str(), "_browserid.sandmill.org.");
    }

    #[test]
    fn authenticate_request_shape() {
        let body = serde_json::to_value(AuthenticateRequest { email: "a@b.com", pass: "pw" }).unwrap();
        assert_eq!(body, serde_json::json!({"email": "a@b.com", "pass": "pw"}));
    }

    #[test]
    fn cert_key_request_shape() {
        let pk = browserid_core::KeyPair::generate().public_key();
        let body = serde_json::to_value(CertKeyRequest {
            email: "a@b.com",
            pubkey: &pk,
            ephemeral: true,
        })
        .unwrap();
        assert_eq!(body["email"], "a@b.com");
        assert_eq!(body["ephemeral"], true);
        assert_eq!(body["pubkey"]["algorithm"], "Ed25519");
        assert_eq!(body["pubkey"]["publicKey"], pk.to_base64());
    }

    #[test]
    fn cert_key_response_parses_success_and_failure() {
        let ok: CertKeyResponse =
            serde_json::from_value(serde_json::json!({"success": true, "cert": "JWT"})).unwrap();
        assert!(ok.success);
        assert_eq!(ok.cert.as_deref(), Some("JWT"));

        let err: CertKeyResponse =
            serde_json::from_value(serde_json::json!({"success": false, "reason": "nope"})).unwrap();
        assert!(!err.success);
        assert_eq!(err.reason.as_deref(), Some("nope"));
    }

    #[test]
    fn support_document_deserializes() {
        let doc: SupportDocument = serde_json::from_value(serde_json::json!({
            "public-key": {"algorithm": "Ed25519", "publicKey": "5w9yzPdFp5kjZZLbYl4jaR6EeS9VYGDEakzAf-a8Q9E"},
            "authentication": "/auth",
            "provisioning": "/provision"
        }))
        .unwrap();
        assert_eq!(doc.authentication.as_deref(), Some("/auth"));
        assert_eq!(doc.provisioning.as_deref(), Some("/provision"));
    }

    #[test]
    fn evidence_inline_roundtrips_with_verifier_parser() {
        let proof = b"\x00\x01rfc9102-proof\xfe\xff";
        let encoded = sbo_core::authorize::encode_auth_evidence_inline(proof);
        assert!(encoded.starts_with("inline:"));
        let decoded = sbo_core::authorize::parse_auth_evidence(&encoded).unwrap();
        assert_eq!(decoded, proof);
    }

    /// Live test: capture real DNSSEC evidence for `_browserid.sandmill.org`
    /// from a validating resolver. Requires network; run with
    /// `cargo test -p sbo-capture -- --ignored`.
    #[tokio::test]
    #[ignore = "requires live DNS"]
    async fn live_capture_evidence_sandmill() {
        let resolver: SocketAddr = DEFAULT_RESOLVER.parse().unwrap();
        let proof = capture_evidence(resolver, "sandmill.org").await.unwrap();
        assert!(!proof.is_empty());
        // The proof must validate offline against the pinned IANA root.
        let rrs = dnssec_prover::ser::parse_rr_stream(&proof).unwrap();
        dnssec_prover::validation::verify_rr_stream(&rrs).unwrap();
    }
}
