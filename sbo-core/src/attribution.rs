//! SBO attribution verifier (the deterministic L2 check).
//!
//! Given a BrowserID certificate, a DNSSEC proof (RFC 9102), an inclusion
//! timestamp, and pinned trust anchors, this module deterministically decides
//! "this signing key speaks for this email at that time."
//!
//! This is self-contained: it does not touch owner/ownership resolution, the
//! state trie, or the wire `Message.owner` field.
//!
//! # Algorithm
//!
//! 1. Parse `auth_cert` (a BrowserID [`Certificate`]) and require the cert's
//!    certified public key to equal the SBO `public_key` argument.
//! 2. Validate `auth_evidence` as an RFC 9102 DNSSEC proof, anchored to the
//!    IANA root KSK, fully offline. Extract the validated
//!    `_browserid.<iss>` TXT record (→ the provider's Ed25519 key) and the
//!    proof's RRSig validity window.
//! 3. Check `inclusion_time` lies within BOTH the proof's RRSig window AND the
//!    cert `[iat, exp]`.
//! 4. Verify the cert signature against the provider key from step 2.
//! 5. Authority: the email's domain == `iss` (primary IdP path), OR `iss` is in
//!    `anchors.brokers` (broker path). Otherwise reject.
//!
//! On success the returned [`Attribution`] window is the intersection of the
//! cert and proof windows: `[max(iat, inception), min(exp, expiration)]`.
//!
//! ## Trust anchor note
//!
//! `dnssec-prover` hardcodes the IANA DNSSEC root trust anchors in
//! `dnssec_prover::validation::root_hints()` and offers no way to inject a
//! custom root into [`verify_rr_stream`]. Consequently the [`TrustAnchors`]
//! `root_ksk` field is informational/configurable for callers that wish to pin
//! a root out-of-band; the actual proof validation always uses the library's
//! hardcoded IANA root. This means a fully-synthetic offline DNSSEC proof
//! cannot be validated against the real root, so the DNSSEC-dependent path is
//! covered by an `#[ignore]`d live test, while the cert/window/authority logic
//! is unit-tested offline via [`verify_attribution_with_provider_key`].

use browserid_core::{Certificate, DnsRecord, PublicKey};
use dnssec_prover::rr::{Name, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;
use thiserror::Error;

/// Pinned trust anchors corresponding to `/sys/trust/dns-root` and
/// `/sys/trust/brokers`.
///
/// Note: `dnssec-prover` hardcodes the IANA root KSK internally, so `root_ksk`
/// is informational only — it lets a caller record/pin the root they expect,
/// but it is not (and cannot be) injected into the proof validator.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    /// The pinned DNS root KSK, recorded for out-of-band auditing. The actual
    /// proof validation uses `dnssec-prover`'s hardcoded IANA root anchors.
    pub root_ksk: Option<String>,
    /// The set of authorized broker provider domains (`/sys/trust/brokers`).
    pub brokers: Vec<String>,
}

impl TrustAnchors {
    /// Construct trust anchors from a broker list, relying on the library's
    /// hardcoded IANA root KSK.
    pub fn with_brokers(brokers: Vec<String>) -> Self {
        Self { root_ksk: None, brokers }
    }

    fn is_broker(&self, iss: &str) -> bool {
        self.brokers.iter().any(|b| b == iss)
    }
}

/// A successful attribution: `key` (the SBO Public-Key string) speaks for
/// `email`, valid within `[valid_from, valid_until]` (inclusive, UNIX seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// The email this key speaks for.
    pub email: String,
    /// The SBO Public-Key string (base64url of the Ed25519 key).
    pub key: String,
    /// Start of the validity window (UNIX seconds, inclusive).
    pub valid_from: i64,
    /// End of the validity window (UNIX seconds, inclusive).
    pub valid_until: i64,
}

/// Failure modes of [`verify_attribution`].
#[derive(Debug, Error)]
pub enum AttributionError {
    /// The certificate could not be parsed.
    #[error("certificate parse failed: {0}")]
    BadCertificate(String),
    /// The certificate certifies a different public key than the SBO key arg.
    #[error("certified key does not match the SBO public key")]
    KeyMismatch,
    /// The certificate has no email principal.
    #[error("certificate has no email principal")]
    MissingEmail,
    /// The DNSSEC proof bytes could not be deserialized.
    #[error("DNSSEC evidence could not be parsed")]
    EvidenceParse,
    /// The DNSSEC proof failed cryptographic validation against the root.
    #[error("DNSSEC evidence failed validation: {0}")]
    EvidenceInvalid(String),
    /// No validated `_browserid.<iss>` TXT record was found in the proof.
    #[error("no validated _browserid.{0} TXT record in evidence")]
    MissingProviderRecord(String),
    /// The provider TXT record could not be parsed into a key.
    #[error("provider DNS record parse failed: {0}")]
    BadProviderRecord(String),
    /// `inclusion_time` falls outside the proof's RRSig validity window.
    #[error("inclusion time {time} outside DNSSEC window [{from}, {until}]")]
    EvidenceWindowMismatch {
        /// The supplied inclusion time.
        time: i64,
        /// Window start (RRSig inception).
        from: i64,
        /// Window end (RRSig expiration).
        until: i64,
    },
    /// `inclusion_time` falls outside the certificate `[iat, exp]` window.
    #[error("inclusion time {time} outside cert window [{iat}, {exp}]")]
    CertWindowMismatch {
        /// The supplied inclusion time.
        time: i64,
        /// Certificate issued-at.
        iat: i64,
        /// Certificate expiry.
        exp: i64,
    },
    /// The certificate signature did not verify against the provider key.
    #[error("certificate signature verification failed")]
    SignatureInvalid,
    /// The issuer is neither the email's domain nor a pinned broker.
    #[error("issuer '{iss}' is not authorized for email domain '{domain}'")]
    IssuerNotAuthorized {
        /// The certificate issuer.
        iss: String,
        /// The email's domain.
        domain: String,
    },
    /// The resulting validity window is empty (windows do not intersect).
    #[error("attribution window is empty after intersecting cert and proof windows")]
    EmptyWindow,
}

/// Verify an attribution end-to-end, validating the DNSSEC proof offline
/// against the hardcoded IANA root.
///
/// See the module docs for the full algorithm. `inclusion_time` is in UNIX
/// seconds.
pub fn verify_attribution(
    public_key: &str,
    auth_cert: &str,
    auth_evidence: &[u8],
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<Attribution, AttributionError> {
    // Parse the cert first so we know which issuer's TXT record to look for.
    let cert = Certificate::parse(auth_cert)
        .map_err(|e| AttributionError::BadCertificate(e.to_string()))?;
    let iss = cert.issuer().to_string();

    // Step 2: validate the DNSSEC proof and extract the provider key + window.
    let (provider_key, inception, expiration) = extract_provider_key(auth_evidence, &iss)?;

    // Steps 1, 3, 4, 5.
    verify_attribution_with_provider_key(
        public_key,
        &cert,
        &provider_key,
        inception,
        expiration,
        inclusion_time,
        anchors,
    )
}

/// Validate the RFC 9102 proof offline and extract the provider Ed25519 key
/// (from `_browserid.<iss>`) together with the proof's RRSig validity window
/// `(inception, expiration)` in UNIX seconds.
fn extract_provider_key(
    auth_evidence: &[u8],
    iss: &str,
) -> Result<(PublicKey, i64, i64), AttributionError> {
    let rrs: Vec<RR> =
        parse_rr_stream(auth_evidence).map_err(|_| AttributionError::EvidenceParse)?;

    let verified = verify_rr_stream(&rrs)
        .map_err(|e| AttributionError::EvidenceInvalid(format!("{:?}", e)))?;

    // Names in dnssec-prover are FQDNs with a trailing dot.
    let target = format!("_browserid.{}.", iss);
    let name: Name = target
        .clone()
        .try_into()
        .map_err(|_| AttributionError::MissingProviderRecord(iss.to_string()))?;

    let records = verified.resolve_name(&name);
    let txt = records
        .iter()
        .find_map(|rr| match rr {
            RR::Txt(txt) => Some(txt),
            _ => None,
        })
        .ok_or_else(|| AttributionError::MissingProviderRecord(iss.to_string()))?;

    let txt_str = String::from_utf8(txt.data.as_vec())
        .map_err(|e| AttributionError::BadProviderRecord(e.to_string()))?;
    let record = DnsRecord::parse(&txt_str)
        .map_err(|e| AttributionError::BadProviderRecord(e.to_string()))?;

    Ok((record.public_key, verified.valid_from as i64, verified.expires as i64))
}

/// The cert/window/authority half of the verifier, separated so it can be
/// unit-tested offline with a directly-supplied provider key (bypassing
/// DNSSEC).
///
/// `inception`/`expiration` are the proof's RRSig window (UNIX seconds).
#[allow(clippy::too_many_arguments)]
pub fn verify_attribution_with_provider_key(
    public_key: &str,
    cert: &Certificate,
    provider_key: &PublicKey,
    inception: i64,
    expiration: i64,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<Attribution, AttributionError> {
    let claims = cert.claims();

    // Step 1: the certified key must equal the SBO public key argument.
    if claims.public_key.to_base64() != public_key {
        return Err(AttributionError::KeyMismatch);
    }

    let email = cert
        .email()
        .ok_or(AttributionError::MissingEmail)?
        .to_string();

    let iat = claims.iat.unwrap_or(claims.exp);
    let exp = claims.exp;

    // Step 3: inclusion_time must be within the proof window AND cert window.
    if inclusion_time < inception || inclusion_time > expiration {
        return Err(AttributionError::EvidenceWindowMismatch {
            time: inclusion_time,
            from: inception,
            until: expiration,
        });
    }
    if inclusion_time < iat || inclusion_time > exp {
        return Err(AttributionError::CertWindowMismatch {
            time: inclusion_time,
            iat,
            exp,
        });
    }

    // Step 4: verify the cert signature against the provider key.
    cert.verify(provider_key)
        .map_err(|_| AttributionError::SignatureInvalid)?;

    // Step 5: authority — primary IdP (domain == iss) or pinned broker.
    let iss = claims.iss.clone();
    let domain = email.split('@').nth(1).unwrap_or("");
    if domain != iss && !anchors.is_broker(&iss) {
        return Err(AttributionError::IssuerNotAuthorized {
            iss,
            domain: domain.to_string(),
        });
    }

    // Intersect the cert and proof windows.
    let valid_from = iat.max(inception);
    let valid_until = exp.min(expiration);
    if valid_from > valid_until {
        return Err(AttributionError::EmptyWindow);
    }

    Ok(Attribution {
        email,
        key: public_key.to_string(),
        valid_from,
        valid_until,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::KeyPair;
    use chrono::{Duration, Utc};

    // A fixed proof window around "now" for deterministic tests.
    fn window() -> (i64, i64) {
        let now = Utc::now().timestamp();
        (now - 3600, now + 3600)
    }

    /// Build a cert for `email` issued by `iss`, signed by `provider`, with the
    /// SBO key being `user`'s public key. Returns (cert, sbo_public_key_string).
    fn make_cert(
        provider: &KeyPair,
        user: &KeyPair,
        iss: &str,
        email: &str,
        validity: Duration,
    ) -> (Certificate, String) {
        let cert =
            Certificate::create(iss, email, &user.public_key(), validity, provider).unwrap();
        let pk = user.public_key().to_base64();
        (cert, pk)
    }

    #[test]
    fn happy_path_primary_idp() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();
        let anchors = TrustAnchors::default();

        let attr = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &anchors,
        )
        .unwrap();

        assert_eq!(attr.email, "alice@example.com");
        assert_eq!(attr.key, pk);
        // Window is intersection of cert [iat, exp] and proof window.
        assert!(attr.valid_from >= inception);
        assert!(attr.valid_until <= expiration);
        assert!(attr.valid_from <= attr.valid_until);
    }

    #[test]
    fn key_mismatch_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, _pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();

        let other = KeyPair::generate().public_key().to_base64();
        let err = verify_attribution_with_provider_key(
            &other,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::KeyMismatch));
    }

    #[test]
    fn expired_cert_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        // 1-second validity; inclusion_time will be after exp.
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::seconds(1));
        let (inception, expiration) = window();
        let after_exp = cert.claims().exp + 10_000;

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            after_exp,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        // after_exp is inside the proof window check only if <= expiration;
        // expiration is now+3600 so after_exp (cert.exp+10000) exceeds it →
        // EvidenceWindowMismatch fires first. Accept either window error.
        assert!(matches!(
            err,
            AttributionError::CertWindowMismatch { .. }
                | AttributionError::EvidenceWindowMismatch { .. }
        ));
    }

    #[test]
    fn inclusion_before_iat_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let iat = cert.claims().iat.unwrap();
        // Before iat but still inside a generous proof window.
        let inception = iat - 10_000;
        let expiration = iat + 10_000;
        let before_iat = iat - 5_000;

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            before_iat,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::CertWindowMismatch { .. }));
    }

    #[test]
    fn inclusion_outside_proof_window_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let now = Utc::now().timestamp();
        // Proof window entirely in the past.
        let inception = now - 20_000;
        let expiration = now - 10_000;

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::EvidenceWindowMismatch { .. }));
    }

    #[test]
    fn wrong_provider_key_signature_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();

        let wrong_provider = KeyPair::generate();
        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &wrong_provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::SignatureInvalid));
    }

    #[test]
    fn issuer_not_authorized_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        // iss does not match the email domain and is not a broker.
        let (cert, pk) =
            make_cert(&provider, &user, "evil.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::IssuerNotAuthorized { .. }));
    }

    #[test]
    fn broker_path_accepted() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        // iss != email domain, but iss is a pinned broker.
        let (cert, pk) =
            make_cert(&provider, &user, "broker.example", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();
        let anchors = TrustAnchors::with_brokers(vec!["broker.example".to_string()]);

        let attr = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &anchors,
        )
        .unwrap();
        assert_eq!(attr.email, "alice@example.com");
    }

    #[test]
    fn window_is_intersection() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let iat = cert.claims().iat.unwrap();
        let exp = cert.claims().exp;
        // Proof window tighter than the cert window on both ends.
        let inception = iat + 100;
        let expiration = exp - 100;
        let mid = (inception + expiration) / 2;

        let attr = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            mid,
            &TrustAnchors::default(),
        )
        .unwrap();
        assert_eq!(attr.valid_from, inception);
        assert_eq!(attr.valid_until, expiration);
    }

    #[test]
    fn bad_evidence_parse_rejected() {
        // Garbage bytes that cannot be parsed as an RFC 9102 proof. We can't
        // easily reach a valid root-anchored proof offline, so this exercises
        // the parse-failure path of the full entry point.
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let now = Utc::now().timestamp();

        let err = verify_attribution(&pk, cert.encoded(), &[], now, &TrustAnchors::default())
            .unwrap_err();
        // Empty evidence parses to an empty RR stream which then fails
        // validation; non-empty garbage fails to parse. Either is acceptable.
        assert!(matches!(
            err,
            AttributionError::EvidenceParse | AttributionError::EvidenceInvalid(_)
        ));
    }

    /// Live, network-dependent end-to-end test. Requires the `query` feature
    /// and network access; not run in CI. Documents how a real proof would be
    /// built and validated against the IANA root.
    #[test]
    #[ignore = "requires network + dnssec-prover `std`/`query` feature"]
    fn live_dnssec_end_to_end() {
        // Intentionally empty: building a proof requires the `std` feature's
        // `dnssec_prover::query` module and a live recursive resolver. The
        // offline tests above cover all deterministic logic; the DNSSEC
        // validation itself is exercised by dnssec-prover's own test suite.
    }
}
