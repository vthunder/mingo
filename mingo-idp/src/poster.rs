//! The **mingo-poster** server-side signer (mingo-3f3i): mingo signs SBO
//! objects on a consenting user's behalf so posting works with no client-side
//! signing popups (mobile Safari). One shared agent identity —
//! `mingo-poster@<domain>`, the [`poster_agent_email`] — signs every such
//! write with its key ([`AppState::poster_key`](crate::routes::AppState)),
//! attaching:
//!
//! - a **per-user agent cert** ([`mint_poster_cert`]): `agent =
//!   mingo-poster@<domain>`, `parent = <the delegating user>`, certifying the
//!   shared poster key, signed in-process by the mingo IdP key. The parent
//!   claim is inert without the user's warrant, so minting one needs no user
//!   authorization;
//! - the **user-signed warrant** the user granted once at their registrar
//!   (browserid.me), requested via [`external_warrant_request`]. Its `as:`
//!   scope makes the on-chain **effective author the user** (pseudonym
//!   preserved — the post reads "mingo-poster acting for <user>").
//!
//! browserid-core builds the certs/warrant/request (all JWS strings); sbo-core
//! assembles the SBO envelope. The two never meet at a type boundary — only
//! the encoded strings cross into the [`Message`].

use anyhow::{anyhow, Result};
use browserid_core::provisioning::{ExternalWarrantRequest, ProvisioningRequest, WarrantGrant};
use browserid_core::{Certificate, KeyPair, PublicKey};
use chrono::Duration;
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;

/// Recommended per-user agent cert lifetime; refresh before it lapses.
const CERT_VALIDITY_HOURS: i64 = 24;

/// The shared agent identity's email under this IdP domain.
pub fn poster_agent_email(domain: &str) -> String {
    format!("mingo-poster@{domain}")
}

/// Mint (in-process) a per-user mingo-poster agent cert, signed by the mingo
/// IdP key: `agent = mingo-poster@<domain>`, `parent = user_email`, certifying
/// the shared poster public key. `registrar` is stamped into the cert so
/// on-chain verifiers find where the warrant's status list is published.
pub fn mint_poster_cert(
    idp_key: &KeyPair,
    domain: &str,
    poster_pub: &PublicKey,
    user_email: &str,
    registrar: Option<String>,
) -> Result<Certificate> {
    Certificate::create_agent(
        domain,
        &poster_agent_email(domain),
        user_email,
        poster_pub,
        Duration::hours(CERT_VALIDITY_HOURS),
        idp_key,
        registrar,
    )
    .map_err(|e| anyhow!("mint poster cert: {e}"))
}

/// Build the `agent_cert~R` **external warrant request** mingo POSTs to the
/// user's registrar (`browserid.me/warrant/request`): `R` is signed by the
/// shared poster key, carries `delegator = user_email` and one grant at the
/// mingo db `audience` with `scopes` — which the registrar's consent page
/// copies verbatim into the warrant the user signs.
pub fn external_warrant_request(
    poster_key: &KeyPair,
    poster_cert: &Certificate,
    registrar_domain: &str,
    user_email: &str,
    audience: &str,
    scopes: Vec<String>,
) -> Result<String> {
    let grants = vec![WarrantGrant {
        aud: audience.to_string(),
        scopes: Some(scopes),
    }];
    let request =
        ProvisioningRequest::warrant_external(registrar_domain, user_email, grants, poster_key)
            .map_err(|e| anyhow!("build external warrant request: {e}"))?;
    Ok(ExternalWarrantRequest::new(poster_cert.clone(), request)
        .encoded()
        .to_string())
}

/// The warrant scopes mingo requests for a user: post on their behalf (`as:`,
/// making the effective author the user), bounded to mingo content paths and
/// schemas. The `as:` guardrail requires at least one `path:` scope, satisfied
/// here. Scopes are opaque to the registrar — it renders and copies them; the
/// daemon enforces them (`sbo_core::authorize`).
pub fn default_scopes(user_email: &str) -> Vec<String> {
    vec![
        "action:post".into(),
        "schema:post.v1".into(),
        "schema:comment.v1".into(),
        "schema:reaction.v1".into(),
        "schema:attestation.v1".into(),
        "path:/communities/**".into(),
        format!("path:/u/{user_email}/**"),
        format!("as:{user_email}"),
    ]
}

/// One SBO write mingo makes on a user's behalf.
pub struct WriteSpec<'a> {
    pub action: Action,
    pub path: &'a str,
    pub id: &'a str,
    pub schema: &'a str,
    pub content_type: &'a str,
    pub payload: Vec<u8>,
    /// The object's owner — the delegating user (the object lives in their
    /// namespace; the on-chain effective author resolves to them via the
    /// warrant's `as:` scope).
    pub owner: &'a str,
    pub hlc: Option<&'a str>,
    pub prev: Option<&'a str>,
}

/// Assemble the SBO wire bytes for [`WriteSpec`], signed by the shared poster
/// key and carrying `auth_cert` (the per-user agent cert), `auth_warrant` (the
/// user-signed warrant JWS), and `auth_evidence` (the DNSSEC proof reference
/// the daemon resolves). The result is what mingo POSTs to `<daemon>/v1/submit`.
pub fn assemble_agent_write(
    poster_key: &KeyPair,
    poster_cert: &Certificate,
    warrant_jws: &str,
    auth_evidence: &str,
    spec: WriteSpec<'_>,
) -> Result<Vec<u8>> {
    let key = SigningKey::from_bytes(poster_key.secret_bytes());
    let content_hash = ContentHash::sha256(&spec.payload);
    let mut msg = Message {
        action: spec.action,
        path: Path::parse(spec.path).map_err(|e| anyhow!("bad path '{}': {e}", spec.path))?,
        id: Id::new(spec.id).map_err(|e| anyhow!("bad id '{}': {e}", spec.id))?,
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        // Overwritten by `sign` below; a syntactically-valid placeholder.
        signature: Signature::parse(&"0".repeat(128)).expect("valid placeholder signature"),
        content_type: Some(spec.content_type.to_string()),
        content_hash: Some(content_hash),
        payload: Some(spec.payload),
        owner: Some(Id::new(spec.owner).map_err(|e| anyhow!("bad owner '{}': {e}", spec.owner))?),
        creator: None,
        content_encoding: None,
        content_schema: Some(spec.schema.to_string()),
        policy_ref: None,
        related: None,
        hlc: spec.hlc.map(str::to_string),
        prev: spec.prev.map(str::to_string),
        auth_cert: Some(poster_cert.encoded().to_string()),
        auth_evidence: Some(auth_evidence.to_string()),
        auth_warrant: Some(warrant_jws.to_string()),
    };
    msg.sign(&key);
    Ok(wire::serialize(&msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (KeyPair, KeyPair, Certificate) {
        let idp = KeyPair::generate();
        let poster = KeyPair::generate();
        let cert = mint_poster_cert(
            &idp,
            "mingo.place",
            &poster.public_key(),
            "dan@example.com",
            Some("https://browserid.me".into()),
        )
        .unwrap();
        (idp, poster, cert)
    }

    #[test]
    fn poster_cert_binds_agent_to_user_under_idp_key() {
        let (idp, poster, cert) = setup();
        assert!(cert.is_agent());
        assert_eq!(cert.email(), Some("mingo-poster@mingo.place"));
        assert_eq!(cert.agent_parent(), Some("dan@example.com"));
        assert_eq!(cert.public_key(), &poster.public_key());
        cert.verify(&idp.public_key())
            .expect("signed by the mingo IdP key");
    }

    #[test]
    fn external_request_verifies_as_the_registrar_would() {
        // The registrar (browserid.me) discovers mingo.place's key and runs
        // ExternalWarrantRequest::verify — mirror that here with the IdP key.
        let (idp, poster, cert) = setup();
        let bundle = external_warrant_request(
            &poster,
            &cert,
            "browserid.me",
            "dan@example.com",
            "sbo+raw://avail:turing:506/",
            default_scopes("dan@example.com"),
        )
        .unwrap();
        let parsed = ExternalWarrantRequest::parse(&bundle).unwrap();
        let verified = parsed
            .verify(&idp.public_key())
            .expect("registrar accepts it");
        assert_eq!(verified.agent_email, "mingo-poster@mingo.place");
        assert_eq!(verified.agent_issuer, "mingo.place");
        assert_eq!(verified.delegator, "dan@example.com");
        let grants = verified.request.warrant_grants.as_deref().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].aud, "sbo+raw://avail:turing:506/");
        assert!(grants[0]
            .scopes
            .as_deref()
            .unwrap()
            .contains(&"as:dan@example.com".to_string()));
    }

    #[test]
    fn assembled_write_round_trips_and_carries_the_envelope() {
        let (_idp, poster, cert) = setup();
        let warrant_jws = "warrant.jws.placeholder";
        let wire_bytes = assemble_agent_write(
            &poster,
            &cert,
            warrant_jws,
            "onchain:/sys/dnssec/mingo.place",
            WriteSpec {
                action: Action::Post,
                path: "/communities/hub/spaces/general/",
                id: "note-1",
                schema: "post.v1",
                content_type: "application/json",
                payload: b"{\"title\":\"hi\"}".to_vec(),
                owner: "dan@example.com",
                hlc: Some("123.0"),
                prev: None,
            },
        )
        .unwrap();

        // Signed by the poster key, envelope survives serialize → parse, and
        // the on-chain effective author resolves to the delegating user.
        let msg = wire::parse(&wire_bytes).expect("wire parses");
        let poster_sbo_pub = SigningKey::from_bytes(poster.secret_bytes()).public_key();
        assert_eq!(msg.signing_key, poster_sbo_pub);
        assert_eq!(
            msg.owner.as_ref().map(|o| o.as_str()),
            Some("dan@example.com")
        );
        assert_eq!(msg.auth_cert.as_deref(), Some(cert.encoded()));
        assert_eq!(msg.auth_warrant.as_deref(), Some(warrant_jws));
        assert_eq!(
            msg.auth_evidence.as_deref(),
            Some("onchain:/sys/dnssec/mingo.place")
        );
        // Re-signing the parsed message with the poster key reproduces the
        // exact wire — proof the bytes we emit are what the key actually
        // signed (sbo-core's own tests cover the verifier side).
        let mut resigned = msg.clone();
        resigned.sign(&SigningKey::from_bytes(poster.secret_bytes()));
        assert_eq!(
            wire::serialize(&resigned),
            wire_bytes,
            "poster signature is stable"
        );
    }
}
