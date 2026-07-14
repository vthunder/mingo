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

use std::time::Duration as StdDuration;

use anyhow::{anyhow, Result};
use axum::extract::State;
use axum::Json;
use base64::Engine as _;
use browserid_core::provisioning::{ExternalWarrantRequest, ProvisioningRequest, WarrantGrant};
use browserid_core::{Certificate, KeyPair, PublicKey, Warrant};
use chrono::Duration;
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::error::AppError;
use crate::routes::{require_session, Shared};
use crate::store::Account;

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
/// key and carrying `auth_cert` (the per-user agent cert) and `auth_warrant`
/// (the user-signed warrant JWS). `auth_evidence` is the DNSSEC proof
/// reference; pass `None` to let the daemon resolve both issuers' proofs from
/// their on-chain `/sys/dnssec/<issuer>` records (the same pattern the
/// client-signed path uses — it omits inline evidence and keeps the on-chain
/// proof fresh instead). The result is what mingo POSTs to `<daemon>/v1/submit`.
pub fn assemble_agent_write(
    poster_key: &KeyPair,
    poster_cert: &Certificate,
    warrant_jws: &str,
    auth_evidence: Option<&str>,
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
        auth_evidence: auth_evidence.map(str::to_string),
        auth_warrant: Some(warrant_jws.to_string()),
    };
    msg.sign(&key);
    Ok(wire::serialize(&msg))
}

// ===========================================================================
// HTTP surface (mingo-web talks to these; all session-gated, same-origin)
// ===========================================================================

/// The public identity a user's mingo posts attribute to: their claimed
/// `<handle>@<domain>` pseudonym when they chose one, else their external
/// email. This is the warrant's delegator and the write's owner.
fn public_identity(account: &Account, domain: &str) -> String {
    match (account.identity_mode.as_deref(), &account.handle) {
        (Some("handle"), Some(h)) => format!("{h}@{domain}"),
        _ => account.external_email.clone(),
    }
}

/// `scheme://host` for a domain — https, except localhost/127.* (dev).
fn origin_for(domain: &str) -> String {
    if domain.starts_with("localhost") || domain.starts_with("127.") {
        format!("http://{domain}")
    } else {
        format!("https://{domain}")
    }
}

#[derive(Deserialize)]
struct WarrantRequestResp {
    code: String,
    verification_uri: String,
}

#[derive(Deserialize)]
struct PollResp {
    status: String,
    #[serde(default)]
    warrants: Option<Vec<String>>,
    #[serde(default)]
    warrant: Option<String>,
}

/// POST a JSON body to `url` and decode the JSON response (blocking reqwest on
/// the blocking pool, matching the rest of mingo-idp).
async fn post_json<T: DeserializeOwned + Send + 'static>(
    url: String,
    body: serde_json::Value,
) -> Result<T, AppError> {
    tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(StdDuration::from_secs(15))
            .build()
            .map_err(|e| AppError::Internal(format!("http client: {e}")))?;
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| AppError::Internal(format!("POST {url}: {e}")))?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::BadRequest(format!("{url} -> {status}: {text}")));
        }
        serde_json::from_str(&text)
            .map_err(|e| AppError::Internal(format!("decode {url}: {e}; body={text}")))
    })
    .await
    .map_err(|e| AppError::Internal(format!("http task: {e}")))?
}

/// Headroom over `needed_by` when checking DNSSEC-proof freshness — covers
/// inclusion latency + clock skew (mirrors the client's `MARGIN`).
const DNSSEC_MARGIN_SECS: i64 = 3600;

#[derive(Deserialize)]
struct DnssecInfo {
    #[serde(default)]
    needs_refresh: bool,
    /// The freshly-captured RFC 9102 proof (base64url), present only when a
    /// refresh is needed.
    #[serde(default)]
    proof_b64: Option<String>,
}

/// GET the daemon's freshness verdict for `/sys/dnssec/<domain>` (and, when
/// stale, the fresh proof it captured for us).
async fn get_dnssec(
    daemon_url: &str,
    domain: &str,
    needed_by: i64,
) -> Result<DnssecInfo, AppError> {
    let url = format!(
        "{daemon_url}/v1/dnssec?domain={}&needed_by={needed_by}&margin={DNSSEC_MARGIN_SECS}",
        urlencoding(domain)
    );
    tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(StdDuration::from_secs(20))
            .build()
            .map_err(|e| AppError::Internal(format!("http client: {e}")))?;
        let resp = client
            .get(&url)
            .send()
            .map_err(|e| AppError::Internal(format!("GET {url}: {e}")))?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::Internal(format!("dnssec check {status}: {text}")));
        }
        serde_json::from_str(&text)
            .map_err(|e| AppError::Internal(format!("decode dnssec: {e}; body={text}")))
    })
    .await
    .map_err(|e| AppError::Internal(format!("dnssec task: {e}")))?
}

/// Ensure `/sys/dnssec/<domain>`'s on-chain proof is valid through `now +
/// margin`, refreshing it server-side when it isn't. This is the server-side
/// counterpart of the client's `ensureDnssecFresh`: an agent write attributes
/// only if BOTH the agent's issuer and the delegator's issuer have a fresh
/// on-chain proof, and in server-side mode no browser is posting them. The
/// refresh is a **key-rooted, self-authorizing** write (the RFC 9102 proof
/// payload proves its own authority — see `sbo_core::presets::set_dnssec`), so
/// a throwaway key signs it; no identity is implied. Best-effort: on a check
/// failure we proceed and let the daemon be authoritative at submit time.
async fn ensure_dnssec_fresh(daemon_url: &str, domain: &str) -> Result<(), AppError> {
    let now = chrono::Utc::now().timestamp();
    let info = match get_dnssec(daemon_url, domain, now).await {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(domain, error = %e, "dnssec freshness check failed; proceeding");
            return Ok(());
        }
    };
    let proof_b64 = match (info.needs_refresh, info.proof_b64) {
        (true, Some(p)) => p,
        _ => return Ok(()), // already fresh (or the daemon gave us nothing to post)
    };
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof_b64.trim())
        .map_err(|e| AppError::Internal(format!("decode dnssec proof for {domain}: {e}")))?;
    let ephemeral = SigningKey::generate();
    let wire = sbo_core::presets::set_dnssec(&ephemeral, domain, &proof);
    submit_wire(daemon_url.to_string(), wire).await?;
    tracing::info!(domain, "refreshed on-chain /sys/dnssec proof (server-side)");
    Ok(())
}

/// Minimal query-component percent-encoding (domains are `[a-z0-9.-]`, but be
/// safe against anything unexpected in the issuer string).
fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// POST raw SBO wire bytes to the daemon's `/v1/submit`.
async fn submit_wire(daemon_url: String, wire: Vec<u8>) -> Result<serde_json::Value, AppError> {
    let url = format!("{daemon_url}/v1/submit");
    tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(StdDuration::from_secs(30))
            .build()
            .map_err(|e| AppError::Internal(format!("http client: {e}")))?;
        let resp = client
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(wire)
            .send()
            .map_err(|e| AppError::Internal(format!("daemon submit: {e}")))?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::BadRequest(format!(
                "daemon submit {status}: {text}"
            )));
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::json!({ "raw": text })))
    })
    .await
    .map_err(|e| AppError::Internal(format!("submit task: {e}")))?
}

#[derive(Serialize)]
pub struct EnableResp {
    /// The registrar consent page to redirect the user to; on return they poll.
    pub verification_uri: String,
}

/// POST /poster/enable — start delegation: mint the per-user agent cert, build
/// the external warrant request, raise it at the user's registrar, and hand
/// back the consent URL to redirect to. On return the client polls `/poster/poll`.
pub async fn enable(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<EnableResp>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let account = st
        .store
        .get_account(account_id)?
        .ok_or(AppError::NotAuthenticated)?;
    let domain = st.config.domain.clone();
    let user_email = public_identity(&account, &domain);
    let registrar_origin = origin_for(&st.config.broker_domain);

    let cert = mint_poster_cert(
        &st.keypair,
        &domain,
        &st.poster_key.public_key(),
        &user_email,
        Some(registrar_origin.clone()),
    )?;
    let bundle = external_warrant_request(
        &st.poster_key,
        &cert,
        &st.config.broker_domain,
        &user_email,
        &st.config.sbo_db_audience,
        default_scopes(&user_email),
    )?;

    let resp: WarrantRequestResp = post_json(
        format!("{registrar_origin}/warrant/request"),
        serde_json::json!({ "request_bundle": bundle }),
    )
    .await?;
    st.store
        .set_poster_pending(account_id, &user_email, &resp.code)?;
    Ok(Json(EnableResp {
        verification_uri: resp.verification_uri,
    }))
}

/// POST /poster/poll — pick up the approved warrant (or report progress). On
/// approval the warrant is stored; subsequent posts go server-side.
pub async fn poll(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let (user_email, code) = match st.store.get_poster_pending(account_id)? {
        Some(x) => x,
        None => return Ok(Json(serde_json::json!({ "status": "none" }))),
    };
    let registrar_origin = origin_for(&st.config.broker_domain);
    let resp: PollResp = post_json(
        format!("{registrar_origin}/warrant/poll"),
        serde_json::json!({ "code": code }),
    )
    .await?;

    match resp.status.as_str() {
        "approved" => {
            let jws = resp
                .warrants
                .and_then(|w| w.into_iter().next())
                .or(resp.warrant)
                .ok_or_else(|| AppError::Internal("approved poll carried no warrant".into()))?;
            let warrant = Warrant::parse(&jws).map_err(|e| {
                AppError::Internal(format!("registrar returned a bad warrant: {e}"))
            })?;
            st.store.set_poster_warrant(
                account_id,
                &user_email,
                &jws,
                warrant.audience(),
                warrant.claims().exp,
            )?;
            st.store.clear_poster_pending(account_id)?;
            Ok(Json(serde_json::json!({ "status": "approved" })))
        }
        "pending" => Ok(Json(serde_json::json!({ "status": "pending" }))),
        other => {
            // denied / expired / gone — drop the dead code.
            st.store.clear_poster_pending(account_id)?;
            Ok(Json(serde_json::json!({ "status": other })))
        }
    }
}

/// GET /poster/status — whether mingo may currently post for this account.
pub async fn status(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let now = chrono::Utc::now().timestamp();
    let w = st.store.get_poster_warrant(account_id)?;
    let enabled = w.as_ref().is_some_and(|w| w.expires_at > now);
    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "expires_at": w.map(|w| w.expires_at),
    })))
}

/// POST /poster/disable — forget the stored warrant (the user can also revoke
/// it at the registrar, which cuts it off on-chain; this just stops mingo from
/// using it).
pub async fn disable(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    st.store.delete_poster_warrant(account_id)?;
    st.store.clear_poster_pending(account_id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct SubmitReq {
    pub path: String,
    pub id: String,
    pub schema: String,
    #[serde(default)]
    pub content_type: Option<String>,
    /// The object body as a byte array (same shape the client builds).
    pub payload: Vec<u8>,
    #[serde(default)]
    pub hlc: Option<String>,
    #[serde(default)]
    pub prev: Option<String>,
}

/// POST /poster/submit — mingo signs the write on the user's behalf (agent
/// cert + stored warrant) and forwards the wire to the daemon. No client-side
/// signing, so it works identically on mobile. `auth_evidence` is omitted: the
/// daemon resolves both issuers' `/sys/dnssec` proofs on-chain (same as the
/// client path).
pub async fn submit(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<SubmitReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let w = st
        .store
        .get_poster_warrant(account_id)?
        .ok_or_else(|| AppError::BadRequest("mingo-poster is not enabled".into()))?;
    let now = chrono::Utc::now().timestamp();
    if w.expires_at <= now {
        return Err(AppError::BadRequest(
            "mingo-poster warrant expired — re-enable".into(),
        ));
    }
    let domain = st.config.domain.clone();
    let registrar_origin = origin_for(&st.config.broker_domain);
    let cert = mint_poster_cert(
        &st.keypair,
        &domain,
        &st.poster_key.public_key(),
        &w.user_email,
        Some(registrar_origin),
    )?;

    // An agent write attributes only if BOTH the agent's issuer (this IdP) and
    // the delegator's issuer have a fresh on-chain /sys/dnssec proof. The
    // client keeps these fresh on its own writes; in server-side mode we do it
    // here. The delegator's issuer is the warrant's embedded parent cert's
    // `iss` (the email's own domain for a primary, the broker for a fallback).
    let mut issuers = vec![domain.clone()];
    if let Ok(warrant) = Warrant::parse(&w.warrant) {
        if let Ok(parent) = Certificate::parse(&warrant.claims().parent_cert) {
            let iss = parent.issuer().to_string();
            if !issuers.iter().any(|d| d.eq_ignore_ascii_case(&iss)) {
                issuers.push(iss);
            }
        }
    }
    for issuer in &issuers {
        ensure_dnssec_fresh(&st.config.daemon_url, issuer).await?;
    }

    let hlc = req
        .hlc
        .unwrap_or_else(|| format!("{}.0", chrono::Utc::now().timestamp_millis()));
    let wire_bytes = assemble_agent_write(
        &st.poster_key,
        &cert,
        &w.warrant,
        None,
        WriteSpec {
            action: Action::Post,
            path: &req.path,
            id: &req.id,
            schema: &req.schema,
            content_type: req.content_type.as_deref().unwrap_or("application/json"),
            payload: req.payload,
            owner: &w.user_email,
            hlc: Some(&hlc),
            prev: req.prev.as_deref(),
        },
    )?;

    let result = submit_wire(st.config.daemon_url.clone(), wire_bytes).await?;
    Ok(Json(result))
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
            Some("onchain:/sys/dnssec/mingo.place"),
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
