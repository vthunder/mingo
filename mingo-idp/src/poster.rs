//! The **mingo-poster** server-side signer, rebuilt on the browserid
//! holder-authorization model (agent/D phase): mingo signs SBO objects on a
//! consenting user's behalf so posting works with no client-side signing
//! popups (mobile Safari).
//!
//! Under the holder model the poster is an **as-you service**: it holds the
//! user's identity ITSELF — writes stay owned by and attributed to the user —
//! isolated by a broker-assigned holder in the user's `services` namespace.
//! There is no separate `mingo-poster@` identity and no `as:` scope; the
//! warrant's identifier IS the user, and its `<id>` matcher confines the grant
//! to this one service's holder.
//!
//! Enable = one merged provisioning request at the broker (one URL, one
//! approval, one pickup): mingo generates a per-user device keypair, POSTs
//! `/agent-provision/request` (no handle → as-you; namespace `services`; one
//! grant at the mingo SBO db), and hands back the verification URL. The user
//! approves once on their broker account page — which assigns the holder,
//! obtains the PRIMARY-signed device cert via the device-authorize hop (for
//! `@mingo.place` identities; broker-signed for external emails), and signs
//! the warrant with their config cert. `/poster/poll` picks up device cert +
//! `warrant~config_cert` together and stores them.
//!
//! Submit = mint an access cert from the credential's IdP (`DeviceAgent`),
//! sign the SBO envelope with the SAME access key (envelope-key binding), and
//! forward the wire to the daemon. browserid types and sbo types never meet at
//! a type boundary — only encoded strings cross into the [`Message`].

use std::time::Duration as StdDuration;

use anyhow::Result;
use axum::extract::State;
use axum::Json;
use base64::Engine as _;
use browserid_agent::{DeviceAgent, DeviceCredential};
use browserid_core::device::{DeviceCert, Warrant};
use browserid_core::KeyPair;
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::error::AppError;
use crate::routes::{require_session, Shared};
use crate::store::Account;

/// The warrant scopes mingo requests for a user: post (and owner-delete) on
/// their behalf, bounded to mingo content paths and schemas. Scopes are opaque
/// to the registrar — it renders and copies them; the daemon enforces them
/// (`sbo_core::authorize`). No `as:` scope: under the holder model the warrant
/// identifier IS the user, so attribution lands on them directly.
pub fn default_scopes(user_email: &str) -> Vec<String> {
    vec![
        "action:post".into(),
        "action:delete".into(),
        "schema:post.v1".into(),
        "schema:comment.v1".into(),
        "schema:reaction.v1".into(),
        "schema:attestation.v1".into(),
        "path:/communities/**".into(),
        format!("path:/u/{user_email}/**"),
    ]
}

/// The public identity a user's mingo posts attribute to: their claimed
/// `<handle>@<domain>` pseudonym when they have one, else their external
/// email. This is the write's owner AND the warrant's identifier, so it MUST
/// match the identity the SPA authors as.
fn public_identity(account: &Account, domain: &str) -> String {
    match &account.handle {
        Some(h) => format!("{h}@{domain}"),
        None => account.external_email.clone(),
    }
}

/// `scheme://host` for a domain — https, except localhost/127.* (dev).
pub(crate) fn origin_for(domain: &str) -> String {
    if domain.starts_with("localhost") || domain.starts_with("127.") {
        format!("http://{domain}")
    } else {
        format!("https://{domain}")
    }
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

/// Like [`post_json`] but returns `(status, body)` without treating a non-2xx
/// as an error — the caller decides. The poll path uses this so the broker's
/// 429 "polling too fast" throttle reads as "keep waiting", not a hard failure.
async fn post_json_raw(
    url: String,
    body: serde_json::Value,
) -> Result<(u16, serde_json::Value), AppError> {
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
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        let val = serde_json::from_str(&text).unwrap_or(serde_json::json!({ "raw": text }));
        Ok((status, val))
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
/// margin`, refreshing it server-side when it isn't. An attributed write
/// verifies only if the presentation issuer has a fresh on-chain proof, and in
/// server-side mode no browser is posting them. The refresh is a key-rooted,
/// self-authorizing write, so a throwaway key signs it. **Fail-closed**: if we
/// can't confirm freshness, error out rather than submit a doomed write.
async fn ensure_dnssec_fresh(daemon_url: &str, domain: &str) -> Result<(), AppError> {
    let now = chrono::Utc::now().timestamp();
    let info = get_dnssec(daemon_url, domain, now).await.map_err(|e| {
        AppError::Internal(format!(
            "could not confirm the DNSSEC attribution proof for '{domain}' is fresh \
             (required before mingo can post on your behalf) — please retry: {e}"
        ))
    })?;
    let proof_b64 = match (info.needs_refresh, info.proof_b64) {
        (false, _) => return Ok(()),
        (true, Some(p)) => p,
        (true, None) => {
            return Err(AppError::Internal(format!(
                "the DNSSEC attribution proof for '{domain}' is stale and could not be \
                 refreshed (required before mingo can post on your behalf) — please retry"
            )));
        }
    };
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof_b64.trim())
        .map_err(|e| AppError::Internal(format!("decode dnssec proof for {domain}: {e}")))?;
    let ephemeral = SigningKey::generate();
    let wire = sbo_core::presets::set_dnssec(&ephemeral, domain, &proof);
    submit_wire(daemon_url.to_string(), wire).await.map_err(|e| {
        AppError::Internal(format!(
            "could not refresh the DNSSEC attribution proof for '{domain}' \
             (required before mingo can post on your behalf) — please retry: {e}"
        ))
    })?;
    tracing::info!(domain, "refreshed on-chain /sys/dnssec proof (server-side)");
    Ok(())
}

/// Minimal query-component percent-encoding.
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

// ===========================================================================
// HTTP surface (mingo-web talks to these; all session-gated, same-origin)
// ===========================================================================

#[derive(Deserialize)]
struct ProvisionRequestResp {
    code: String,
    verification_uri_complete: String,
    #[serde(default)]
    expires_in: i64,
}

/// POST /poster/enable — start the merged provisioning request at the broker:
/// generate a per-user device keypair, ask for the user's own identity (as-you,
/// `services` namespace) plus one warrant grant at the mingo SBO db, and hand
/// back the one approval URL. On return the client polls `/poster/poll`.
///
/// Idempotent while a request is outstanding: reuse the live pending request
/// (same identity) instead of parking a fresh one per reopened dialog.
pub async fn enable(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let account = st
        .store
        .get_account(account_id)?
        .ok_or(AppError::NotAuthenticated)?;
    let domain = st.config.domain.clone();
    let user_email = public_identity(&account, &domain);
    let broker_origin = origin_for(&st.config.broker_domain);

    let now = chrono::Utc::now().timestamp();
    if let Some(p) = st.store.get_poster_pending(account_id)? {
        if let (Some(uri), Some(_)) = (p.verification_uri, p.device_seed) {
            if p.user_email == user_email && p.expires_at > now + 60 {
                return Ok(Json(serde_json::json!({ "verification_uri": uri })));
            }
        }
    }

    let device_key = KeyPair::generate();
    let resp: ProvisionRequestResp = post_json(
        format!("{broker_origin}/agent-provision/request"),
        serde_json::json!({
            "provisioning_pubkey": {
                "algorithm": "Ed25519",
                "publicKey": device_key.public_key().to_base64(),
            },
            // No requested_handles: an as-you service — the poster holds the
            // user's identity itself, isolated by its services holder.
            "namespace": "services",
            "grants": [{
                "audience": st.config.sbo_db_audience,
                "scopes": default_scopes(&user_email),
            }],
            "label": format!("mingo poster ({user_email})"),
        }),
    )
    .await?;
    let seed_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_key.secret_bytes());
    st.store.set_poster_pending(
        account_id,
        &user_email,
        &resp.code,
        &resp.verification_uri_complete,
        now + resp.expires_in,
        &seed_b64,
    )?;
    Ok(Json(
        serde_json::json!({ "verification_uri": resp.verification_uri_complete }),
    ))
}

/// POST /poster/poll — pick up the approved credential (or report progress).
/// One pickup delivers BOTH the device cert and the warrant tail; on approval
/// they're stored and subsequent posts go server-side.
pub async fn poll(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let Some(pending) = st.store.get_poster_pending(account_id)? else {
        return Ok(Json(serde_json::json!({ "status": "none" })));
    };
    let Some(seed_b64) = pending.device_seed.clone() else {
        // Classic-era pending row — not resumable on the device model.
        st.store.clear_poster_pending(account_id)?;
        return Ok(Json(serde_json::json!({ "status": "expired" })));
    };
    let broker_origin = origin_for(&st.config.broker_domain);
    let (http_status, body) = post_json_raw(
        format!("{broker_origin}/agent-provision/poll"),
        serde_json::json!({ "code": pending.code }),
    )
    .await?;
    // The broker throttles per-code polls (429 "polling too fast") — still pending.
    if http_status == 429 {
        return Ok(Json(serde_json::json!({ "status": "pending" })));
    }
    let status = body["status"].as_str().unwrap_or_default().to_string();
    match status.as_str() {
        "pending" => Ok(Json(serde_json::json!({ "status": "pending" }))),
        "completed" => {
            let device_cert_jws = body["credential"]["device_cert"]
                .as_str()
                .ok_or_else(|| AppError::Internal("completed poll carried no device cert".into()))?;
            let idp = body["credential"]["idp"]
                .as_str()
                .ok_or_else(|| AppError::Internal("completed poll carried no idp".into()))?;
            let identity = body["credential"]["identity"].as_str().unwrap_or_default();
            if !identity.eq_ignore_ascii_case(&pending.user_email) {
                st.store.clear_poster_pending(account_id)?;
                return Err(AppError::Internal(format!(
                    "approved identity '{identity}' does not match the requested '{}'",
                    pending.user_email
                )));
            }
            let tail = body["grants"][0]["warrant"]
                .as_str()
                .ok_or_else(|| AppError::Internal("completed poll carried no warrant".into()))?;
            let device_cert = DeviceCert::parse(device_cert_jws)
                .map_err(|e| AppError::Internal(format!("broker returned a bad device cert: {e}")))?;
            let warrant_jws = tail.split('~').next().unwrap_or_default();
            let warrant = Warrant::parse(warrant_jws)
                .map_err(|e| AppError::Internal(format!("broker returned a bad warrant: {e}")))?;
            let expires_at = warrant.claims().exp.min(device_cert.claims().exp);
            st.store.set_poster_warrant(
                account_id,
                &pending.user_email,
                tail,
                &warrant.claims().audience,
                expires_at,
                &seed_b64,
                device_cert_jws,
                device_cert.holder().as_str(),
                idp,
            )?;
            st.store.clear_poster_pending(account_id)?;
            tracing::info!(user = %pending.user_email, holder = %device_cert.holder().as_str(),
                "mingo-poster enabled (device model)");
            Ok(Json(serde_json::json!({ "status": "approved" })))
        }
        other => {
            // denied / expired / failed / gone — drop the dead code.
            st.store.clear_poster_pending(account_id)?;
            let label = if other.is_empty() { "expired" } else { other };
            Ok(Json(serde_json::json!({ "status": label })))
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
    let enabled = w
        .as_ref()
        .is_some_and(|w| w.expires_at > now && w.device_seed.is_some());
    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "available": true,
        "expires_at": w.map(|w| w.expires_at),
    })))
}

/// POST /poster/disable — forget the stored credential (the user can also
/// revoke the warrant at their broker account page, which cuts it off
/// on-chain; this just stops mingo from using it).
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
    /// Wire action: `post` (default, incl. edit-as-update) or `delete`
    /// (owner-delete). Absent/empty means `post` for back-compat.
    #[serde(default)]
    pub action: Option<String>,
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

/// POST /poster/submit — mingo signs the write on the user's behalf and
/// forwards the wire to the daemon. The stored credential mints a fresh access
/// cert at its IdP; the envelope is signed with the SAME access key the cert
/// certifies (envelope-key binding); the presentation rides `auth_cert`.
/// `auth_evidence` is omitted: the daemon resolves the issuer's `/sys/dnssec`
/// proof on-chain (kept fresh here, fail-closed).
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
            "mingo-poster authorization expired — re-enable".into(),
        ));
    }
    let (Some(seed), Some(cert_jws), Some(idp)) =
        (w.device_seed.clone(), w.device_cert.clone(), w.idp.clone())
    else {
        return Err(AppError::BadRequest(
            "mingo-poster needs re-enabling on the current authorization model".into(),
        ));
    };

    // Assemble the presentation via the headless SDK: mint an access cert at
    // the credential's IdP, get back `access~assertion~warrant~config` plus
    // the access key seed for envelope signing.
    let credential = DeviceCredential {
        device_key: seed,
        agent_device_cert: cert_jws,
        idp,
    };
    let mut agent = DeviceAgent::new(credential)
        .map_err(|e| AppError::Internal(format!("poster credential: {e}")))?;
    let (warrant_jws, config_jws) = w
        .warrant
        .split_once('~')
        .ok_or_else(|| AppError::Internal("stored grant is not warrant~config_cert".into()))?;
    agent
        .add_grant(warrant_jws, config_jws)
        .map_err(|e| AppError::Internal(format!("stored grant: {e}")))?;
    let (presentation, access_seed) = agent
        .assertion_with_access_seed(&w.audience)
        .await
        .map_err(|e| AppError::Internal(format!("access mint: {e}")))?;

    // The attribution proof for the presentation's issuer must be fresh
    // on-chain before the daemon will attribute the write.
    let issuer = DeviceCert::parse(agent_cert_of(&presentation)?)
        .map_err(|e| AppError::Internal(format!("presentation config cert: {e}")))?
        .claims()
        .iss
        .clone();
    ensure_dnssec_fresh(&st.config.daemon_url, &issuer).await?;

    // Only post (incl. edit-as-update) and owner-delete are signable on a
    // user's behalf. Reject anything else rather than silently downgrading.
    let action = match req.action.as_deref() {
        None | Some("") | Some("post") => Action::Post,
        Some("delete") => Action::Delete,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "poster cannot sign action '{other}' (only post or delete)"
            )));
        }
    };
    let hlc = req
        .hlc
        .unwrap_or_else(|| format!("{}.0", chrono::Utc::now().timestamp_millis()));

    let key = SigningKey::from_bytes(&access_seed);
    let payload = req.payload;
    let content_hash = ContentHash::sha256(&payload);
    let mut msg = Message {
        action,
        path: Path::parse(&req.path).map_err(|e| AppError::BadRequest(format!("bad path '{}': {e}", req.path)))?,
        id: Id::new(&req.id).map_err(|e| AppError::BadRequest(format!("bad id '{}': {e}", req.id)))?,
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature::parse(&"0".repeat(128)).expect("valid placeholder signature"),
        content_type: Some(req.content_type.unwrap_or_else(|| "application/json".into())),
        content_hash: Some(content_hash),
        payload: Some(payload),
        owner: Some(Id::new(&w.user_email).map_err(|e| AppError::Internal(format!("bad owner '{}': {e}", w.user_email)))?),
        creator: None,
        content_encoding: None,
        content_schema: Some(req.schema),
        policy_ref: None,
        related: None,
        hlc: Some(hlc),
        prev: req.prev,
        auth_cert: Some(presentation),
        auth_evidence: None,
        auth_warrant: None,
    };
    msg.sign(&key);
    let wire_bytes = wire::serialize(&msg);

    let result = submit_wire(st.config.daemon_url.clone(), wire_bytes).await?;
    Ok(Json(result))
}

/// The 4th `~`-object of a presentation (the config cert) — its `iss` is the
/// presentation's single issuer (verify enforces config.iss == access.iss).
fn agent_cert_of(presentation: &str) -> Result<&str, AppError> {
    presentation
        .split('~')
        .nth(3)
        .ok_or_else(|| AppError::Internal("presentation is not 4 ~-joined objects".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scopes_have_no_as_scope_and_bound_paths() {
        let scopes = default_scopes("dan@mingo.place");
        assert!(scopes.iter().any(|s| s == "action:post"));
        assert!(scopes.iter().any(|s| s == "path:/u/dan@mingo.place/**"));
        // Holder model: attribution lands on the user directly — no `as:`.
        assert!(!scopes.iter().any(|s| s.starts_with("as:")));
    }

    #[test]
    fn presentation_issuer_extraction_takes_the_config_cert() {
        assert_eq!(agent_cert_of("a~b~c~d").unwrap(), "d");
        assert!(agent_cert_of("a~b~c").is_err());
    }
}
