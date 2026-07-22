//! Device-cert model endpoints for the mingo.place primary IdP (DC conformance).
//!
//! mingo is an interoperable device-cert IdP: it issues IdP-signed **device
//! certs** and mints short-lived **access certs** headlessly, exactly like the
//! sandmill.org reference IdP (`app/Http/Controllers/BrowserIdController.php`),
//! but reusing the `browserid_core::device` types directly instead of a wire
//! reimplementation. Added ADDITIVELY alongside the legacy `/cert_key` +
//! `/provision/*` surface (which stays).
//!
//! Two endpoints:
//!   * `POST /device_cert` — session-authed **batch** issuance of the two USER
//!     device certs for the session's `<handle>@mingo.place` identity: an
//!     `authentication` device cert (mints access certs) and an `authorization`
//!     **config cert** (signs warrants). Both signed by mingo's IdP key.
//!   * `POST /access/mint` — **headless** (no session; the device cert is the
//!     credential): verify the authentication device cert (mingo sig, unexpired,
//!     purpose, issuer) + the device-signed access request, then mint a 24h
//!     access cert over the fresh access key. This is what the
//!     `browserid_agent::DeviceAgent` SDK calls.
//!
//! The mint COPIES the device cert's opaque `holder` verbatim into the access
//! cert (holder-authorization model), and rejects an access request whose holder
//! disagrees — the requester can never choose a different holder than its device
//! cert carries.

use axum::extract::State;
use axum::Json;
use browserid_core::device::{
    AccessCert, AccessRequest, DeviceCert, Holder, Purpose, ACCESS_CERT_VALIDITY_HOURS,
    DEVICE_CERT_VALIDITY_DAYS,
};
use browserid_core::PublicKey;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::error::AppError;
use crate::routes::{require_session, PubKeyJson, Shared};

/// The two device pubkeys the client generated: the device (authentication) key
/// and the config (authorization) key. Both are certified in one batch.
#[derive(Deserialize)]
pub struct DeviceCertReq {
    pub device_pubkey: PubKeyJson,
    pub config_pubkey: PubKeyJson,
    /// The client broker's stable per-browser holder — opaque passthrough,
    /// signed verbatim. Optional (backward-compat): absent → derive one locally.
    #[serde(default)]
    pub holder: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceCertResp {
    pub success: bool,
    /// The `authentication` device cert (mints access certs).
    pub device_cert: String,
    /// The `authorization` config cert (signs warrants).
    pub config_cert: String,
    /// The `<handle>@mingo.place` identity both certs authorize.
    pub identity: String,
}

/// Derive a stable, opaque holder id for a device slot from its device key.
/// Deterministic (same key → same holder, so a re-issue keeps the slot), unique
/// per device, and dotted so the browser can form a `<prefix>.*` login matcher.
fn holder_for_device(device_pub: &PublicKey) -> String {
    let clean: String = device_pub
        .to_base64()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    // clean is a 43-char ed25519 base64; slices are safe, but guard anyway.
    let pre = &clean[..6.min(clean.len())];
    let id = &clean[6.min(clean.len())..16.min(clean.len())];
    format!("br{pre}.{id}")
}

fn parse_pubkey(p: &PubKeyJson) -> Result<PublicKey, AppError> {
    if p.algorithm != "Ed25519" {
        return Err(AppError::BadRequest(format!(
            "unsupported algorithm: {}",
            p.algorithm
        )));
    }
    PublicKey::from_base64(&p.public_key)
        .map_err(|e| AppError::BadRequest(format!("invalid public key: {e}")))
}

// --------------------------------------------------------------------------
// POST /device_cert  (session-authed)  { device_pubkey, config_pubkey }
//   -> { success, device_cert, config_cert, identity }
//
// Issues the two USER device certs for the session's claimed handle identity.
// A handle must be claimed first (like /cert_key) — mingo only issues for the
// `<handle>@mingo.place` pseudonym it is authoritative for.
// --------------------------------------------------------------------------
pub async fn device_cert(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<DeviceCertReq>,
) -> Result<Json<DeviceCertResp>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let handle = st
        .store
        .get_account(account_id)?
        .and_then(|a| a.handle)
        .ok_or_else(|| AppError::BadRequest("claim a handle before issuing device certs".into()))?;
    let identity = format!("{}@{}", handle, st.config.domain);

    let device_pub = parse_pubkey(&req.device_pubkey)?;
    let config_pub = parse_pubkey(&req.config_pubkey)?;
    let validity = chrono::Duration::days(DEVICE_CERT_VALIDITY_DAYS);

    // One opaque holder per device slot (holder-authorization model), carried by
    // BOTH the authentication and authorization cert. The client broker supplies
    // this browser's stable holder (reused across identities), which mingo treats
    // as OPAQUE PASSTHROUGH and signs verbatim. Absent → derive one locally from
    // the device key (stable per slot; older clients / backward-compat). Dotted
    // `<prefix>.<id>` lets the browser derive `<prefix>.*` login-warrant matchers.
    let holder_str = match req.holder.as_deref() {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => holder_for_device(&device_pub),
    };
    let holder = Holder::new(holder_str)
        .map_err(|e| AppError::Internal(format!("holder: {e}")))?;

    let device_cert = DeviceCert::create(
        &st.config.domain,
        &device_pub,
        Purpose::Authentication,
        holder.clone(),
        vec![identity.clone()],
        validity,
        &st.keypair,
        None,
    )
    .map_err(|e| AppError::Internal(format!("device cert: {e}")))?;

    // The config (authorization) cert also covers the handle's `+tag`
    // sub-addresses so it can sign warrants for plus-named agent identities
    // (browserid design doc, Stage 3).
    let config_cert = DeviceCert::create(
        &st.config.domain,
        &config_pub,
        Purpose::Authorization,
        holder.clone(),
        vec![identity.clone(), format!("{}+*@{}", handle, st.config.domain)],
        validity,
        &st.keypair,
        None,
    )
    .map_err(|e| AppError::Internal(format!("config cert: {e}")))?;

    Ok(Json(DeviceCertResp {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        config_cert: config_cert.encoded().to_string(),
        identity,
    }))
}

// --------------------------------------------------------------------------
// POST /agent_device_cert  (session-authed)
//   { agent_pubkey, agent_email, holder } -> { success, device_cert, identity }
//
// Agent-mode issuance (merged one-approval provisioning, agent/D phase): the
// broker's approval page hops here (device-authorize popup, agent mode) so the
// PRIMARY signs the agent's authentication cert — required because a
// presentation's config cert and access cert must share one issuer, and the
// warrant for a `<handle>+<tag>@mingo.place` agent is signed by the
// mingo-issued config cert. The holder is broker-assigned (opaque passthrough,
// required — an agent's holder is never minted here), and the agent identity
// must sub-address the session's own handle.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct AgentDeviceCertReq {
    pub agent_pubkey: PubKeyJson,
    /// Full agent identity `<handle>+<tag>@<domain>` — must sub-address the
    /// session's handle.
    pub agent_email: String,
    /// The broker-assigned holder (opaque passthrough, signed verbatim).
    pub holder: String,
}

#[derive(Serialize)]
pub struct AgentDeviceCertResp {
    pub success: bool,
    pub device_cert: String,
    pub identity: String,
}

pub async fn agent_device_cert(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<AgentDeviceCertReq>,
) -> Result<Json<AgentDeviceCertResp>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let handle = st
        .store
        .get_account(account_id)?
        .and_then(|a| a.handle)
        .ok_or_else(|| AppError::BadRequest("claim a handle before issuing agent certs".into()))?;

    let agent_email = req.agent_email.trim().to_lowercase();
    let (local, domain) = agent_email
        .split_once('@')
        .ok_or_else(|| AppError::BadRequest("agent_email must be an email".into()))?;
    if domain != st.config.domain {
        return Err(AppError::BadRequest(format!(
            "agent_email must be @{}",
            st.config.domain
        )));
    }
    // The agent identity is either the session's handle ITSELF (an as-you
    // service: acts as the user, isolated by its holder) or a `+tag`
    // sub-address of it (a named agent; stripping the tag yields the owner).
    let own = handle.to_lowercase();
    let prefix = format!("{own}+");
    let is_self = local == own;
    let is_subaddress = local.starts_with(&prefix) && local.len() > prefix.len();
    if !is_self && !is_subaddress {
        return Err(AppError::Forbidden);
    }
    // Same charset/reservation rules as handle claiming — a signed cert must
    // never carry an un-normalizable local-part.
    if crate::routes::normalize_agent_name(local)? != local {
        return Err(AppError::BadRequest("agent name is not normalized".into()));
    }

    let agent_pub = parse_pubkey(&req.agent_pubkey)?;
    if req.holder.trim().is_empty() {
        return Err(AppError::BadRequest("holder required".into()));
    }
    let holder = Holder::new(req.holder.trim().to_string())
        .map_err(|e| AppError::BadRequest(format!("holder: {e}")))?;

    let device_cert = DeviceCert::create(
        &st.config.domain,
        &agent_pub,
        Purpose::Authentication,
        holder,
        vec![agent_email.clone()],
        chrono::Duration::days(DEVICE_CERT_VALIDITY_DAYS),
        &st.keypair,
        None,
    )
    .map_err(|e| AppError::Internal(format!("agent device cert: {e}")))?;

    Ok(Json(AgentDeviceCertResp {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        identity: agent_email,
    }))
}

// --------------------------------------------------------------------------
// POST /access/mint  (headless)  { device_cert, access_request }
//   -> { success, access_cert }
//
// The device cert is the credential; no session. Mirrors sandmill's
// `accessCert`, and matches what `browserid_agent::DeviceAgent::mint` expects
// (`success` + `access_cert`).
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct AccessMintReq {
    pub device_cert: String,
    pub access_request: String,
}

#[derive(Serialize)]
pub struct AccessMintResp {
    pub success: bool,
    pub access_cert: String,
}

pub async fn access_mint(
    State(st): State<Shared>,
    Json(req): Json<AccessMintReq>,
) -> Result<Json<AccessMintResp>, AppError> {
    let domain = &st.config.domain;

    // 1. The device cert must be signed by THIS IdP, be an authentication cert,
    //    carry our issuer, and be unexpired.
    let device_cert = DeviceCert::parse(&req.device_cert)
        .map_err(|e| AppError::BadRequest(format!("device cert: {e}")))?;
    device_cert
        .verify(&st.keypair.public_key())
        .map_err(|_| AppError::BadRequest("device cert: bad signature".into()))?;
    if device_cert.iss() != domain {
        return Err(AppError::BadRequest("device cert: wrong issuer".into()));
    }
    if device_cert.purpose() != Purpose::Authentication {
        return Err(AppError::BadRequest(
            "device cert: not an authentication cert".into(),
        ));
    }
    if device_cert.is_expired() {
        return Err(AppError::BadRequest("device cert: expired".into()));
    }

    // 2. The access request must be signed by the device key.
    let access_request = AccessRequest::parse(&req.access_request)
        .map_err(|e| AppError::BadRequest(format!("access request: {e}")))?;
    access_request
        .verify(device_cert.public_key())
        .map_err(|_| AppError::BadRequest("access request: bad signature".into()))?;
    if access_request.is_expired() {
        return Err(AppError::BadRequest("access request: expired".into()));
    }
    let ar = access_request.claims();
    if ar.domain != *domain {
        return Err(AppError::BadRequest("access request: wrong domain".into()));
    }

    // 3. The identity must be authorized by the device cert; the access
    //    request's holder must match the device cert's (the mint copies it).
    if !device_cert.authorizes_identity(&ar.identity) {
        return Err(AppError::Forbidden);
    }
    if ar.holder != *device_cert.holder() {
        return Err(AppError::BadRequest("access request: holder mismatch".into()));
    }

    // 4. Mint the access cert over the fresh access key, copying the device
    //    cert's holder verbatim (isolation guarantee).
    let access_cert = AccessCert::create(
        domain,
        &ar.identity,
        device_cert.holder().clone(),
        &ar.access_key,
        chrono::Duration::hours(ACCESS_CERT_VALIDITY_HOURS),
        &st.keypair,
        None,
    )
    .map_err(|e| AppError::Internal(format!("access cert: {e}")))?;

    Ok(Json(AccessMintResp {
        success: true,
        access_cert: access_cert.encoded().to_string(),
    }))
}
