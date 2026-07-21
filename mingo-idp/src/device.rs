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
