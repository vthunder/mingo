//! HTTP handlers for the mingo.place primary IdP.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::keys::{KeyPair, PublicKey};
use browserid_core::{discovery::SupportDocument, Certificate};
use serde::{Deserialize, Serialize};
use tower_cookies::cookie::{time::Duration as CookieDuration, SameSite};
use tower_cookies::{Cookie, Cookies};

use crate::config::Config;
use crate::error::AppError;
use crate::store::Store;
use crate::verify::verify_external_assertion;

pub const SESSION_COOKIE: &str = "mingo_session";

pub struct AppState {
    pub keypair: KeyPair,
    pub store: Store,
    pub config: Config,
}

pub type Shared = Arc<AppState>;

// --------------------------------------------------------------------------
// GET /.well-known/browserid
// --------------------------------------------------------------------------
pub async fn well_known(State(st): State<Shared>) -> Json<SupportDocument> {
    let doc = SupportDocument::new(st.keypair.public_key())
        .with_authentication("/auth")
        .with_provisioning("/provision");
    Json(doc)
}

// --------------------------------------------------------------------------
// POST /session/from-assertion  { assertion }  ->  { handle }
// Verifies the broker's assertion for the user's external identity and sets a
// mingo.place session cookie keyed by that external email.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct SessionReq {
    pub assertion: String,
}

#[derive(Serialize)]
pub struct SessionResp {
    pub handle: Option<String>,
    pub csrf: String,
}

pub async fn session_from_assertion(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<SessionReq>,
) -> Result<Json<SessionResp>, AppError> {
    let audience = st.config.app_origin.clone();
    let broker = st.config.broker_domain.clone();
    let require_https = !st.config.allow_http_verify;
    let assertion = req.assertion;

    let email = tokio::task::spawn_blocking(move || {
        verify_external_assertion(&assertion, &audience, &broker, require_https)
    })
    .await
    .map_err(|e| AppError::Internal(format!("verify task: {}", e)))?
    .map_err(AppError::InvalidAssertion)?;

    let account = st.store.find_or_create_account(&email)?;
    let (sid, csrf) = st.store.create_session(account.id)?;
    set_session_cookie(&cookies, &sid, st.config.allow_http_verify);

    Ok(Json(SessionResp { handle: account.handle, csrf }))
}

// --------------------------------------------------------------------------
// GET /whoami  ->  { authenticated, handle }
// Lightweight session probe used by the /auth fallback page.
// --------------------------------------------------------------------------
#[derive(Serialize)]
pub struct WhoAmI {
    pub authenticated: bool,
    pub handle: Option<String>,
}

pub async fn whoami(State(st): State<Shared>, cookies: Cookies) -> Json<WhoAmI> {
    match require_session(&st, &cookies) {
        Ok(account_id) => {
            let handle = st.store.get_account(account_id).ok().flatten().and_then(|a| a.handle);
            Json(WhoAmI { authenticated: true, handle })
        }
        Err(_) => Json(WhoAmI { authenticated: false, handle: None }),
    }
}

// --------------------------------------------------------------------------
// POST /claim_handle  { handle }  ->  { email }
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct ClaimReq {
    pub handle: String,
}

#[derive(Serialize)]
pub struct ClaimResp {
    pub email: String,
}

pub async fn claim_handle(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<ClaimReq>,
) -> Result<Json<ClaimResp>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    let handle = normalize_handle(&req.handle)?;

    if !st.store.set_handle(account_id, &handle)? {
        return Err(AppError::HandleTaken);
    }
    Ok(Json(ClaimResp { email: format!("{}@{}", handle, st.config.domain) }))
}

// --------------------------------------------------------------------------
// POST /cert_key  { email, pubkey: { algorithm, publicKey } }  ->  { cert }
// Called by the /provision page once the broker dialog hands it the keypair.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct CertReq {
    pub email: String,
    pub pubkey: PubKeyJson,
}

#[derive(Deserialize)]
pub struct PubKeyJson {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Serialize)]
pub struct CertResp {
    pub success: bool,
    pub cert: String,
}

pub async fn cert_key(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<CertReq>,
) -> Result<Json<CertResp>, AppError> {
    let account_id = require_session(&st, &cookies)?;

    // The requested email must be <handle>@<our-domain> and owned by this session.
    let (handle, domain) = req
        .email
        .split_once('@')
        .ok_or_else(|| AppError::BadRequest("malformed email".into()))?;
    if domain != st.config.domain {
        return Err(AppError::Forbidden);
    }
    let handle = normalize_handle(handle)?;
    match st.store.account_id_for_handle(&handle)? {
        Some(owner) if owner == account_id => {}
        _ => return Err(AppError::Forbidden),
    }

    if req.pubkey.algorithm != "Ed25519" {
        return Err(AppError::BadRequest(format!("unsupported algorithm: {}", req.pubkey.algorithm)));
    }
    let user_pk = PublicKey::from_base64(&req.pubkey.public_key)
        .map_err(|e| AppError::BadRequest(format!("invalid public key: {}", e)))?;

    let cert = Certificate::create(
        &st.config.domain,
        &req.email,
        &user_pk,
        chrono::Duration::hours(24),
        &st.keypair,
    )
    .map_err(|e| AppError::Internal(format!("cert create: {}", e)))?;

    Ok(Json(CertResp { success: true, cert: cert.encoded().to_string() }))
}

// --------------------------------------------------------------------------
// POST /admin/seed  (X-Admin-Token)  { external_email, handle }  ->  { email }
// Demo seeding: bind a handle to an external identity without the live flow.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct SeedReq {
    pub external_email: String,
    pub handle: String,
}

pub async fn admin_seed(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SeedReq>,
) -> Result<Json<ClaimResp>, AppError> {
    let expected = st.config.admin_token.as_deref().ok_or(AppError::Forbidden)?;
    let provided = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).unwrap_or("");
    if provided != expected {
        return Err(AppError::Forbidden);
    }
    let handle = normalize_handle(&req.handle)?;
    let account = st.store.find_or_create_account(&req.external_email)?;
    if !st.store.set_handle(account.id, &handle)? {
        return Err(AppError::HandleTaken);
    }
    Ok(Json(ClaimResp { email: format!("{}@{}", handle, st.config.domain) }))
}

// --------------------------------------------------------------------------
// POST /admin/delete-account  (X-Admin-Token)  { external_email }
// Resets an identity so the next sign-in re-triggers the handle chooser.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct DeleteReq {
    pub external_email: String,
}

pub async fn admin_delete_account(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeleteReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let expected = st.config.admin_token.as_deref().ok_or(AppError::Forbidden)?;
    let provided = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).unwrap_or("");
    if provided != expected {
        return Err(AppError::Forbidden);
    }
    let removed = st.store.delete_account(&req.external_email)?;
    Ok(Json(serde_json::json!({ "deleted": removed })))
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------
fn require_session(st: &Shared, cookies: &Cookies) -> Result<i64, AppError> {
    let sid = cookies.get(SESSION_COOKIE).map(|c| c.value().to_string());
    let sid = sid.ok_or(AppError::NotAuthenticated)?;
    st.store
        .account_for_session(&sid)?
        .ok_or(AppError::NotAuthenticated)
}

fn set_session_cookie(cookies: &Cookies, sid: &str, dev_insecure: bool) {
    // The /provision page runs in a hidden iframe inside the broker dialog
    // (top origin = browserid.me), so the cookie is a third-party context and
    // must be SameSite=None; Secure to be sent. In dev (http) fall back to Lax.
    let mut b = Cookie::build((SESSION_COOKIE, sid.to_string()))
        .path("/")
        .http_only(true)
        .max_age(CookieDuration::days(30));
    b = if dev_insecure {
        b.same_site(SameSite::Lax)
    } else {
        b.same_site(SameSite::None).secure(true)
    };
    cookies.add(b.build());
}

/// Validate + normalize a handle: lowercase, `[a-z0-9._-]`, 1..=31, alnum start.
fn normalize_handle(raw: &str) -> Result<String, AppError> {
    let h = raw.trim().to_lowercase();
    if h.is_empty() || h.len() > 31 {
        return Err(AppError::InvalidHandle("must be 1–31 chars".into()));
    }
    let mut chars = h.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(AppError::InvalidHandle("must start with a letter or digit".into()));
    }
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(AppError::InvalidHandle("only a-z 0-9 . _ - allowed".into()));
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_validation() {
        assert_eq!(normalize_handle("Dan").unwrap(), "dan");
        assert_eq!(normalize_handle(" dan_m.1-x ").unwrap(), "dan_m.1-x");
        assert!(normalize_handle("").is_err());
        assert!(normalize_handle(".leadingdot").is_err());
        assert!(normalize_handle("has space").is_err());
        assert!(normalize_handle("bad!").is_err());
        assert!(normalize_handle(&"x".repeat(32)).is_err());
    }

    #[test]
    fn issued_cert_verifies_against_idp_key() {
        // The trustless contract: a cert we issue for <handle>@mingo.place verifies
        // under the public key we publish (the one in the _browserid TXT).
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let cert = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &user.public_key(),
            chrono::Duration::hours(24),
            &idp,
        )
        .unwrap();
        let parsed = Certificate::parse(cert.encoded()).unwrap();
        assert!(parsed.verify(&idp.public_key()).is_ok());
        // A different key must NOT validate it.
        assert!(parsed.verify(&KeyPair::generate().public_key()).is_err());
    }
}
