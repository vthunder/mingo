//! Headless agent provisioning (mingo-ua8w) — mingo-idp's implementation of
//! the agent provisioning spec (browserid-ng
//! `docs/specs/agent-provisioning-and-grant-api.md`, §4).
//!
//! Two route families, both gated on `config.agent_provisioning`:
//!
//! - `/agent_keys*` — browser-side API-key management (mingo session + CSRF).
//!   A key's attribution root is the account's `external_email` — the same
//!   parent the cm8z `subordinate_to` machinery reports for human handles.
//! - `/agent/*` — agent-side REST (`Authorization: Bearer bidk_…`): mint
//!   `<name>@mingo.place` identities + certs for the agent's own keypair,
//!   re-mint, list, revoke. Names share the human handle namespace (one
//!   `<local>@<domain>` space) and go through `normalize_handle`, so the
//!   `sys`/`sys-*` reservations hold for agents too.
//!
//! Error bodies follow the spec: `{"success": false, "reason": "…"}` with the
//! spec's status contract (401/403/404/409/429). This replaces
//! `/admin/provision` as the agent path; that endpoint stays for admin seeding.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use browserid_core::keys::PublicKey;
use browserid_core::Certificate;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::Cookies;

use crate::routes::{normalize_handle, PubKeyJson, Shared, SESSION_COOKIE};
use crate::store::ApiKey;

const API_KEY_PREFIX: &str = "bidk_";

/// Spec-shaped errors: `{"success": false, "reason"}` + the §4 status contract.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent provisioning is not enabled")]
    Disabled,
    #[error("invalid or revoked API key")]
    InvalidApiKey,
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("invalid CSRF token")]
    InvalidCsrf,
    #[error("identity revoked")]
    IdentityRevoked,
    #[error("not found")]
    NotFound,
    #[error("name already taken")]
    NameTaken,
    #[error("agent identity quota exceeded")]
    QuotaExceeded,
    #[error("{0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<rusqlite::Error> for AgentError {
    fn from(e: rusqlite::Error) -> Self {
        AgentError::Internal(format!("db: {}", e))
    }
}

impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let status = match &self {
            // Disabled and unknown/unowned are indistinguishable per spec §4.
            AgentError::Disabled | AgentError::NotFound => StatusCode::NOT_FOUND,
            AgentError::InvalidApiKey | AgentError::NotAuthenticated => StatusCode::UNAUTHORIZED,
            AgentError::InvalidCsrf | AgentError::IdentityRevoked => StatusCode::FORBIDDEN,
            AgentError::NameTaken => StatusCode::CONFLICT,
            AgentError::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            AgentError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AgentError::Internal(msg) => {
                tracing::error!("agent api internal error: {}", msg);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(serde_json::json!({ "success": false, "reason": self.to_string() }));
        (status, body).into_response()
    }
}

fn hash_api_key(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_api_key_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "{}{}",
        API_KEY_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn generate_agent_name() -> String {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("agent-{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

fn require_enabled(st: &Shared) -> Result<(), AgentError> {
    if st.config.agent_provisioning {
        Ok(())
    } else {
        Err(AgentError::Disabled)
    }
}

/// Session + CSRF gate for the key-management endpoints.
fn require_session_csrf(st: &Shared, cookies: &Cookies, csrf: &str) -> Result<i64, AgentError> {
    let sid = cookies
        .get(SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(AgentError::NotAuthenticated)?;
    let account_id = st
        .store
        .account_for_session(&sid)?
        .ok_or(AgentError::NotAuthenticated)?;
    let expected = st.store.session_csrf(&sid)?.ok_or(AgentError::NotAuthenticated)?;
    if csrf != expected {
        return Err(AgentError::InvalidCsrf);
    }
    Ok(account_id)
}

/// Bearer gate for `/agent/*`: hash the presented secret, load the active key
/// row, touch `last_used_at` (audit trail).
fn authenticate_api_key(st: &Shared, headers: &HeaderMap) -> Result<ApiKey, AgentError> {
    require_enabled(st)?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AgentError::InvalidApiKey)?;
    let key = st
        .store
        .get_api_key_by_hash(&hash_api_key(token))?
        .ok_or(AgentError::InvalidApiKey)?;
    if !key.is_active() {
        return Err(AgentError::InvalidApiKey);
    }
    st.store.touch_api_key(key.id)?;
    Ok(key)
}

fn issue_cert(st: &Shared, email: &str, pubkey: &PubKeyJson, ephemeral: bool) -> Result<String, AgentError> {
    if pubkey.algorithm != "Ed25519" {
        return Err(AgentError::BadRequest(format!(
            "unsupported algorithm: {}",
            pubkey.algorithm
        )));
    }
    let pk = PublicKey::from_base64(&pubkey.public_key)
        .map_err(|e| AgentError::BadRequest(format!("invalid public key: {}", e)))?;
    let validity = if ephemeral {
        chrono::Duration::hours(1)
    } else {
        chrono::Duration::hours(24)
    };
    let cert = Certificate::create(&st.config.domain, email, &pk, validity, &st.keypair)
        .map_err(|e| AgentError::Internal(format!("cert create: {}", e)))?;
    Ok(cert.encoded().to_string())
}

// ---------------------------------------------------------------------------
// Browser-side: API-key management (session + CSRF)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AgentKeyInfo {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}

/// GET /agent_keys — list the session account's API keys (never secrets)
pub async fn list_agent_keys(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AgentError> {
    require_enabled(&st)?;
    let sid = cookies
        .get(SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(AgentError::NotAuthenticated)?;
    let account_id = st
        .store
        .account_for_session(&sid)?
        .ok_or(AgentError::NotAuthenticated)?;

    let keys: Vec<AgentKeyInfo> = st
        .store
        .list_api_keys(account_id)?
        .into_iter()
        .map(|k| AgentKeyInfo {
            id: k.id,
            name: k.name,
            created_at: k.created_at,
            last_used_at: k.last_used_at,
            revoked: k.revoked_at.is_some(),
        })
        .collect();

    Ok(Json(serde_json::json!({ "success": true, "keys": keys })))
}

#[derive(Deserialize)]
pub struct CreateKeyReq {
    pub csrf: String,
    pub name: String,
}

/// POST /agent_keys — mint a key. The secret is returned exactly once. The
/// attribution root is the account's external_email (no parent choice needed:
/// a mingo account has exactly one external identity).
pub async fn create_agent_key(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<CreateKeyReq>,
) -> Result<Json<serde_json::Value>, AgentError> {
    require_enabled(&st)?;
    let account_id = require_session_csrf(&st, &cookies, &req.csrf)?;

    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(AgentError::BadRequest("key name must be 1-64 characters".into()));
    }

    let secret = generate_api_key_secret();
    let key = st.store.create_api_key(account_id, name, &hash_api_key(&secret))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "id": key.id,
        "name": key.name,
        "api_key": secret,
    })))
}

#[derive(Deserialize)]
pub struct RevokeKeyReq {
    pub csrf: String,
    pub id: i64,
}

/// POST /agent_keys/revoke
pub async fn revoke_agent_key(
    State(st): State<Shared>,
    cookies: Cookies,
    Json(req): Json<RevokeKeyReq>,
) -> Result<Json<serde_json::Value>, AgentError> {
    require_enabled(&st)?;
    let account_id = require_session_csrf(&st, &cookies, &req.csrf)?;
    if !st.store.revoke_api_key(account_id, req.id)? {
        return Err(AgentError::NotFound);
    }
    Ok(Json(serde_json::json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// Agent-side: REST provisioning (Bearer-key gated)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateIdentityReq {
    pub pubkey: PubKeyJson,
    pub name: Option<String>,
}

/// POST /agent/identities — mint (or idempotently re-provision) an agent
/// identity and issue a certificate for the presented pubkey (spec §4.2)
pub async fn create_identity(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<CreateIdentityReq>,
) -> Result<Json<serde_json::Value>, AgentError> {
    let key = authenticate_api_key(&st, &headers)?;

    // Same validation as human handles (incl. the sys/sys-* reservations —
    // an agent must never mint a cert attributable to a system principal).
    let name = match &req.name {
        Some(raw) => normalize_handle(raw).map_err(|e| AgentError::BadRequest(e.to_string()))?,
        None => generate_agent_name(),
    };
    let email = format!("{}@{}", name, st.config.domain);

    match st.store.get_agent_identity(&name)? {
        // Restart case: same account, still active → treat create as re-mint.
        Some(rec) if rec.account_id == key.account_id => {
            if !rec.is_active() {
                // Revocation sticks; a revoked name is not silently revivable.
                return Err(AgentError::IdentityRevoked);
            }
        }
        Some(_) => return Err(AgentError::NameTaken),
        None => {
            if st.store.count_active_agent_identities(key.account_id)? >= st.config.agent_quota {
                return Err(AgentError::QuotaExceeded);
            }
            // False here means a human handle (or a racing insert) owns the name.
            if !st.store.create_agent_identity(key.account_id, &name)? {
                return Err(AgentError::NameTaken);
            }
        }
    }

    let cert = issue_cert(&st, &email, &req.pubkey, false)?;
    let subordinate_to = st.store.get_account(key.account_id)?.map(|a| a.external_email);

    tracing::info!(email = %email, key_id = key.id, "provisioned agent identity");

    Ok(Json(serde_json::json!({
        "success": true,
        "email": email,
        "cert": cert,
        // Attribution root, same private-channel semantics as /cert_key's
        // subordinate_to (mingo-cm8z) — never present in the cert itself.
        "subordinate_to": subordinate_to,
    })))
}

/// GET /agent/identities — list the account's agent identities (spec §4.4)
pub async fn list_identities(
    State(st): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AgentError> {
    let key = authenticate_api_key(&st, &headers)?;
    let parent = st.store.get_account(key.account_id)?.map(|a| a.external_email);

    let identities: Vec<serde_json::Value> = st
        .store
        .list_agent_identities(key.account_id)?
        .into_iter()
        .map(|i| {
            serde_json::json!({
                "email": format!("{}@{}", i.name, st.config.domain),
                "parent_email": parent,
                "active": i.is_active(),
                "verified_at": chrono::DateTime::from_timestamp(i.created_at, 0)
                    .map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "success": true, "identities": identities })))
}

#[derive(Deserialize)]
pub struct AgentCertReq {
    pub email: String,
    pub pubkey: PubKeyJson,
    #[serde(default)]
    pub ephemeral: bool,
}

/// POST /agent/cert — re-mint for an existing agent identity (spec §4.3).
/// The presented pubkey is what gets certified: the API key is the root
/// credential, so the agent keypair may rotate freely.
pub async fn agent_cert(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<AgentCertReq>,
) -> Result<Json<serde_json::Value>, AgentError> {
    let key = authenticate_api_key(&st, &headers)?;
    let rec = owned_agent_identity(&st, &key, &req.email)?;
    if !rec.is_active() {
        return Err(AgentError::IdentityRevoked);
    }
    let email = format!("{}@{}", rec.name, st.config.domain);
    let cert = issue_cert(&st, &email, &req.pubkey, req.ephemeral)?;
    Ok(Json(serde_json::json!({ "success": true, "cert": cert })))
}

#[derive(Deserialize)]
pub struct RevokeIdentityReq {
    pub email: String,
}

/// POST /agent/identities/revoke — disable an identity (spec §4.5). Re-mints
/// fail from now on; outstanding certs age out within their TTL (≤24 h).
pub async fn revoke_identity(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<RevokeIdentityReq>,
) -> Result<Json<serde_json::Value>, AgentError> {
    let key = authenticate_api_key(&st, &headers)?;
    let rec = owned_agent_identity(&st, &key, &req.email)?;
    st.store.revoke_agent_identity(&rec.name)?;
    tracing::info!(email = %req.email, key_id = key.id, "revoked agent identity");
    Ok(Json(serde_json::json!({ "success": true })))
}

/// Resolve `email` to an agent identity owned by the key's account. Unknown
/// name, foreign domain, someone else's identity, and human handles are all
/// the same `NotFound` — an API key must never be able to probe or act on
/// anything outside its own agent namespace (spec §4's visibility rule).
fn owned_agent_identity(
    st: &Shared,
    key: &ApiKey,
    email: &str,
) -> Result<crate::store::AgentIdentity, AgentError> {
    let (local, domain) = email.split_once('@').ok_or(AgentError::NotFound)?;
    if !domain.eq_ignore_ascii_case(&st.config.domain) {
        return Err(AgentError::NotFound);
    }
    match st.store.get_agent_identity(local)? {
        Some(rec) if rec.account_id == key.account_id => Ok(rec),
        _ => Err(AgentError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_secret_shape_and_hash() {
        let s = generate_api_key_secret();
        assert!(s.starts_with(API_KEY_PREFIX));
        assert_eq!(hash_api_key(&s).len(), 64);
        assert_ne!(generate_api_key_secret(), s);
    }

    #[test]
    fn generated_names_pass_handle_validation() {
        for _ in 0..20 {
            let n = generate_agent_name();
            assert_eq!(normalize_handle(&n).unwrap(), n);
        }
    }
}
