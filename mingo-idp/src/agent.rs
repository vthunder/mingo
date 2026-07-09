//! Delegation-chain agent provisioning — mingo-idp as a target IdP (tdxf,
//! spec v0.2 §4.3-4.5). Key management lives at the broker (browserid.me);
//! mingo-idp only *mints*, verifying a dual-signed request:
//!
//! - the user-signed delegation chain `U_cert~P_cert~R`, where `U_cert` is a
//!   `<handle>@mingo.place` identity cert **we issued** (verified against our
//!   own key, with signing-time semantics), and
//! - a fresh endorsement from the trusted broker (`config.broker_domain`),
//!   whose key we discover via `.well-known/browserid`.
//!
//! The agent identity `<name>@mingo.place` shares the human handle namespace
//! (so `sys`/`sys-*` reservations apply), is attributed to the delegating
//! identity, and re-mints/​revokes are ordinary signed requests. There is no
//! bearer credential and no per-IdP key storage.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use browserid_core::keys::PublicKey;
use browserid_core::provisioning::{Action, Endorsement, RequestBundle, VerifiedRequest};
use browserid_core::Certificate;
use serde::Deserialize;

use crate::routes::{normalize_agent_name, Shared};

/// Spec-shaped errors with the §4 status contract.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent provisioning is not enabled")]
    Disabled,
    #[error("invalid provisioning request: {0}")]
    BadRequest(String),
    #[error("not endorsed: {0}")]
    NotEndorsed(String),
    #[error("identity revoked")]
    IdentityRevoked,
    #[error("not found")]
    NotFound,
    #[error("name already taken")]
    NameTaken,
    /// Reservation collision — carries the unavailable names for UI feedback.
    #[error("some requested handles are unavailable")]
    NamesTaken(Vec<String>),
    #[error("agent identity quota exceeded")]
    QuotaExceeded,
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
        // Reservation collisions carry the specific unavailable names.
        if let AgentError::NamesTaken(taken) = &self {
            let body = Json(serde_json::json!({
                "success": false,
                "reason": "some requested handles are unavailable",
                "taken": taken,
            }));
            return (StatusCode::CONFLICT, body).into_response();
        }
        let status = match &self {
            // Disabled and unknown/unowned are indistinguishable (spec §4).
            AgentError::Disabled | AgentError::NotFound => StatusCode::NOT_FOUND,
            AgentError::NotEndorsed(_) => StatusCode::UNAUTHORIZED,
            AgentError::IdentityRevoked => StatusCode::FORBIDDEN,
            AgentError::NameTaken | AgentError::NamesTaken(_) => StatusCode::CONFLICT,
            AgentError::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            AgentError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AgentError::Internal(msg) => {
                tracing::error!("agent provisioning internal error: {}", msg);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(serde_json::json!({ "success": false, "reason": self.to_string() }));
        (status, body).into_response()
    }
}

#[derive(Deserialize)]
pub struct ProvisionRequest {
    pub request_bundle: String,
    pub endorsement: String,
}

/// Resolve the trusted broker's signing key, discovering + caching it. The
/// discovery fetch is blocking (`reqwest::blocking`), so run it off the async
/// runtime.
async fn broker_key(st: &Shared) -> Result<PublicKey, AgentError> {
    if let Some(k) = st.broker_pubkey.lock().unwrap().clone() {
        return Ok(k);
    }
    let broker_domain = st.config.broker_domain.clone();
    let require_https = !st.config.allow_http_verify;
    let key = tokio::task::spawn_blocking(move || {
        crate::verify::fetch_domain_pubkey(&broker_domain, require_https)
    })
    .await
    .map_err(|e| AgentError::Internal(format!("broker key task: {e}")))?
    .map_err(|e| AgentError::Internal(format!("broker key discovery: {e}")))?;
    *st.broker_pubkey.lock().unwrap() = Some(key.clone());
    Ok(key)
}

/// Verify a dual-signed provisioning request as the target IdP:
/// full chain against our own key (we issued `U_cert`) + a fresh endorsement
/// from the trusted broker bound to this exact bundle. Returns the verified
/// request and the delegating identity's local handle.
fn verify_request(
    st: &Shared,
    req: &ProvisionRequest,
    expected: Action,
    broker_key: &PublicKey,
) -> Result<(VerifiedRequest, String), AgentError> {
    if !st.config.agent_provisioning {
        return Err(AgentError::Disabled);
    }

    let bundle =
        RequestBundle::parse(&req.request_bundle).map_err(|e| AgentError::BadRequest(e.to_string()))?;

    // The U_cert must be our own issuance (identity-domain rule): verifying the
    // chain against our key rejects any foreign-rooted parent.
    let verified = bundle
        .verify(&st.keypair.public_key())
        .map_err(|e| AgentError::BadRequest(e.to_string()))?;
    if verified.issuer != st.config.domain {
        return Err(AgentError::BadRequest(format!(
            "identity is rooted at '{}', not this IdP",
            verified.issuer
        )));
    }
    if verified.request.domain != st.config.domain {
        return Err(AgentError::BadRequest(
            "request domain does not target this IdP".into(),
        ));
    }
    if verified.request.action != expected {
        return Err(AgentError::BadRequest(
            "request action does not match this endpoint".into(),
        ));
    }

    // Endorsement from the trusted broker, fresh, bound to this exact bundle.
    let endorsement =
        Endorsement::parse(&req.endorsement).map_err(|e| AgentError::NotEndorsed(e.to_string()))?;
    endorsement
        .verify_for(broker_key, &st.config.domain, &bundle)
        .map_err(|e| AgentError::NotEndorsed(e.to_string()))?;

    // The delegating identity's local part is the mingo handle (dan@mingo.place
    // ↔ handle "dan").
    let handle = verified
        .delegator
        .split('@')
        .next()
        .ok_or_else(|| AgentError::BadRequest("delegator has no local part".into()))?
        .to_string();

    Ok((verified, handle))
}

/// Resolve the delegating identity's account (by its handle).
fn delegator_account(st: &Shared, handle: &str) -> Result<i64, AgentError> {
    st.store
        .account_id_for_handle(handle)?
        .ok_or(AgentError::NotFound)
}

/// Ensure the agent identity `raw_name` exists for `account_id`, creating it
/// (quota-checked) if new. Enforces the constraint + name grammar + `sys/sys-*`
/// reservations. Returns the normalized name. Shared by mint (issues a cert)
/// and reserve (pre-allocates, no cert).
fn ensure_identity(
    st: &Shared,
    verified: &VerifiedRequest,
    account_id: i64,
    raw_name: &str,
) -> Result<String, AgentError> {
    let name = normalize_agent_name(raw_name).map_err(|e| AgentError::BadRequest(e.to_string()))?;
    if !verified.constraint.authorizes(&name) {
        return Err(AgentError::BadRequest(format!(
            "'{name}' is not authorized by this key's constraint"
        )));
    }
    match st.store.get_agent_identity(&name)? {
        Some(rec) if rec.account_id == account_id => {
            if !rec.is_active() {
                return Err(AgentError::IdentityRevoked);
            }
        }
        Some(_) => return Err(AgentError::NameTaken),
        None => {
            if st.store.count_active_agent_identities(account_id)? >= st.config.agent_quota {
                return Err(AgentError::QuotaExceeded);
            }
            if !st.store.create_agent_identity(account_id, &name)? {
                return Err(AgentError::NameTaken);
            }
        }
    }
    Ok(name)
}

/// POST /provision/mint
pub async fn mint(
    State(st): State<Shared>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<serde_json::Value>, AgentError> {
    if !st.config.agent_provisioning {
        return Err(AgentError::Disabled);
    }
    let bk = broker_key(&st).await?;
    let (verified, delegator_handle) = verify_request(&st, &req, Action::Mint, &bk)?;
    let account_id = delegator_account(&st, &delegator_handle)?;

    let raw_name = verified
        .request
        .name
        .as_deref()
        .ok_or_else(|| AgentError::BadRequest("mint requires a name".into()))?;
    let agent_pub = verified
        .request
        .agent_key
        .as_ref()
        .ok_or_else(|| AgentError::BadRequest("mint requires an agent-key".into()))?;

    let name = ensure_identity(&st, &verified, account_id, raw_name)?;

    let email = format!("{}@{}", name, st.config.domain);
    let cert = Certificate::create(
        &st.config.domain,
        &email,
        agent_pub,
        chrono::Duration::hours(24),
        &st.keypair,
    )
    .map_err(|e| AgentError::Internal(format!("cert create: {e}")))?;

    tracing::info!(email = %email, delegator = %verified.delegator, "minted agent identity");
    Ok(Json(serde_json::json!({
        "success": true,
        "email": email,
        "cert": cert.encoded(),
        // Attribution root = the delegating identity (dan@mingo.place),
        // carried privately, never in the cert (cm8z semantics).
        "subordinate_to": verified.delegator,
    })))
}

/// POST /provision/reserve — pre-allocate the cert's bound `names` (all-or-
/// nothing) so a later mint can't be refused. Idempotent; consumes quota.
pub async fn reserve(
    State(st): State<Shared>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<serde_json::Value>, AgentError> {
    if !st.config.agent_provisioning {
        return Err(AgentError::Disabled);
    }
    let bk = broker_key(&st).await?;
    let (verified, delegator_handle) = verify_request(&st, &req, Action::Reserve, &bk)?;
    let account_id = delegator_account(&st, &delegator_handle)?;

    // Availability up front (all-or-nothing): collect every name taken by
    // another account or already a human handle, so the user learns exactly
    // which handles to change.
    let names = verified.constraint.names.clone();
    let mut taken = Vec::new();
    for raw in &names {
        let name = normalize_agent_name(raw).map_err(|e| AgentError::BadRequest(e.to_string()))?;
        let unavailable = match st.store.get_agent_identity(&name)? {
            Some(rec) => rec.account_id != account_id,
            None => st.store.account_id_for_handle(&name)?.is_some(),
        };
        if unavailable {
            taken.push(name);
        }
    }
    if !taken.is_empty() {
        return Err(AgentError::NamesTaken(taken));
    }
    for raw in &names {
        ensure_identity(&st, &verified, account_id, raw)?;
    }
    tracing::info!(delegator = %verified.delegator, count = names.len(), "reserved agent identities");
    Ok(Json(serde_json::json!({ "success": true })))
}

/// POST /provision/list
pub async fn list(
    State(st): State<Shared>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<serde_json::Value>, AgentError> {
    if !st.config.agent_provisioning {
        return Err(AgentError::Disabled);
    }
    let bk = broker_key(&st).await?;
    let (verified, delegator_handle) = verify_request(&st, &req, Action::List, &bk)?;
    let account_id = delegator_account(&st, &delegator_handle)?;

    let identities: Vec<serde_json::Value> = st
        .store
        .list_agent_identities(account_id)?
        .into_iter()
        .map(|i| {
            serde_json::json!({
                "email": format!("{}@{}", i.name, st.config.domain),
                "parent_email": verified.delegator,
                "active": i.is_active(),
                "created_at": chrono::DateTime::from_timestamp(i.created_at, 0).map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "success": true, "identities": identities })))
}

/// POST /provision/revoke
pub async fn revoke(
    State(st): State<Shared>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<serde_json::Value>, AgentError> {
    if !st.config.agent_provisioning {
        return Err(AgentError::Disabled);
    }
    let bk = broker_key(&st).await?;
    let (verified, delegator_handle) = verify_request(&st, &req, Action::Revoke, &bk)?;
    let account_id = delegator_account(&st, &delegator_handle)?;

    let raw_name = verified
        .request
        .name
        .as_deref()
        .ok_or_else(|| AgentError::BadRequest("revoke requires a name".into()))?;
    let name = normalize_agent_name(raw_name).map_err(|e| AgentError::BadRequest(e.to_string()))?;

    // Visibility rule: only the delegator's own agent identities are actionable.
    match st.store.get_agent_identity(&name)? {
        Some(rec) if rec.account_id == account_id => {}
        _ => return Err(AgentError::NotFound),
    }
    st.store.revoke_agent_identity(&name)?;
    tracing::info!(name = %name, delegator = %verified.delegator, "revoked agent identity");
    Ok(Json(serde_json::json!({ "success": true })))
}
