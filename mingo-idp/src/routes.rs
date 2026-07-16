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
    /// The shared **mingo-poster** agent signing key: mingo signs SBO objects
    /// on a consenting user's behalf with this one key, attaching a per-user
    /// agent cert (parent = the user) + the user-signed warrant (poster.rs).
    pub poster_key: KeyPair,
    pub store: Store,
    pub config: Config,
    /// Lazily-discovered signing key of the trusted broker (config.broker_domain),
    /// for verifying provisioning endorsements (tdxf). Cached after first fetch.
    pub broker_pubkey: std::sync::Mutex<Option<browserid_core::PublicKey>>,
}

impl AppState {
    pub fn new(keypair: KeyPair, poster_key: KeyPair, store: Store, config: Config) -> Self {
        Self {
            keypair,
            poster_key,
            store,
            config,
            broker_pubkey: std::sync::Mutex::new(None),
        }
    }
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
    /// The user's external (sign-in) email — so the client can offer using it
    /// directly as a public identity.
    pub email: String,
    /// `"handle"`, `"email"`, or `null` (undecided) — lets a returning user
    /// skip the identity chooser.
    pub identity_mode: Option<String>,
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

    let verified = tokio::task::spawn_blocking(move || {
        verify_external_assertion(&assertion, &audience, &broker, require_https)
    })
    .await
    .map_err(|e| AppError::Internal(format!("verify task: {}", e)))?
    .map_err(AppError::InvalidAssertion)?;
    let email = verified.email;
    if let Some((parent, scopes)) = &verified.agent {
        tracing::info!(agent = %email, parent = %parent, ?scopes,
            "agent session (warrant-backed)");
    }

    reject_own_domain(&email, &st.config.domain)?;

    let account = st.store.find_or_create_account(&email)?;
    let (sid, csrf) = st.store.create_session(account.id)?;
    set_session_cookie(&cookies, &sid, st.config.allow_http_verify);

    Ok(Json(SessionResp {
        handle: account.handle,
        email: account.external_email,
        identity_mode: account.identity_mode,
        csrf,
    }))
}

// --------------------------------------------------------------------------
// POST /use_external  ->  { email }
// Record that the user chose to use their external email as their public
// identity instead of a local @mingo.place handle. Session-gated; no cert is
// issued (the external identity is certified by its own IdP/the broker).
// --------------------------------------------------------------------------
pub async fn use_external(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<ClaimResp>, AppError> {
    let account_id = require_session(&st, &cookies)?;
    st.store.set_identity_mode(account_id, "email")?;
    let email = st
        .store
        .get_account(account_id)?
        .map(|a| a.external_email)
        .ok_or(AppError::NotAuthenticated)?;
    Ok(Json(ClaimResp { email }))
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
            let handle = st
                .store
                .get_account(account_id)
                .ok()
                .flatten()
                .and_then(|a| a.handle);
            Json(WhoAmI {
                authenticated: true,
                handle,
            })
        }
        Err(_) => Json(WhoAmI {
            authenticated: false,
            handle: None,
        }),
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
    st.store.set_identity_mode(account_id, "handle")?;
    Ok(Json(ClaimResp {
        email: format!("{}@{}", handle, st.config.domain),
    }))
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
    /// The account's external (parent) identity. Returned PRIVATELY to our own
    /// provision page so browserid can record `<handle>@domain` as subordinate to
    /// it — carried over the provisioning channel, never in the cert (mingo-cm8z).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subordinate_to: Option<String>,
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
        return Err(AppError::BadRequest(format!(
            "unsupported algorithm: {}",
            req.pubkey.algorithm
        )));
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

    // The <handle>@domain identity is minted/derived; its controlling parent is
    // the account's external identity. Hand it back privately so browserid can
    // record the subordinate→parent link (mingo-cm8z).
    let subordinate_to = st.store.get_account(account_id)?.map(|a| a.external_email);

    Ok(Json(CertResp {
        success: true,
        cert: cert.encoded().to_string(),
        subordinate_to,
    }))
}

// --------------------------------------------------------------------------
// GET /provision_return?email=&pubkey=&state=&return_to=
//
// Same-tab (first-party) provisioning handshake (mingo-ytrs). The old path minted
// handle certs inside a HIDDEN cross-site `/provision` iframe embedded in the
// broker; mobile Safari ITP blocks our `SameSite=None` session cookie in that
// third-party context, so nothing was ever deposited into the broker keystore and
// a handle user could never sign a warrant on a fresh mobile device.
//
// Here the broker's consent page instead generates a NON-EXTRACTABLE keypair and
// navigates the TOP frame to this endpoint, so our session cookie is FIRST-PARTY
// and works. We mint the `<handle>@<domain>` cert for the handle THIS SESSION owns
// and 302 back to the broker with the cert in the URL FRAGMENT (never sent to any
// server, never logged, never leaked via Referer).
//
// Pseudonymity (mingo-ytrs, dan): the session is keyed to the account's external
// login email, but the cert principal is ONLY the handle. The external email is
// never read into, and never appears in, the minted cert / URL / anything the
// broker sees. We derive the handle from the session and require the broker's
// requested email to equal it — a session can only provision the pseudonym it owns.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct ProvReturnQuery {
    /// The `<handle>@<domain>` identity the broker wants a cert for. Cross-checked
    /// against the session's own handle; never trusted as an input beyond that.
    pub email: String,
    /// base64url (no pad) Ed25519 public key the broker generated (JWK `x`).
    pub pubkey: String,
    /// Opaque broker nonce, echoed back verbatim so the broker can bind the
    /// returned cert to the pending keypair it generated. Constrained to
    /// base64url so it can't inject extra fragment params.
    pub state: String,
    /// Where to hand the cert back. MUST be an exact broker origin (allowlist).
    pub return_to: String,
}

/// Reject any `return_to` that is not an exact broker origin. This endpoint is the
/// sole delivery point of a freshly-minted cert, so an open redirect here would be
/// a cert-exfiltration primitive. Requires `https://<broker_domain>/…` (the trailing
/// slash pins the host exactly, defeating `browser­id.me.evil.com` /
/// `browserid.me@evil.com` tricks) and forbids a caller-supplied fragment (we append
/// our own). In dev (`allow_http_verify`) `http://` is also accepted.
fn validate_return_to(raw: &str, broker_domain: &str, dev_insecure: bool) -> Result<(), AppError> {
    if raw.contains('#') {
        return Err(AppError::BadRequest("return_to must not contain a fragment".into()));
    }
    // Reject control chars (esp. a %0D%0A-decoded CR/LF): they pass the origin
    // allowlist below but then make the redirect's HeaderValue construction fail.
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(AppError::BadRequest("return_to contains control characters".into()));
    }
    let mut allowed = vec![
        format!("https://{}/", broker_domain),
        format!("https://{}", broker_domain),
    ];
    if dev_insecure {
        allowed.push(format!("http://{}/", broker_domain));
        allowed.push(format!("http://{}", broker_domain));
    }
    // Exact-origin match: either the bare origin, or the origin followed by a path.
    let ok = allowed.iter().any(|base| {
        if base.ends_with('/') {
            raw.starts_with(base)
        } else {
            raw == base
        }
    });
    if ok {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// `state` must be pure base64url so it can't smuggle extra `&`/`#` fragment params
/// into the redirect we build.
fn is_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub async fn provision_return(
    State(st): State<Shared>,
    cookies: Cookies,
    axum::extract::Query(q): axum::extract::Query<ProvReturnQuery>,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;

    // 1. Allowlist the return target BEFORE doing anything else.
    validate_return_to(&q.return_to, &st.config.broker_domain, st.config.allow_http_verify)?;
    if !is_base64url(&q.state) {
        return Err(AppError::BadRequest("invalid state".into()));
    }

    // 2. First-party session required. Without one we must not mint (and must not
    //    reveal whether the handle exists) — show a minimal sign-in prompt.
    let account_id = match require_session(&st, &cookies) {
        Ok(id) => id,
        Err(_) => return Ok(sign_in_first_page(&st.config.app_origin)),
    };

    // 3. Resolve the session to ITS handle; mint ONLY for that pseudonym. The
    //    external login email is never read into the cert.
    let account = st
        .store
        .get_account(account_id)?
        .ok_or(AppError::Forbidden)?;
    let handle = account.handle.ok_or(AppError::Forbidden)?;
    let handle_email = format!("{}@{}", handle, st.config.domain);
    if !q.email.eq_ignore_ascii_case(&handle_email) {
        // The session doesn't own the requested handle.
        return Err(AppError::Forbidden);
    }

    // 4. Mint — identical to /cert_key (24h, our issuer key), principal = handle.
    let user_pk = PublicKey::from_base64(&q.pubkey)
        .map_err(|e| AppError::BadRequest(format!("invalid public key: {}", e)))?;
    let cert = Certificate::create(
        &st.config.domain,
        &handle_email,
        &user_pk,
        chrono::Duration::hours(24),
        &st.keypair,
    )
    .map_err(|e| AppError::Internal(format!("cert create: {}", e)))?;

    // 5. Hand the cert back in the FRAGMENT. Both the JWS and `state` are base64url,
    //    so no percent-encoding is needed and nothing can break out of the fragment.
    let location = format!(
        "{}#prov_cert={}&state={}",
        q.return_to,
        cert.encoded(),
        q.state
    );
    Ok(axum::response::Redirect::to(&location).into_response())
}

/// Minimal first-party page shown when `/provision_return` is hit without a mingo
/// session (shouldn't happen coming from an in-app flow, but handled). No cert is
/// minted and the handle is never named.
fn sign_in_first_page(app_origin: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>mingo.place — sign in</title></head>\
<body style=\"font:16px/1.6 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1.25rem\">\
<h1>Sign in to mingo.place</h1>\
<p>To set up signing on this device, sign in to mingo.place first, then return to the approval page.</p>\
<p><a href=\"{}\">Open mingo.place</a></p></body></html>",
        html_escape_attr(app_origin)
    );
    (axum::http::StatusCode::OK, axum::response::Html(html)).into_response()
}

/// Minimal attribute-safe escaping for the one interpolated URL above.
fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

/// Verify the `X-Admin-Token` header against the configured admin token. Fails
/// closed when no admin token is configured.
fn require_admin(st: &Shared, headers: &axum::http::HeaderMap) -> Result<(), AppError> {
    let expected = st
        .config
        .admin_token
        .as_deref()
        .ok_or(AppError::Forbidden)?;
    let provided = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != expected {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

pub async fn admin_seed(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SeedReq>,
) -> Result<Json<ClaimResp>, AppError> {
    require_admin(&st, &headers)?;
    let handle = normalize_handle(&req.handle)?;
    reject_own_domain(&req.external_email, &st.config.domain)?;
    let account = st.store.find_or_create_account(&req.external_email)?;
    if !st.store.set_handle(account.id, &handle)? {
        return Err(AppError::HandleTaken);
    }
    Ok(Json(ClaimResp {
        email: format!("{}@{}", handle, st.config.domain),
    }))
}

// --------------------------------------------------------------------------
// POST /admin/provision  (X-Admin-Token)
//   { external_email, handle, pubkey: { algorithm, publicKey } }
//   -> { email, cert, subordinate_to }
//
// DEPRECATED as the agent path (mingo-ua8w): agents should use the per-user,
// API-key-gated `/agent/*` provisioning surface (src/agent.rs; spec in
// browserid-ng docs/specs/agent-provisioning-and-grant-api.md). This endpoint
// remains for genesis/admin seeding only.
//
// Programmatic provisioning for automation and tests: bind `handle` to
// `external_email` (like /admin/seed) AND issue a `<handle>@<domain>` cert for
// `pubkey` (like /cert_key) — all under admin auth, bypassing the interactive
// browserid session. The cert is identical to the one /cert_key mints, so a
// caller can assemble the on-chain `identity.email.v1` without an email round
// trip. Idempotent on the account/handle binding: re-provisioning the same
// (external_email, handle) re-issues a fresh cert for the given pubkey.
// --------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct ProvisionReq {
    pub external_email: String,
    pub handle: String,
    pub pubkey: PubKeyJson,
    /// When set, mint an AGENT cert (`agent.parent = <this email>`) instead of
    /// a plain identity cert — the shape `mint_poster_cert` produces, usable
    /// only alongside a warrant signed by this delegator (mingo-b2yz seeding:
    /// one agent cert per delegator, exactly like mingo-poster's per-user
    /// certs). Admin-gated like the rest of this endpoint.
    #[serde(default)]
    pub agent_parent: Option<String>,
}

pub async fn admin_provision(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProvisionReq>,
) -> Result<Json<CertResp>, AppError> {
    require_admin(&st, &headers)?;
    let handle = normalize_handle(&req.handle)?;
    reject_own_domain(&req.external_email, &st.config.domain)?;

    // Seed (or reuse) the account and its handle binding.
    let account = st.store.find_or_create_account(&req.external_email)?;
    match st.store.account_id_for_handle(&handle)? {
        // Already bound to this account: fine, re-issue.
        Some(owner) if owner == account.id => {}
        // Unbound: claim it for this account.
        None => {
            if !st.store.set_handle(account.id, &handle)? {
                return Err(AppError::HandleTaken);
            }
        }
        // Bound to a different account: refuse (don't hijack).
        Some(_) => return Err(AppError::HandleTaken),
    }

    if req.pubkey.algorithm != "Ed25519" {
        return Err(AppError::BadRequest(format!(
            "unsupported algorithm: {}",
            req.pubkey.algorithm
        )));
    }
    let user_pk = PublicKey::from_base64(&req.pubkey.public_key)
        .map_err(|e| AppError::BadRequest(format!("invalid public key: {}", e)))?;

    let email = format!("{}@{}", handle, st.config.domain);
    let cert = match &req.agent_parent {
        Some(parent) => Certificate::create_agent(
            &st.config.domain,
            &email,
            parent,
            &user_pk,
            chrono::Duration::hours(24),
            &st.keypair,
            Some(crate::poster::origin_for(&st.config.broker_domain)),
        ),
        None => Certificate::create(
            &st.config.domain,
            &email,
            &user_pk,
            chrono::Duration::hours(24),
            &st.keypair,
        ),
    }
    .map_err(|e| AppError::Internal(format!("cert create: {}", e)))?;

    Ok(Json(CertResp {
        success: true,
        cert: cert.encoded().to_string(),
        subordinate_to: Some(account.external_email),
    }))
}

/// Reject the IdP's own domain as an *external* identity. A `<handle>@<domain>`
/// address must never become an `external_email` account: doing so creates a
/// self-referential loop (the handle email logs in and claims its own handle)
/// and pollutes the handle namespace. Users must sign in with a real external
/// email; the `<handle>@<domain>` identity is *issued* by this IdP, never an input.
fn reject_own_domain(email: &str, domain: &str) -> Result<(), AppError> {
    let email_domain = email.rsplit('@').next().unwrap_or("");
    if email_domain.eq_ignore_ascii_case(domain) {
        return Err(AppError::BadRequest(format!(
            "{email} cannot be used to sign in — it is a @{domain} identity issued by this \
             service, not an external email. Sign in with your real email instead."
        )));
    }
    Ok(())
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
    let expected = st
        .config
        .admin_token
        .as_deref()
        .ok_or(AppError::Forbidden)?;
    let provided = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != expected {
        return Err(AppError::Forbidden);
    }
    let removed = st.store.delete_account(&req.external_email)?;
    Ok(Json(serde_json::json!({ "deleted": removed })))
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------
pub(crate) fn require_session(st: &Shared, cookies: &Cookies) -> Result<i64, AppError> {
    let sid = cookies.get(SESSION_COOKIE).map(|c| c.value().to_string());
    let sid = sid.ok_or(AppError::NotAuthenticated)?;
    st.store
        .account_for_session(&sid)?
        .ok_or(AppError::NotAuthenticated)
}

// --------------------------------------------------------------------------
// POST /logout  ->  { success }
// Real sign-out: invalidate the server session AND clear the cookie. (mingo-web's
// old client-only signOut left the session valid, so a stale cookie could still
// mint certs via /cert_key — see mingo-n153.) Scoped to the mingo.place session;
// the browserid broker session is separate and untouched.
// --------------------------------------------------------------------------
pub async fn logout(
    State(st): State<Shared>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(c) = cookies.get(SESSION_COOKIE) {
        // Full sign-out: end ALL of the account's sessions, not just this cookie's,
        // so stale sessions can't linger and keep authorizing /cert_key
        // (mingo session hygiene). Falls back to deleting just this session if the
        // cookie doesn't resolve to an account.
        match st.store.account_for_session(c.value())? {
            Some(account_id) => st.store.delete_account_sessions(account_id)?,
            None => st.store.delete_session(c.value())?,
        }
    }
    clear_session_cookie(&cookies, st.config.allow_http_verify);
    Ok(Json(serde_json::json!({ "success": true })))
}

/// Expire the session cookie. Attributes must match `set_session_cookie` (path +
/// SameSite/Secure) or the browser won't overwrite the third-party-context cookie.
fn clear_session_cookie(cookies: &Cookies, dev_insecure: bool) {
    let mut b = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .max_age(CookieDuration::seconds(0));
    b = if dev_insecure {
        b.same_site(SameSite::Lax)
    } else {
        b.same_site(SameSite::None).secure(true)
    };
    cookies.add(b.build());
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
/// Handles that must never be issued as `<handle>@<domain>` identities. Issuing a
/// cert for e.g. `sys@<domain>` would let the holder be attributed as the on-chain
/// `sys` identity (the root policy's `admin` role) — a privilege escalation. On-chain
/// system principals are key-rooted; nobody should reach them via the email onramp.
///
/// The reservation is STRUCTURAL: `sys` and the entire `sys-*` namespace are
/// reserved, so every current and FUTURE system authority under the `sys-<role>`
/// convention (e.g. `sys-checkpointer`) is auto-reserved without editing this list.
/// The remaining entries are conventionally-sensitive email local-parts.
const RESERVED_HANDLES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "superuser",
    "postmaster",
    "hostmaster",
    "webmaster",
    "abuse",
    "security",
    "noreply",
    "no-reply",
    "mailer-daemon",
    "daemon",
];

/// A handle is reserved if it is `sys`, lives in the `sys-*` system namespace, or
/// is a conventionally-sensitive address. Input is already lowercased/trimmed.
fn handle_is_reserved(h: &str) -> bool {
    h == "sys" || h.starts_with("sys-") || RESERVED_HANDLES.contains(&h)
}

pub(crate) fn normalize_handle(raw: &str) -> Result<String, AppError> {
    normalize_name(raw, false)
}

/// Like [`normalize_handle`] but allows `+` for `<handle>+<suffix>`
/// subaddressing — agent identities (mingo-ua8w) may use it; human handles
/// may not. Reservations (`sys`/`sys-*`, …) apply either way.
pub(crate) fn normalize_agent_name(raw: &str) -> Result<String, AppError> {
    normalize_name(raw, true)
}

fn normalize_name(raw: &str, allow_plus: bool) -> Result<String, AppError> {
    let h = raw.trim().to_lowercase();
    let max = if allow_plus { 64 } else { 31 };
    if h.is_empty() || h.len() > max {
        return Err(AppError::InvalidHandle(format!("must be 1–{max} chars")));
    }
    let mut chars = h.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(AppError::InvalidHandle(
            "must start with a letter or digit".into(),
        ));
    }
    let ok = |c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') || (allow_plus && c == '+')
    };
    if !h.chars().all(ok) {
        return Err(AppError::InvalidHandle(
            "disallowed character in name".into(),
        ));
    }
    if handle_is_reserved(&h) {
        return Err(AppError::InvalidHandle("this handle is reserved".into()));
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_own_domain_as_external_identity() {
        // The IdP's own domain (and case variants) must be rejected as a sign-in email.
        assert!(reject_own_domain("dan@mingo.place", "mingo.place").is_err());
        assert!(reject_own_domain("danmills@mingo.place", "mingo.place").is_err());
        assert!(reject_own_domain("dan@MINGO.PLACE", "mingo.place").is_err());
        // Real external emails are allowed.
        assert!(reject_own_domain("danmills@sandmill.org", "mingo.place").is_ok());
        assert!(reject_own_domain("user@gmail.com", "mingo.place").is_ok());
    }

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

    #[test]
    fn reserved_handles_are_rejected() {
        // Privileged on-chain principals must not be claimable via the email onramp
        // (issuing sys@<domain> → attributed as the on-chain `sys` admin identity).
        for h in [
            "sys",
            "Sys",
            " SYS ",
            "admin",
            "root",
            "sys-checkpointer",
            "sys-moderator",
            "SYS-anything",
        ] {
            assert!(
                matches!(normalize_handle(h), Err(AppError::InvalidHandle(_))),
                "reserved handle {h:?} must be rejected"
            );
        }
        // Ordinary handles still pass — including a "sys"-substring that isn't the
        // reserved `sys` / `sys-*` namespace.
        assert_eq!(normalize_handle(" Dan ").unwrap(), "dan");
        assert!(
            normalize_handle("system").is_ok(),
            "not in the sys- namespace"
        );
        assert!(
            normalize_handle("sysadmin").is_ok(),
            "sysadmin != sys / sys-*"
        );
    }
}
