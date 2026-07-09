//! mingo.place primary BrowserID IdP — library surface.
//!
//! The binary (`src/main.rs`) is a thin wrapper; the router lives here so
//! integration tests can boot the real app in-process (e.g. the agent
//! provisioning conformance test drives it with the `browserid-agent` SDK).

pub mod agent;
pub mod config;
pub mod error;
pub mod routes;
pub mod store;
pub mod verify;

use std::path::Path;

use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::services::{ServeDir, ServeFile};

pub use routes::{AppState, Shared};

/// Build the full application router. `static_dir` holds the IdP protocol
/// assets (provision/auth pages + shims); `spa_dir` the mingo-web SPA.
pub fn build_router(state: Shared, static_dir: &Path, spa_dir: &Path) -> Router {
    let file = |name: &str| ServeFile::new(static_dir.join(name));
    Router::new()
        .route("/.well-known/browserid", get(routes::well_known))
        .route("/session/from-assertion", post(routes::session_from_assertion))
        .route("/whoami", get(routes::whoami))
        .route("/logout", post(routes::logout))
        .route("/claim_handle", post(routes::claim_handle))
        .route("/cert_key", post(routes::cert_key))
        .route("/admin/seed", post(routes::admin_seed))
        .route("/admin/provision", post(routes::admin_provision))
        .route("/admin/delete-account", post(routes::admin_delete_account))
        // Agent provisioning (mingo-ua8w; spec §4) — 404s until
        // config.agent_provisioning is enabled.
        .route("/agent_keys", get(agent::list_agent_keys).post(agent::create_agent_key))
        .route("/agent_keys/revoke", post(agent::revoke_agent_key))
        .route("/agent/identities", post(agent::create_identity).get(agent::list_identities))
        .route("/agent/cert", post(agent::agent_cert))
        .route("/agent/identities/revoke", post(agent::revoke_identity))
        .route_service("/provision", file("provision.html"))
        .route_service("/auth", file("auth.html"))
        .route_service("/provision.js", file("provision.js"))
        .route_service("/auth.js", file("auth.js"))
        .route_service("/provisioning_api.js", file("provisioning_api.js"))
        .route_service("/authentication_api.js", file("authentication_api.js"))
        // The mingo-web SPA, served same-origin as a fallback.
        .fallback_service(ServeDir::new(spa_dir).append_index_html_on_directories(true))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
