//! mingo.place primary BrowserID IdP — library surface.
//!
//! The binary (`src/main.rs`) is a thin wrapper; the router lives here so
//! integration tests can boot the real app in-process (e.g. the agent
//! provisioning conformance test drives it with the `browserid-agent` SDK).

pub mod agent;
pub mod config;
pub mod error;
pub mod poster;
pub mod routes;
pub mod store;
pub mod verify;

use std::path::Path;

use axum::http::{header, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

pub use routes::{AppState, Shared};

/// Build the full application router. `static_dir` holds the IdP protocol
/// assets (provision/auth pages + shims); `spa_dir` the mingo-web SPA.
pub fn build_router(state: Shared, static_dir: &Path, spa_dir: &Path) -> Router {
    let file = |name: &str| ServeFile::new(static_dir.join(name));
    // Agent provisioning (mingo-ua8w; tdxf spec §4.3-4.5) — target-IdP
    // mint/list/revoke/reserve of dual-signed requests. `/provision/reserve`
    // is called cross-origin by the browser at browserid.me/agents, so this
    // group gets permissive CORS (no cookies — the credential is the bundle).
    let provision = Router::new()
        .route("/provision/reserve", post(agent::reserve))
        .route("/provision/mint", post(agent::mint))
        .route("/provision/list", post(agent::list))
        .route("/provision/revoke", post(agent::revoke))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE]),
        );
    Router::new()
        .route("/.well-known/browserid", get(routes::well_known))
        .route(
            "/session/from-assertion",
            post(routes::session_from_assertion),
        )
        .route("/whoami", get(routes::whoami))
        .route("/logout", post(routes::logout))
        .route("/claim_handle", post(routes::claim_handle))
        .route("/use_external", post(routes::use_external))
        .route("/cert_key", post(routes::cert_key))
        .route("/admin/seed", post(routes::admin_seed))
        .route("/admin/provision", post(routes::admin_provision))
        .route("/admin/delete-account", post(routes::admin_delete_account))
        .merge(provision)
        .route_service("/provision", file("provision.html"))
        .route_service("/auth", file("auth.html"))
        .route_service("/provision.js", file("provision.js"))
        .route_service("/auth.js", file("auth.js"))
        .route_service("/provisioning_api.js", file("provisioning_api.js"))
        .route_service("/authentication_api.js", file("authentication_api.js"))
        // The mingo-web SPA, served same-origin as a fallback.
        .fallback_service(ServeDir::new(spa_dir).append_index_html_on_directories(true))
        // Always revalidate served assets. The SPA (app.js) is security-critical
        // and updates land per deploy; stale cached JS must never silently run.
        // `no-cache` still allows 304s via etag/last-modified — cheap, never blindly fresh.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
