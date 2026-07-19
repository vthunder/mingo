//! mingo.place primary BrowserID IdP — library surface.
//!
//! The binary (`src/main.rs`) is a thin wrapper; the router lives here so
//! integration tests can boot the real app in-process (e.g. the agent
//! provisioning conformance test drives it with the `browserid-agent` SDK).

pub mod config;
pub mod device;
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
    // The headless access-cert mint is called cross-origin by the browserid
    // dialog (uncredentialed fetch), so it gets permissive CORS.
    let mint = Router::new()
        .route("/access/mint", post(device::access_mint))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::ACCEPT]),
        );
    Router::new()
        .route("/.well-known/browserid", get(routes::well_known))
        .route(
            "/session/from-presentation",
            post(routes::session_from_presentation),
        )
        .route("/whoami", get(routes::whoami))
        .route("/logout", post(routes::logout))
        .route("/claim_handle", post(routes::claim_handle))
        .route("/use_external", post(routes::use_external))
        // Device-cert model (DC conformance): session-authed batch device-cert
        // issuance; the headless mint is in the CORS-wrapped group below.
        .route("/device_cert", post(device::device_cert))
        // mingo-poster delegated signing (mingo-3f3i), same-origin + session-gated.
        .route("/poster/enable", post(poster::enable))
        .route("/poster/poll", post(poster::poll))
        .route("/poster/status", get(poster::status))
        .route("/poster/disable", post(poster::disable))
        .route("/poster/submit", post(poster::submit))
        .route("/admin/seed", post(routes::admin_seed))
        .route("/admin/delete-account", post(routes::admin_delete_account))
        .merge(mint)
        // Device-authorization popup: the browserid dialog opens it to obtain
        // the session identity's device+config certs first-party.
        .route_service("/device-authorize", file("device-authorize.html"))
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
