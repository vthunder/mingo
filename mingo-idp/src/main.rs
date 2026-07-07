//! mingo.place primary BrowserID IdP.
//!
//! Serves the BrowserID primary-IdP surface for `mingo.place` (discovery doc,
//! `/provision`, `/auth`, cert issuance, handle store) plus the mingo-web SPA
//! same-origin. The broker (browserid.me) discovers this IdP via DNSSEC and
//! loads `/provision` in a hidden iframe to silently mint `<handle>@mingo.place`
//! certs once a mingo session exists.

mod config;
mod error;
mod routes;
mod store;
mod verify;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::services::{ServeDir, ServeFile};

use config::{load_or_generate_keypair, Config};
use routes::{AppState, Shared};
use store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mingo_idp=info,tower_http=warn".into()),
        )
        .init();

    let config = Config::from_env();
    let keypair = load_or_generate_keypair(&config.key_file)?;
    tracing::info!(
        domain = %config.domain,
        pubkey = %keypair.public_key().to_base64(),
        "mingo-idp key loaded (this must match _browserid.{} TXT)",
        config.domain
    );
    let store = Store::open(&config.db_path)?;

    let static_dir = config.static_dir.clone();
    let spa_dir = config.spa_dir.clone();
    let bind = config.bind.clone();

    let state: Shared = Arc::new(AppState { keypair, store, config });

    // IdP protocol assets (served at root so provision.html's relative refs resolve).
    let file = |name: &str| ServeFile::new(static_dir.join(name));
    let app = Router::new()
        .route("/.well-known/browserid", get(routes::well_known))
        .route("/session/from-assertion", post(routes::session_from_assertion))
        .route("/whoami", get(routes::whoami))
        .route("/logout", post(routes::logout))
        .route("/claim_handle", post(routes::claim_handle))
        .route("/cert_key", post(routes::cert_key))
        .route("/admin/seed", post(routes::admin_seed))
        .route("/admin/provision", post(routes::admin_provision))
        .route("/admin/delete-account", post(routes::admin_delete_account))
        .route_service("/provision", file("provision.html"))
        .route_service("/auth", file("auth.html"))
        .route_service("/provision.js", file("provision.js"))
        .route_service("/auth.js", file("auth.js"))
        .route_service("/provisioning_api.js", file("provisioning_api.js"))
        .route_service("/authentication_api.js", file("authentication_api.js"))
        // The mingo-web SPA, served same-origin as a fallback.
        .fallback_service(ServeDir::new(spa_dir).append_index_html_on_directories(true))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("mingo-idp listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
