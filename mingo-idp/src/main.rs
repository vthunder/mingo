//! mingo.place primary BrowserID IdP.
//!
//! Serves the BrowserID primary-IdP surface for `mingo.place` (discovery doc,
//! `/provision`, `/auth`, cert issuance, handle store) plus the mingo-web SPA
//! same-origin. The broker (browserid.me) discovers this IdP via DNSSEC and
//! loads `/provision` in a hidden iframe to silently mint `<handle>@mingo.place`
//! certs once a mingo session exists. Router construction lives in the library
//! (`mingo_idp::build_router`) so tests can boot the app in-process.

use std::sync::Arc;

use mingo_idp::config::{load_or_generate_keypair, Config};
use mingo_idp::store::Store;
use mingo_idp::{build_router, AppState, Shared};

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
    if config.agent_provisioning {
        tracing::info!(quota = config.agent_quota, "agent provisioning enabled");
    }
    let store = Store::open(&config.db_path)?;

    let static_dir = config.static_dir.clone();
    let spa_dir = config.spa_dir.clone();
    let bind = config.bind.clone();

    let state: Shared = Arc::new(AppState { keypair, store, config });
    let app = build_router(state, &static_dir, &spa_dir);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("mingo-idp listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
