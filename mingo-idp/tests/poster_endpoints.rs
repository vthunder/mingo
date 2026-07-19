//! HTTP smoke test for the mingo-poster endpoints (mingo-3f3i). The poster is
//! TEMPORARILY DISABLED during the device-cert migration (see src/poster.rs);
//! these tests pin the disabled contract: /poster/status reports
//! available:false (so the SPA hides the affordance) and the mutating
//! endpoints answer 503 with a clear reason.

use std::path::PathBuf;
use std::sync::Arc;

use browserid_core::keys::KeyPair;
use mingo_idp::config::Config;
use mingo_idp::store::Store;
use mingo_idp::{build_router, AppState, Shared};
use serde_json::{json, Value};

fn test_config(domain: String) -> Config {
    Config {
        bind: String::new(),
        domain,
        app_origin: "https://mingo.place".into(),
        broker_domain: "browserid.me".into(),
        key_file: PathBuf::from("/nonexistent"),
        poster_key_file: PathBuf::from("/nonexistent"),
        sbo_db_audience: "sbo+raw://avail:turing:506/".into(),
        daemon_url: "http://127.0.0.1:0".into(),
        db_path: PathBuf::from("/nonexistent"),
        static_dir: PathBuf::from("/nonexistent"),
        spa_dir: PathBuf::from("/nonexistent"),
        admin_token: None,
        allow_http_verify: true,
        agent_provisioning: false,
        agent_quota: 5,
    }
}

/// Boot the router on a loopback port; return (base_url, shared_state).
async fn start() -> (String, Shared) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state: Shared = Arc::new(AppState::new(
        KeyPair::generate(),
        KeyPair::generate(),
        Store::open_in_memory().unwrap(),
        test_config("mingo.place".into()),
    ));
    let app = build_router(
        state.clone(),
        &PathBuf::from("static"),
        &PathBuf::from("../mingo-web"),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, state)
}

/// Seed an account + session directly and return its cookie value.
fn session_cookie(state: &Shared, email: &str) -> (i64, String) {
    let acct = state.store.find_or_create_account(email).unwrap();
    let (sid, _csrf) = state.store.create_session(acct.id).unwrap();
    (acct.id, format!("mingo_session={sid}"))
}

#[tokio::test]
async fn status_reports_unavailable() {
    let (base, _state) = start().await;
    let client = reqwest::Client::new();
    let body: Value = client
        .get(format!("{base}/poster/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["enabled"], false);
    assert_eq!(body["available"], false);
    assert!(body["reason"].as_str().unwrap_or("").contains("device-cert"));
}

#[tokio::test]
async fn mutating_endpoints_are_disabled() {
    let (base, state) = start().await;
    let (_id, cookie) = session_cookie(&state, "dan@example.com");
    let client = reqwest::Client::new();
    for path in ["/poster/enable", "/poster/poll", "/poster/disable", "/poster/submit"] {
        let resp = client
            .post(format!("{base}{path}"))
            .header("cookie", &cookie)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503, "{path} must report the migration");
        let body: Value = resp.json().await.unwrap();
        assert!(
            body["error"].as_str().unwrap_or("").contains("device-cert"),
            "{path}: {body}"
        );
    }
}
