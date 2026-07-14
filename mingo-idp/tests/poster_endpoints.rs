//! HTTP smoke test for the mingo-poster endpoints (mingo-3f3i): routing,
//! session gating, and store integration. The enable/poll/submit paths call
//! out to the registrar + daemon, so those are exercised live; here we cover
//! everything reachable without external services — status gating and the
//! "not enabled" submit guard.

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
async fn status_requires_a_session() {
    let (base, _state) = start().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/poster/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no session → unauthorized");
}

#[tokio::test]
async fn status_reflects_stored_warrant() {
    let (base, state) = start().await;
    let (account_id, cookie) = session_cookie(&state, "dan@example.com");
    let http = reqwest::Client::new();

    // No warrant yet → disabled.
    let body: Value = http
        .get(format!("{base}/poster/status"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["enabled"], false);

    // A live warrant → enabled; an expired one → disabled.
    let future = chrono::Utc::now().timestamp() + 3600;
    state
        .store
        .set_poster_warrant(account_id, "dan@example.com", "jws", "sbo://mingo", future)
        .unwrap();
    let body: Value = http
        .get(format!("{base}/poster/status"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["expires_at"], future);

    state
        .store
        .set_poster_warrant(account_id, "dan@example.com", "jws", "sbo://mingo", 1)
        .unwrap();
    let body: Value = http
        .get(format!("{base}/poster/status"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["enabled"], false, "expired warrant is not enabled");
}

#[tokio::test]
async fn submit_without_a_warrant_is_refused() {
    let (base, state) = start().await;
    let (_id, cookie) = session_cookie(&state, "dan@example.com");
    let resp = reqwest::Client::new()
        .post(format!("{base}/poster/submit"))
        .header("cookie", &cookie)
        .json(&json!({
            "path": "/communities/hub/spaces/general/",
            "id": "note-1",
            "schema": "post.v1",
            "payload": [123, 125],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "not enabled → bad request");
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("not enabled"),
        "{body}"
    );
}

#[tokio::test]
async fn poll_without_pending_is_none() {
    let (base, state) = start().await;
    let (_id, cookie) = session_cookie(&state, "dan@example.com");
    let body: Value = reqwest::Client::new()
        .post(format!("{base}/poster/poll"))
        .header("cookie", &cookie)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "none");
}
