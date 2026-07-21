//! HTTP tests for the device-model mingo-poster (agent/D phase): enable raises
//! a merged as-you provisioning request at the broker (stubbed here), poll
//! picks up device cert + warrant tail in one delivery and stores the
//! credential, status/disable/submit pin their contracts.

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::post;
use axum::{Json, Router};
use browserid_core::device::{DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
use browserid_core::keys::KeyPair;
use chrono::Duration;
use mingo_idp::config::Config;
use mingo_idp::store::Store;
use mingo_idp::{build_router, AppState, Shared};
use serde_json::{json, Value};

const USER: &str = "dan@example.com";
const AUDIENCE: &str = "sbo+raw://avail:turing:506/";

fn test_config(domain: String, broker_domain: String) -> Config {
    Config {
        bind: String::new(),
        domain,
        app_origin: "https://mingo.place".into(),
        broker_domain,
        key_file: PathBuf::from("/nonexistent"),
        poster_key_file: PathBuf::from("/nonexistent"),
        sbo_db_audience: AUDIENCE.into(),
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
async fn start_with_broker(broker_domain: String) -> (String, Shared) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state: Shared = Arc::new(AppState::new(
        KeyPair::generate(),
        KeyPair::generate(),
        Store::open_in_memory().unwrap(),
        test_config("mingo.place".into(), broker_domain),
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

/// A stub broker: /agent-provision/request returns a pairing; /agent-provision/poll
/// returns "completed" with a credential + grant built from the request's pubkey.
async fn start_stub_broker() -> (String, KeyPair) {
    let idp_kp = KeyPair::generate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kp = KeyPair::from_seed(&idp_kp.secret_bytes()[..]).unwrap();

    let request = post(|Json(body): Json<Value>| async move {
        // Remember the pubkey by encoding it into the code (stateless stub).
        let pubkey = body["provisioning_pubkey"]["publicKey"].as_str().unwrap().to_string();
        Json(json!({
            "success": true,
            "code": format!("apr_{pubkey}"),
            "user_code": "AAAA-2222",
            "verification_uri": "https://broker.test/account",
            "verification_uri_complete": format!("https://broker.test/account?provision=apr_{pubkey}"),
            "fingerprint": "AA-BB-CC",
            "expires_in": 900,
            "interval": 5,
        }))
    });
    let poll = post(move |Json(body): Json<Value>| async move {
        let code = body["code"].as_str().unwrap_or_default().to_string();
        let pubkey = code.strip_prefix("apr_").unwrap_or_default();
        let device_pub = browserid_core::PublicKey::from_base64(pubkey).unwrap();
        let holder = Holder::new("svcpfx.poster1").unwrap();
        let device_cert = DeviceCert::create(
            "broker.test", &device_pub, Purpose::Authentication, holder,
            vec![USER.to_string()], Duration::days(90), &idp_kp, None,
        )
        .unwrap();
        let config_kp = KeyPair::generate();
        let config_cert = DeviceCert::create(
            "broker.test", &config_kp.public_key(), Purpose::Authorization,
            Holder::new("br.main").unwrap(), vec![USER.to_string()],
            Duration::days(90), &idp_kp, None,
        )
        .unwrap();
        let warrant = Warrant::create(
            USER, HolderMatcher::new("svcpfx.poster1").unwrap(), AUDIENCE,
            vec!["action:post".into()], Duration::days(90), &config_kp, None,
        )
        .unwrap();
        Json(json!({
            "status": "completed",
            "credential": {
                "device_cert": device_cert.encoded(),
                "idp": "https://broker.test",
                "identity": USER,
            },
            "grants": [{ "audience": AUDIENCE, "warrant": format!("{}~{}", warrant.encoded(), config_cert.encoded()) }],
        }))
    });
    let app = Router::new()
        .route("/agent-provision/request", request)
        .route("/agent-provision/poll", poll);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("127.0.0.1:{}", addr.port()), kp)
}

#[tokio::test]
async fn status_is_available_but_disabled_before_enable() {
    let (base, state) = start_with_broker("broker.test".into()).await;
    let (_id, cookie) = session_cookie(&state, USER);
    let client = reqwest::Client::new();
    let body: Value = client
        .get(format!("{base}/poster/status"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["enabled"], false, "{body}");
    assert_eq!(body["available"], true, "{body}");
}

#[tokio::test]
async fn submit_without_enable_is_a_clear_400() {
    let (base, state) = start_with_broker("broker.test".into()).await;
    let (_id, cookie) = session_cookie(&state, USER);
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/poster/submit"))
        .header("cookie", &cookie)
        .json(&json!({ "path": "/u/dan/", "id": "n1", "schema": "post.v1", "payload": [123, 125] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn enable_then_poll_stores_the_device_credential() {
    let (broker_domain, _broker_kp) = start_stub_broker().await;
    let (base, state) = start_with_broker(broker_domain).await;
    let (account_id, cookie) = session_cookie(&state, USER);
    let client = reqwest::Client::new();

    // Enable: raises the as-you request at the (stub) broker.
    let body: Value = client
        .post(format!("{base}/poster/enable"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uri = body["verification_uri"].as_str().unwrap();
    assert!(uri.contains("provision="), "one-approval URL: {uri}");
    let pending = state.store.get_poster_pending(account_id).unwrap().unwrap();
    assert!(pending.device_seed.is_some(), "pending row holds the device seed");

    // Poll: the stub broker approves instantly; one pickup stores everything.
    let body: Value = client
        .post(format!("{base}/poster/poll"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "approved", "{body}");
    let w = state.store.get_poster_warrant(account_id).unwrap().unwrap();
    assert_eq!(w.user_email, USER);
    assert_eq!(w.audience, AUDIENCE);
    assert_eq!(w.holder.as_deref(), Some("svcpfx.poster1"));
    assert_eq!(w.idp.as_deref(), Some("https://broker.test"));
    assert!(w.warrant.contains('~'), "stored grant is warrant~config_cert");
    assert!(w.device_seed.is_some() && w.device_cert.is_some());
    assert!(state.store.get_poster_pending(account_id).unwrap().is_none());

    // Status flips to enabled.
    let body: Value = client
        .get(format!("{base}/poster/status"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["enabled"], true, "{body}");

    // Disable forgets it.
    let resp = client
        .post(format!("{base}/poster/disable"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(state.store.get_poster_warrant(account_id).unwrap().is_none());
}
