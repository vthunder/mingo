//! HTTP tests for /agent_device_cert (merged-provisioning agent mode): the
//! session's handle may certify itself (as-you service) or a `+tag`
//! sub-address, over a supplied pubkey + broker-assigned holder; anything else
//! is refused.

use std::path::PathBuf;
use std::sync::Arc;

use browserid_core::device::{DeviceCert, Purpose};
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

async fn start() -> (String, Shared, KeyPair) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let idp_kp = KeyPair::generate();
    let idp_pub = KeyPair::from_seed(&idp_kp.secret_bytes()[..]).unwrap();
    let state: Shared = Arc::new(AppState::new(
        idp_kp,
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
    (base, state, idp_pub)
}

fn session_with_handle(state: &Shared, email: &str, handle: &str) -> String {
    let acct = state.store.find_or_create_account(email).unwrap();
    assert!(state.store.set_handle(acct.id, handle).unwrap());
    let (sid, _csrf) = state.store.create_session(acct.id).unwrap();
    format!("mingo_session={sid}")
}

async fn issue(
    base: &str,
    cookie: &str,
    agent_email: &str,
    pubkey: &str,
    holder: &str,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/agent_device_cert"))
        .header("cookie", cookie)
        .json(&json!({
            "agent_pubkey": { "algorithm": "Ed25519", "publicKey": pubkey },
            "agent_email": agent_email,
            "holder": holder,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn signs_self_and_subaddress_with_passthrough_holder() {
    let (base, state, idp_kp) = start().await;
    let cookie = session_with_handle(&state, "dan@example.com", "dan");
    let agent_kp = KeyPair::generate();
    let pubkey = agent_kp.public_key().to_base64();

    // As-you: the handle identity itself.
    let (status, body) = issue(&base, &cookie, "dan@mingo.place", &pubkey, "svcpfx.poster1").await;
    assert_eq!(status, 200, "{body}");
    let cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    cert.verify(&idp_kp.public_key()).expect("signed by mingo IdP key");
    assert_eq!(cert.purpose(), Purpose::Authentication);
    assert_eq!(cert.holder().as_str(), "svcpfx.poster1");
    assert_eq!(cert.claims().identities, vec!["dan@mingo.place".to_string()]);
    assert_eq!(cert.claims().iss, "mingo.place");

    // A +tag sub-address of the handle.
    let (status, body) = issue(&base, &cookie, "dan+claude@mingo.place", &pubkey, "agpfx.bot1").await;
    assert_eq!(status, 200, "{body}");
    let cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(cert.claims().identities, vec!["dan+claude@mingo.place".to_string()]);
}

#[tokio::test]
async fn refuses_foreign_identities_and_missing_holder() {
    let (base, state, _idp) = start().await;
    let cookie = session_with_handle(&state, "dan@example.com", "dan");
    let pubkey = KeyPair::generate().public_key().to_base64();

    // Someone else's handle.
    let (status, _) = issue(&base, &cookie, "alice@mingo.place", &pubkey, "svc.h").await;
    assert_eq!(status, 403);
    // Someone else's sub-address.
    let (status, _) = issue(&base, &cookie, "alice+bot@mingo.place", &pubkey, "svc.h").await;
    assert_eq!(status, 403);
    // Wrong domain.
    let (status, _) = issue(&base, &cookie, "dan@evil.test", &pubkey, "svc.h").await;
    assert_eq!(status, 400);
    // Missing holder — never minted here (broker-assigned only).
    let (status, _) = issue(&base, &cookie, "dan@mingo.place", &pubkey, "").await;
    assert_eq!(status, 400);
}
