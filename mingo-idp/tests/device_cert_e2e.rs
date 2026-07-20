//! Conformance test: mingo-idp's device-cert model (DC conformance) — the
//! equivalent of sandmill.org's reference IdP, in Rust. Drives:
//!   1. `POST /device_cert` (session-authed) — batch issuance of the USER
//!      authentication device cert + authorization config cert.
//!   2. `POST /access/mint` (headless) — via the real `browserid_agent::DeviceAgent`
//!      SDK: device cert -> access request -> access cert.
//!   3. Full RP-facing presentation: `access_cert~assertion~warrant~config_cert`
//!      assembled by the agent and verified with `AccessPresentation::verify`.

use std::path::PathBuf;
use std::sync::Arc;

use browserid_agent::{DeviceAgent, DeviceCredential};
use browserid_core::device::{
    AccessPresentation, DeviceCert, HolderMatcher, Purpose, Warrant as DeviceWarrant,
    WARRANT_VALIDITY_DAYS,
};
use browserid_core::keys::{KeyPair, PublicKey};
use chrono::Duration;
use mingo_idp::config::Config;
use mingo_idp::store::Store;
use mingo_idp::{build_router, AppState, Shared};
use serde_json::Value;

const AUDIENCE: &str = "https://rp.example.com";

fn test_config(domain: String) -> Config {
    Config {
        bind: String::new(),
        domain,
        app_origin: "https://mingo.place".into(),
        broker_domain: "127.0.0.1:0".into(),
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

struct Idp {
    base: String,
    domain: String,
    pubkey: PublicKey,
    state: Shared,
}

async fn start_idp() -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let domain = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let keypair = KeyPair::generate();
    let pubkey = keypair.public_key();
    let state: Shared = Arc::new(AppState::new(
        keypair,
        KeyPair::generate(),
        Store::open_in_memory().unwrap(),
        test_config(domain.clone()),
    ));
    let app = build_router(
        state.clone(),
        &PathBuf::from("/nonexistent"),
        &PathBuf::from("/nonexistent"),
    );
    tokio::spawn({
        let app = app.clone();
        async move { axum::serve(listener, app).await.unwrap() }
    });
    Idp {
        base: format!("http://{domain}"),
        domain,
        pubkey,
        state,
    }
}

/// Register an account with `handle` and open a session; return the session id
/// (the `mingo_session` cookie value).
fn session_for(idp: &Idp, handle: &str) -> String {
    let account = idp
        .state
        .store
        .find_or_create_account(&format!("{handle}@external.example"))
        .unwrap();
    assert!(idp.state.store.set_handle(account.id, handle).unwrap());
    idp.state.store.create_session(account.id).unwrap().0
}

#[tokio::test]
async fn device_cert_issuance_and_headless_mint_and_present() {
    let idp = start_idp().await;
    let sid = session_for(&idp, "dan");
    let identity = format!("dan@{}", idp.domain);
    let http = reqwest::Client::new();

    // Client-generated device + config keypairs.
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();

    // 1. Batch device-cert issuance (session-authed).
    let resp = http
        .post(format!("{}/device_cert", idp.base))
        .header("Cookie", format!("mingo_session={sid}"))
        .json(&serde_json::json!({
            "device_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "config_pubkey": { "algorithm": "Ed25519", "publicKey": config_kp.public_key().to_base64() },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "device_cert status {}", resp.status());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["success"], true);
    assert_eq!(v["identity"], identity);

    let device_cert = DeviceCert::parse(v["device_cert"].as_str().unwrap()).unwrap();
    let config_cert = DeviceCert::parse(v["config_cert"].as_str().unwrap()).unwrap();
    // Both signed by the IdP; correct purpose/holder/identity.
    device_cert.verify(&idp.pubkey).unwrap();
    config_cert.verify(&idp.pubkey).unwrap();
    assert_eq!(device_cert.purpose(), Purpose::Authentication);
    assert_eq!(config_cert.purpose(), Purpose::Authorization);
    // One holder per device slot: both certs carry it, and it's a dotted br id.
    assert_eq!(device_cert.holder(), config_cert.holder());
    assert!(device_cert.holder().as_str().starts_with("br"));
    assert!(device_cert.authorizes_identity(&identity));

    // Session-less issuance is refused.
    let unauth = http
        .post(format!("{}/device_cert", idp.base))
        .json(&serde_json::json!({
            "device_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "config_pubkey": { "algorithm": "Ed25519", "publicKey": config_kp.public_key().to_base64() },
        }))
        .send()
        .await
        .unwrap();
    assert!(!unauth.status().is_success());

    // 2. Headless mint via the DeviceAgent SDK.
    let credential = DeviceCredential {
        device_key: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            device_kp.secret_bytes(),
        ),
        agent_device_cert: device_cert.encoded().to_string(),
        idp: idp.base.clone(),
    };
    let mut agent = DeviceAgent::new(credential).unwrap();
    assert_eq!(agent.email(), identity);
    agent.mint().await.expect("headless access-cert mint");

    // 3. A config-cert-signed warrant for the audience (the principal's grant).
    // Grant the exact holder the IdP minted (an `<id>` matcher covering it).
    let warrant = DeviceWarrant::create(
        &identity,
        HolderMatcher::new(device_cert.holder().as_str()).unwrap(),
        AUDIENCE,
        vec!["post".into()],
        Duration::days(WARRANT_VALIDITY_DAYS),
        &config_kp,
        None,
    )
    .unwrap();
    agent
        .add_grant(warrant.encoded(), config_cert.encoded())
        .unwrap();

    // 4. Assemble + verify the RP-facing presentation.
    let encoded = agent.assertion_for(AUDIENCE).await.unwrap();
    let presentation = AccessPresentation::parse(&encoded).unwrap();
    let idp_pubkey = idp.pubkey.clone();
    let verified = presentation
        .verify(AUDIENCE, |iss| {
            assert_eq!(iss, idp.domain);
            Ok(idp_pubkey.clone())
        })
        .unwrap();
    assert_eq!(verified.email, identity);
    assert_eq!(verified.holder.as_str(), device_cert.holder().as_str());
    assert_eq!(verified.scopes, vec!["post".to_string()]);
    assert_eq!(verified.issuer, idp.domain);
}
