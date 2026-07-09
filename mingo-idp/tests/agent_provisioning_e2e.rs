//! Conformance test: mingo-idp's implementation of the agent provisioning
//! spec (browserid-ng `docs/specs/agent-provisioning-and-grant-api.md` §4),
//! driven end-to-end over real HTTP by the reference client — the
//! `browserid-agent` SDK. If the SDK works against browserid-broker and this
//! IdP interchangeably, federation (spec §7) holds.

use std::path::PathBuf;
use std::sync::Arc;

use browserid_agent::{AgentError, AgentIdentity};
use browserid_core::keys::{KeyPair, PublicKey};
use browserid_core::{Assertion, BackedAssertion, Certificate};
use mingo_idp::config::Config;
use mingo_idp::store::Store;
use mingo_idp::{build_router, AppState, Shared};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://rp.example.com";

fn test_config(domain: String, quota: usize, enabled: bool) -> Config {
    Config {
        bind: String::new(),
        domain,
        app_origin: "https://mingo.place".into(),
        broker_domain: "browserid.me".into(),
        key_file: PathBuf::from("/nonexistent"),
        db_path: PathBuf::from("/nonexistent"),
        static_dir: PathBuf::from("/nonexistent"),
        spa_dir: PathBuf::from("/nonexistent"),
        admin_token: None,
        allow_http_verify: true,
        agent_provisioning: enabled,
        agent_quota: quota,
    }
}

/// Boot the real IdP on 127.0.0.1:0. Returns (base_url, idp pubkey, state).
async fn start_idp(quota: usize, enabled: bool) -> (String, PublicKey, Shared) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let domain = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

    let keypair = KeyPair::generate();
    let idp_pub = keypair.public_key();
    let state: Shared = Arc::new(AppState {
        keypair,
        store: Store::open_in_memory().unwrap(),
        config: test_config(domain.clone(), quota, enabled),
    });

    let app = build_router(
        state.clone(),
        &PathBuf::from("/nonexistent"),
        &PathBuf::from("/nonexistent"),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{domain}"), idp_pub, state)
}

/// The one human-in-the-loop moment, done in-process (the browser sign-in leg
/// is not under test): an account + session, then an API key over HTTP.
async fn mint_api_key(base: &str, state: &Shared, human_email: &str) -> String {
    let account = state.store.find_or_create_account(human_email).unwrap();
    let (sid, csrf) = state.store.create_session(account.id).unwrap();

    let body: Value = reqwest::Client::new()
        .post(format!("{base}/agent_keys"))
        .header("cookie", format!("mingo_session={sid}"))
        .json(&json!({ "csrf": csrf, "name": "ci-key" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["success"], true, "key mint failed: {body}");
    let key = body["api_key"].as_str().unwrap().to_string();
    assert!(key.starts_with("bidk_"));
    key
}

#[tokio::test]
async fn sdk_conformance_full_flow() {
    let (base, idp_pub, state) = start_idp(5, true).await;
    let api_key = mint_api_key(&base, &state, "human@example.com").await;

    // Provision via the SDK — the same client that works against the broker.
    let mut agent = AgentIdentity::provision(&base, &api_key, Some("attestor2"))
        .await
        .unwrap();
    assert!(agent.email().starts_with("attestor2@127.0.0.1:"));

    // Locally signed assertion verifies against the IdP key.
    let assertion = agent.assertion_for(AUDIENCE).await.unwrap();
    let email = BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(idp_pub.clone()))
        .unwrap();
    assert_eq!(email, agent.email());

    // Explicit re-mint works.
    agent.remint().await.unwrap();

    // Idempotent re-provision: same name, fresh SDK instance, same account.
    let again = AgentIdentity::provision(&base, &api_key, Some("attestor2"))
        .await
        .unwrap();
    assert_eq!(again.email(), agent.email());

    // Attribution is recorded and listed (spec §4.4 shape).
    let body: Value = reqwest::Client::new()
        .get(format!("{base}/agent/identities"))
        .bearer_auth(&api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let identities = body["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["parent_email"], "human@example.com");
    assert_eq!(identities[0]["active"], true);

    // Persistence round-trip, then revoke; re-mint via the restored copy → 403.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.json");
    agent.save(&path).unwrap();
    let mut restored = AgentIdentity::load(&path, &api_key).unwrap();

    agent.revoke().await.unwrap();
    match restored.remint().await {
        Err(AgentError::Idp { status: 403, .. }) => {}
        other => panic!("expected 403 after revocation, got {other:?}"),
    }
    // Revocation sticks through the idempotent-create path too.
    match AgentIdentity::provision(&base, &api_key, Some("attestor2")).await {
        Err(AgentError::Idp { status: 403, .. }) => {}
        other => panic!("expected 403 re-creating revoked name, got {other:?}"),
    }
}

#[tokio::test]
async fn name_rules_reserved_and_collisions() {
    let (base, _, state) = start_idp(5, true).await;
    let api_key = mint_api_key(&base, &state, "human@example.com").await;

    // sys/sys-* reservations hold for agents (privileged on-chain principals
    // must not be mintable via the agent onramp).
    for bad in ["sys", "sys-checkpointer", "admin", "has space"] {
        match AgentIdentity::provision(&base, &api_key, Some(bad)).await {
            Err(AgentError::Idp { status: 400, .. }) => {}
            other => panic!("expected 400 for name {bad:?}, got {other:?}"),
        }
    }

    // A human handle blocks the agent name (shared namespace) → 409.
    let other = state.store.find_or_create_account("other@example.com").unwrap();
    assert!(state.store.set_handle(other.id, "dan").unwrap());
    match AgentIdentity::provision(&base, &api_key, Some("dan")).await {
        Err(AgentError::Idp { status: 409, .. }) => {}
        other => panic!("expected 409 for human-handle collision, got {other:?}"),
    }

    // And an agent name blocks the human handle.
    AgentIdentity::provision(&base, &api_key, Some("bot")).await.unwrap();
    assert!(!state.store.set_handle(other.id, "bot").unwrap());

    // Omitted name → generated agent-xxxxxxxx.
    let generated = AgentIdentity::provision(&base, &api_key, None).await.unwrap();
    assert!(generated.email().starts_with("agent-"));
}

#[tokio::test]
async fn quota_and_auth_rejections() {
    let (base, _, state) = start_idp(2, true).await;
    let api_key = mint_api_key(&base, &state, "human@example.com").await;

    AgentIdentity::provision(&base, &api_key, Some("one")).await.unwrap();
    AgentIdentity::provision(&base, &api_key, Some("two")).await.unwrap();
    match AgentIdentity::provision(&base, &api_key, Some("three")).await {
        Err(AgentError::Idp { status: 429, .. }) => {}
        other => panic!("expected 429 over quota, got {other:?}"),
    }

    // Bad bearer key → 401.
    match AgentIdentity::provision(&base, "bidk_not-real", None).await {
        Err(AgentError::Idp { status: 401, .. }) => {}
        other => panic!("expected 401 for bad key, got {other:?}"),
    }

    // The key must not see or touch human identities (visibility rule):
    // /agent/cert against the human's handle email → 404.
    let human = state.store.find_or_create_account("h2@example.com").unwrap();
    assert!(state.store.set_handle(human.id, "danny").unwrap());
    let domain = base.strip_prefix("http://").unwrap();
    let kp = KeyPair::generate();
    let resp = reqwest::Client::new()
        .post(format!("{base}/agent/cert"))
        .bearer_auth(&api_key)
        .json(&json!({
            "email": format!("danny@{domain}"),
            "pubkey": { "algorithm": "Ed25519", "publicKey": kp.public_key().to_base64() },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn disabled_by_default_and_csrf() {
    // Disabled: every agent surface 404s (indistinguishable from unknown).
    let (base, _, state) = start_idp(5, false).await;
    match AgentIdentity::provision(&base, "bidk_whatever", None).await {
        Err(AgentError::Idp { status: 404, .. }) => {}
        other => panic!("expected 404 when disabled, got {other:?}"),
    }
    let account = state.store.find_or_create_account("h@example.com").unwrap();
    let (sid, csrf) = state.store.create_session(account.id).unwrap();
    let resp = reqwest::Client::new()
        .post(format!("{base}/agent_keys"))
        .header("cookie", format!("mingo_session={sid}"))
        .json(&json!({ "csrf": csrf, "name": "k" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    // Enabled: wrong CSRF → 403; no session → 401.
    let (base, _, state) = start_idp(5, true).await;
    let account = state.store.find_or_create_account("h@example.com").unwrap();
    let (sid, _csrf) = state.store.create_session(account.id).unwrap();
    let resp = reqwest::Client::new()
        .post(format!("{base}/agent_keys"))
        .header("cookie", format!("mingo_session={sid}"))
        .json(&json!({ "csrf": "wrong", "name": "k" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let resp = reqwest::Client::new()
        .post(format!("{base}/agent_keys"))
        .json(&json!({ "csrf": "x", "name": "k" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

/// The trustless contract end to end: a cert minted through /agent/cert for a
/// rotated keypair verifies under the IdP's published key.
#[tokio::test]
async fn remint_certifies_rotated_keypair() {
    let (base, idp_pub, state) = start_idp(5, true).await;
    let api_key = mint_api_key(&base, &state, "human@example.com").await;

    let agent = AgentIdentity::provision(&base, &api_key, Some("rotator")).await.unwrap();
    let email = agent.email().to_string();

    let rotated = KeyPair::generate();
    let body: Value = reqwest::Client::new()
        .post(format!("{base}/agent/cert"))
        .bearer_auth(&api_key)
        .json(&json!({
            "email": email,
            "pubkey": { "algorithm": "Ed25519", "publicKey": rotated.public_key().to_base64() },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["success"], true);

    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    let assertion = Assertion::create(AUDIENCE, chrono::Duration::minutes(5), &rotated).unwrap();
    let verified = BackedAssertion::new(cert, assertion)
        .verify(AUDIENCE, |_| Ok(idp_pub.clone()))
        .unwrap();
    assert_eq!(verified, email);
}
