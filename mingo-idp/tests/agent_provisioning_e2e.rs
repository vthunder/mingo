//! Conformance test: mingo-idp's implementation of the delegation-chain
//! provisioning spec (browserid-ng `docs/specs/agent-provisioning-and-grant-api.md`
//! v0.2 §4.3-4.5) — mingo-idp as a *target IdP*. Key management + endorsement
//! live at the broker; here we stand in for the broker (a keypair mingo-idp
//! discovers via a mock `.well-known/browserid`) and build the user-signed
//! chain with core types, then drive `/provision/{mint,list,revoke}` over HTTP.

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use browserid_core::keys::{KeyPair, PublicKey};
use browserid_core::provisioning::{
    Constraint, Endorsement, ProvisioningCert, ProvisioningRequest, RequestBundle,
};
use browserid_core::{Assertion, BackedAssertion, Certificate, Warrant};
use chrono::Duration;
use mingo_idp::config::Config;
use mingo_idp::store::Store;
use mingo_idp::{build_router, AppState, Shared};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://rp.example.com";

/// A stand-in broker: a signing key served at `/.well-known/browserid` so
/// mingo-idp can discover it as its trusted broker.
struct Broker {
    keypair: KeyPair,
    domain: String,
}

async fn start_broker() -> Broker {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let domain = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let keypair = KeyPair::generate();
    let pubkey = keypair.public_key();

    let app = Router::new().route(
        "/.well-known/browserid",
        get(move || {
            let doc = browserid_core::discovery::SupportDocument::new(pubkey.clone());
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Broker { keypair, domain }
}

fn test_config(domain: String, broker_domain: String, quota: usize, enabled: bool) -> Config {
    Config {
        bind: String::new(),
        domain,
        app_origin: "https://mingo.place".into(),
        broker_domain,
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

struct Idp {
    base: String,
    domain: String,
    pubkey: PublicKey,
    keypair_seed: [u8; 32],
    state: Shared,
}

async fn start_idp(broker_domain: String, quota: usize, enabled: bool) -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let domain = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

    let keypair = KeyPair::generate();
    let pubkey = keypair.public_key();
    let seed = *keypair.secret_bytes();
    let state: Shared = Arc::new(AppState::new(
        keypair,
        Store::open_in_memory().unwrap(),
        test_config(domain.clone(), broker_domain, quota, enabled),
    ));

    let app = build_router(
        state.clone(),
        &PathBuf::from("/nonexistent"),
        &PathBuf::from("/nonexistent"),
    );
    tokio::spawn({
        let app = app.clone();
        async move {
            axum::serve(listener, app).await.unwrap();
        }
    });

    Idp { base: format!("http://{domain}"), domain, pubkey, keypair_seed: seed, state }
}

/// A delegator identity rooted at the IdP: an account with handle `handle`, a
/// U_cert we (the IdP) issue for `handle@<idp-domain>`, and its identity key.
struct Delegator {
    email: String,
    user_kp: KeyPair,
    user_cert: Certificate,
}

fn make_delegator(idp: &Idp, handle: &str) -> Delegator {
    // Register the human account + handle so account_id_for_handle resolves.
    let account = idp.state.store.find_or_create_account(&format!("{handle}@external.example")).unwrap();
    assert!(idp.state.store.set_handle(account.id, handle).unwrap());

    let idp_kp = KeyPair::from_seed(&idp.keypair_seed).unwrap();
    let email = format!("{handle}@{}", idp.domain);
    let user_kp = KeyPair::generate();
    let user_cert = Certificate::create(
        &idp.domain,
        &email,
        &user_kp.public_key(),
        Duration::hours(24),
        &idp_kp,
    )
    .unwrap();
    Delegator { email, user_kp, user_cert }
}

/// A registered provisioning credential: P key + the U_cert~P_cert delegation.
struct Credential {
    prov_kp: KeyPair,
    delegation: (Certificate, ProvisioningCert),
}

fn make_credential(delegator: &Delegator) -> Credential {
    // Broad constraint covering the names the tests mint, plus a pattern.
    make_credential_with(
        delegator,
        Constraint {
            names: ["attestor2", "x", "one", "two", "three", "taken"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            patterns: vec!["svc+*".into()],
        },
    )
}

fn make_credential_with(delegator: &Delegator, constraint: Constraint) -> Credential {
    let prov_kp = KeyPair::generate();
    let p_cert = ProvisioningCert::create(
        &delegator.email,
        &prov_kp.public_key(),
        constraint,
        Duration::days(90),
        &delegator.user_kp,
    )
    .unwrap();
    Credential {
        prov_kp,
        delegation: (delegator.user_cert.clone(), p_cert),
    }
}

/// Build a request bundle + a broker endorsement for it.
fn signed(
    broker: &Broker,
    idp_domain: &str,
    cred: &Credential,
    delegator_email: &str,
    request: ProvisioningRequest,
) -> (String, String) {
    let bundle = RequestBundle::new(cred.delegation.0.clone(), cred.delegation.1.clone(), request);
    let endorsement = Endorsement::create(
        &broker.domain,
        idp_domain,
        &bundle,
        delegator_email,
        &format!("https://{}", broker.domain),
        Duration::minutes(10),
        &broker.keypair,
    )
    .unwrap();
    (bundle.encoded().to_string(), endorsement.encoded().to_string())
}

async fn post(base: &str, path: &str, bundle: &str, endorsement: &str) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .json(&json!({ "request_bundle": bundle, "endorsement": endorsement }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or_default())
}

#[tokio::test]
async fn mint_assert_verify_full_chain() {
    let broker = start_broker().await;
    let idp = start_idp(broker.domain.clone(), 5, true).await;
    let delegator = make_delegator(&idp, "dan");
    let cred = make_credential(&delegator);

    let agent_kp = KeyPair::generate();
    let req =
        ProvisioningRequest::mint(&idp.domain, "attestor2", &agent_kp.public_key(), false, &cred.prov_kp)
            .unwrap();
    let (bundle, endorsement) = signed(&broker, &idp.domain, &cred, &delegator.email, req);

    let (status, body) = post(&idp.base, "/provision/mint", &bundle, &endorsement).await;
    assert_eq!(status, 200, "mint failed: {body}");
    assert_eq!(body["email"], format!("attestor2@{}", idp.domain));
    assert_eq!(body["subordinate_to"], delegator.email);

    // The minted cert is a typed agent certificate (v0.4), attributed to the
    // delegator, and verifies against the IdP's published key only as a
    // warrant-backed presentation.
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    assert!(cert.is_agent());
    assert_eq!(cert.agent_parent(), Some(delegator.email.as_str()));

    // Bare cert~assertion is fail-closed.
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &agent_kp).unwrap();
    let bare = format!("{}~{}", cert.encoded(), assertion.encoded());
    assert!(BackedAssertion::parse(&bare).is_err());

    // With the delegator-signed warrant it verifies, with attribution.
    // v0.5: the warrant's status ref is pinned to the cert's registrar (the
    // origin the broker's endorsement named), which the IdP stamped in.
    let registrar = cert.registrar().expect("minted cert names a registrar").to_string();
    let warrant = Warrant::create_with_status(
        &delegator.user_cert,
        &format!("attestor2@{}", idp.domain),
        AUDIENCE,
        Some(vec!["post".into()]),
        Duration::days(30),
        &delegator.user_kp,
        Some(browserid_core::StatusRef {
            uri: format!("{registrar}/.well-known/browserid-status"),
            idx: 1,
        }),
    )
    .unwrap();
    let verified = BackedAssertion::new_agent(cert, warrant, assertion)
        .verify(AUDIENCE, |_| Ok(idp.pubkey.clone()))
        .unwrap();
    assert_eq!(verified.email, format!("attestor2@{}", idp.domain));
    let attribution = verified.agent.expect("agent attribution");
    assert_eq!(attribution.parent, delegator.email);
    assert_eq!(attribution.scopes, vec!["post"]);

    // Idempotent re-mint with a rotated agent key.
    let rotated = KeyPair::generate();
    let req =
        ProvisioningRequest::mint(&idp.domain, "attestor2", &rotated.public_key(), false, &cred.prov_kp)
            .unwrap();
    let (bundle, endorsement) = signed(&broker, &idp.domain, &cred, &delegator.email, req);
    let (status, _) = post(&idp.base, "/provision/mint", &bundle, &endorsement).await;
    assert_eq!(status, 200);

    // List shows one identity attributed to the delegator.
    let req = ProvisioningRequest::list(&idp.domain, &cred.prov_kp).unwrap();
    let (bundle, endorsement) = signed(&broker, &idp.domain, &cred, &delegator.email, req);
    let (_, body) = post(&idp.base, "/provision/list", &bundle, &endorsement).await;
    let ids = body["identities"].as_array().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0]["parent_email"], delegator.email);
}

#[tokio::test]
async fn endorsement_and_chain_rejections() {
    let broker = start_broker().await;
    let idp = start_idp(broker.domain.clone(), 5, true).await;
    let delegator = make_delegator(&idp, "dan");
    let cred = make_credential(&delegator);

    let mint_req = || {
        ProvisioningRequest::mint(
            &idp.domain,
            "attestor2",
            &KeyPair::generate().public_key(),
            false,
            &cred.prov_kp,
        )
        .unwrap()
    };

    // No/garbage endorsement → 401.
    let bundle = RequestBundle::new(cred.delegation.0.clone(), cred.delegation.1.clone(), mint_req());
    let (status, _) = post(&idp.base, "/provision/mint", bundle.encoded(), "not-a-jws").await;
    assert_eq!(status, 401);

    // Endorsement signed by a rogue key (not the trusted broker) → 401.
    let rogue = KeyPair::generate();
    let bundle = RequestBundle::new(cred.delegation.0.clone(), cred.delegation.1.clone(), mint_req());
    let forged = Endorsement::create(
        &broker.domain,
        &idp.domain,
        &bundle,
        &delegator.email,
        &format!("https://{}", broker.domain),
        Duration::minutes(10),
        &rogue,
    )
    .unwrap();
    let (status, _) = post(&idp.base, "/provision/mint", bundle.encoded(), forged.encoded()).await;
    assert_eq!(status, 401);

    // Endorsement for a *different* bundle → 401 (hash binding).
    let (other_bundle, _) = signed(&broker, &idp.domain, &cred, &delegator.email, mint_req());
    let (_, endorsement) = signed(&broker, &idp.domain, &cred, &delegator.email, mint_req());
    let (status, _) = post(&idp.base, "/provision/mint", &other_bundle, &endorsement).await;
    // other_bundle's own endorsement would pass; this reuses a mismatched one.
    let (_, mismatched_endorsement) = signed(&broker, &idp.domain, &cred, &delegator.email, mint_req());
    let (status2, _) = post(&idp.base, "/provision/mint", &other_bundle, &mismatched_endorsement).await;
    assert!(status == 401 || status2 == 401, "hash-binding must reject a swapped endorsement");

    // A U_cert not issued by this IdP (foreign issuer) → 400.
    let foreign_idp = KeyPair::generate();
    let user_kp = KeyPair::generate();
    let foreign_cert = Certificate::create(
        "elsewhere.example",
        "dan@elsewhere.example",
        &user_kp.public_key(),
        Duration::hours(24),
        &foreign_idp,
    )
    .unwrap();
    let p_cert = ProvisioningCert::create("dan@elsewhere.example", &cred.prov_kp.public_key(), Constraint::names(["x"]), Duration::days(90), &user_kp).unwrap();
    let req = ProvisioningRequest::mint(&idp.domain, "x", &KeyPair::generate().public_key(), false, &cred.prov_kp).unwrap();
    let bundle = RequestBundle::new(foreign_cert, p_cert, req);
    let endorsement = Endorsement::create(&broker.domain, &idp.domain, &bundle, "dan@elsewhere.example", &format!("https://{}", broker.domain), Duration::minutes(10), &broker.keypair).unwrap();
    let (status, _) = post(&idp.base, "/provision/mint", bundle.encoded(), endorsement.encoded()).await;
    assert_eq!(status, 400, "foreign-rooted identity must be rejected");
}

#[tokio::test]
async fn reserved_names_quota_and_revocation() {
    let broker = start_broker().await;
    let idp = start_idp(broker.domain.clone(), 2, true).await;
    let delegator = make_delegator(&idp, "dan");
    let cred = make_credential(&delegator);

    let mint = |name: &str| {
        let req = ProvisioningRequest::mint(&idp.domain, name, &KeyPair::generate().public_key(), false, &cred.prov_kp).unwrap();
        signed(&broker, &idp.domain, &cred, &delegator.email, req)
    };

    // Reserved names (sys/sys-*) rejected for agents too → 400.
    for bad in ["sys", "sys-checkpointer", "admin"] {
        let (b, e) = mint(bad);
        let (status, _) = post(&idp.base, "/provision/mint", &b, &e).await;
        assert_eq!(status, 400, "reserved name {bad:?} must be rejected");
    }

    // Quota = 2.
    for name in ["one", "two"] {
        let (b, e) = mint(name);
        assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 200);
    }
    let (b, e) = mint("three");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 429);

    // Revoke "one" → re-mint fails 403, name not recycled.
    let req = ProvisioningRequest::revoke(&idp.domain, "one", &cred.prov_kp).unwrap();
    let (b, e) = signed(&broker, &idp.domain, &cred, &delegator.email, req);
    assert_eq!(post(&idp.base, "/provision/revoke", &b, &e).await.0, 200);
    let (b, e) = mint("one");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 403);

    // A human handle collision → 409.
    let other = idp.state.store.find_or_create_account("other@external.example").unwrap();
    assert!(idp.state.store.set_handle(other.id, "taken").unwrap());
    let (b, e) = mint("taken");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 409);
}

#[tokio::test]
async fn disabled_by_default() {
    let broker = start_broker().await;
    let idp = start_idp(broker.domain.clone(), 5, false).await;
    let delegator = make_delegator(&idp, "dan");
    let cred = make_credential(&delegator);
    let req = ProvisioningRequest::mint(&idp.domain, "x", &KeyPair::generate().public_key(), false, &cred.prov_kp).unwrap();
    let (b, e) = signed(&broker, &idp.domain, &cred, &delegator.email, req);
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 404);
}

#[tokio::test]
async fn constraint_and_reserve() {
    let broker = start_broker().await;
    let idp = start_idp(broker.domain.clone(), 10, true).await;
    let delegator = make_delegator(&idp, "dan");
    // Bound names + a subaddress pattern.
    let cred = make_credential_with(
        &delegator,
        Constraint { names: vec!["alpha".into(), "beta".into()], patterns: vec!["dan+*".into()] },
    );

    // Reserve pre-allocates the bound names (no per-request name).
    let req = ProvisioningRequest::reserve(&idp.domain, &cred.prov_kp).unwrap();
    let (b, e) = signed(&broker, &idp.domain, &cred, &delegator.email, req);
    assert_eq!(post(&idp.base, "/provision/reserve", &b, &e).await.0, 200);

    // A reserved name mints fine.
    let mint = |name: &str| {
        let r = ProvisioningRequest::mint(&idp.domain, name, &KeyPair::generate().public_key(), false, &cred.prov_kp).unwrap();
        signed(&broker, &idp.domain, &cred, &delegator.email, r)
    };
    let (b, e) = mint("alpha");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 200);

    // A subaddress under the pattern mints on demand (not reserved).
    let (b, e) = mint("dan+ci");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 200);

    // A name outside the constraint is refused (400).
    let (b, e) = mint("gamma");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 400);

    // A subaddress NOT under an allowed prefix is refused.
    let (b, e) = mint("bob+ci");
    assert_eq!(post(&idp.base, "/provision/mint", &b, &e).await.0, 400);
}
