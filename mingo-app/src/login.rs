//! `mingo login` / `whoami` / `post` — the CLI's authenticated identity,
//! on the browserid **holder model** (device-cert protocol).
//!
//! The CLI is an **as-you agent**: one merged provisioning request at the
//! broker (`/agent-provision/request`, no handle) asks to hold the user's
//! identity ITSELF — writes stay owned by and attributed to the user —
//! isolated by a broker-assigned holder in their `agents` namespace, plus a
//! warrant grant at the mingo SBO db in the SAME approval. The user opens one
//! URL, approves once, and a single poll returns the device cert AND the
//! `warrant~config_cert` grant (browserid-agent's `request_provision`/`wait`).
//!
//! Posting mints a short-lived access cert headlessly (`DeviceAgent`), signs
//! the SBO envelope with the SAME access key (envelope-key binding), and
//! attaches the 4-object presentation as `Auth-Cert` — mirroring
//! `mingo-idp/src/poster.rs::submit`. There is no `as:` scope and no separate
//! agent identity: attribution lands on the user directly, and the classic
//! `AgentCredential`/`AgentIdentity` chain is gone.
//!
//! Storage: `~/.mingo/device-credential.json` (see [`crate::device_login`]).
//! The classic `credential.json`/`identity.json` files are ignored.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use browserid_agent::{request_provision, GrantRequest};
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;
use serde::Deserialize;

use crate::device_login::{StoredDeviceLogin, StoredGrant};

/// Production broker/registrar (hosts the merged-provisioning approval page).
pub const DEFAULT_BROKER: &str = "https://browserid.me";
/// The mingo SBO database a warrant must be audienced to. A **bare**
/// `sbo+raw://chain:appId/` reference (NOT `sbo://…` — DNS audiences are rejected
/// by `audience_identifies_db`). Matches `MINGO_SBO_DB_AUDIENCE` (mingo-idp) and
/// the daemon's `DbIdentity.uri` for the live repo (chain `avail`, appId 506).
pub const DEFAULT_AUDIENCE: &str = "sbo+raw://avail:turing:506/";
/// Live SBO daemon (reads + `/v1/submit`).
pub const DEFAULT_DAEMON: &str = "https://da.sandmill.org";

// ===========================================================================
// Local credential storage (~/.mingo, 0600)
// ===========================================================================

pub(crate) fn mingo_home() -> Result<PathBuf> {
    let home = std::env::var("MINGO_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".mingo")))
        .ok_or_else(|| anyhow!("cannot locate home dir (set $HOME or $MINGO_HOME)"))?;
    Ok(home)
}

/// Write `contents` to `path` with 0600 perms, creating the parent dir (0700).
pub(crate) fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    use std::io::Write as _;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ===========================================================================
// Warrant scopes
// ===========================================================================

/// Scope preset requested for the warrant. `Post` is the normal-user default;
/// `Admin` adds `action:delete` — the daemon / on-chain policy still gates
/// what admin can actually do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopePreset {
    Post,
    Admin,
}

impl ScopePreset {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "post" | "action:post" => Ok(Self::Post),
            "admin" => Ok(Self::Admin),
            other => bail!("unknown scope preset '{other}' (expected 'post' or 'admin')"),
        }
    }
}

/// The warrant scopes the CLI requests. Mirrors mingo-idp's poster
/// `default_scopes`, minus `as:` (the holder model attributes to the user
/// directly — the warrant identifier IS them) and without a per-user path
/// (the identity isn't known until the user approves; ownership checks bound
/// writes to them regardless).
pub fn scopes_for(preset: ScopePreset) -> Vec<String> {
    let mut scopes = vec![
        "action:post".to_string(),
        "schema:post.v1".to_string(),
        "schema:comment.v1".to_string(),
        "schema:reaction.v1".to_string(),
        "path:/communities/**".to_string(),
        "path:/u/**".to_string(),
    ];
    if preset == ScopePreset::Admin {
        scopes.push("action:delete".to_string());
    }
    scopes
}

// ===========================================================================
// `mingo login`
// ===========================================================================

pub struct LoginArgs {
    pub broker: String,
    pub idp: Option<String>,
    pub audience: String,
    pub scope: String,
    /// Optional named-agent handle (e.g. `dan+claude`). Default (`None`) is an
    /// as-you agent: the CLI holds the approving identity itself.
    pub handle: Option<String>,
}

async fn login_async(args: &LoginArgs) -> Result<()> {
    let preset = ScopePreset::parse(&args.scope)?;

    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(hostname_fallback)
        .unwrap_or_else(|| "cli".to_string());
    let label = format!("mingo CLI on {hostname}");
    let scopes = scopes_for(preset);
    let grants = vec![GrantRequest { audience: args.audience.clone(), scopes: scopes.clone() }];

    println!("Requesting authorization (one approval covers identity + access)…");
    println!("  audience: {}", args.audience);
    for s in &scopes {
        println!("    scope: {s}");
    }
    let pending = request_provision(
        &args.broker,
        args.handle.as_deref(),
        Some("agents"),
        &grants,
        Some(&label),
    )
    .await
    .map_err(|e| anyhow!("starting provisioning at {}: {e}", args.broker))?;

    println!("\nTo authorize this CLI, open:\n");
    println!("    {}\n", pending.verification_uri_complete);
    println!(
        "  or go to {} and enter code:  {}",
        pending.verification_uri, pending.user_code
    );
    println!("  confirm the key fingerprint matches:  {}\n", pending.fingerprint);
    println!("Waiting for approval (expires in {}s)…", pending.expires_in_seconds);

    let provisioned = pending
        .wait()
        .await
        .map_err(|e| anyhow!("provisioning: {e}"))?;

    let mut credential = provisioned.credential;
    if let Some(idp) = &args.idp {
        credential.idp = idp.clone();
    }
    let grants: Vec<StoredGrant> = provisioned
        .grants
        .iter()
        .filter_map(|(audience, tail)| {
            let (warrant, config_cert) = tail.split_once('~')?;
            Some(StoredGrant {
                audience: audience.clone(),
                warrant: warrant.to_string(),
                config_cert: config_cert.to_string(),
            })
        })
        .collect();
    if grants.is_empty() {
        bail!("approval delivered no warrant grant — re-run `mingo login`");
    }

    let mut stored = StoredDeviceLogin::load().unwrap_or_default();
    stored.credential = Some(credential);
    stored.grants = grants;
    stored.save()?;

    // Rehydrate to report (also validates what we stored).
    let agent = stored.agent()?;
    println!("\n✓ logged in as {}", agent.email());
    println!("  idp:        {}", stored.credential.as_ref().map(|c| c.idp.as_str()).unwrap_or("?"));
    for g in &stored.grants {
        println!("  grant:      {}", g.audience);
    }
    println!("\nTry:  mingo whoami");
    Ok(())
}

pub fn login(args: &LoginArgs) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("starting async runtime")?
        .block_on(login_async(args))
}

/// Best-effort hostname without pulling a dependency: read /etc/hostname.
fn hostname_fallback() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ===========================================================================
// `mingo whoami`
// ===========================================================================

pub fn whoami() -> Result<()> {
    crate::device_login::whoami()
}

// ===========================================================================
// Signing writes as the logged-in user (device presentation)
// ===========================================================================

/// One SBO write signed as the logged-in user. Under the holder model the
/// warrant identifier IS the user, so `owner` is them directly (no `as:`).
pub struct WriteSpec {
    pub action: Action,
    pub path: String,
    pub id: String,
    pub schema: String,
    pub content_type: String,
    pub payload: Vec<u8>,
    /// The object owner — the logged-in user.
    pub owner: String,
    pub hlc: Option<String>,
}

/// Sign `spec` as the logged-in user: mint an access cert at the credential's
/// IdP, sign the envelope with the SAME access key (envelope-key binding), and
/// attach the 4-object presentation as `Auth-Cert`. `Auth-Evidence` is omitted
/// so the daemon resolves the issuer's on-chain `/sys/dnssec` proof (same
/// choice mingo-poster makes).
pub async fn sign_as_logged_in_user(
    stored: &StoredDeviceLogin,
    audience: &str,
    spec: &WriteSpec,
) -> Result<Vec<u8>> {
    let mut agent = stored.agent()?;
    if agent.warranted_audiences().iter().all(|a| *a != audience) {
        bail!("no grant held for {audience} — re-run `mingo login`");
    }
    let (presentation, access_seed) = agent
        .assertion_with_access_seed(audience)
        .await
        .map_err(|e| anyhow!("minting access cert: {e}"))?;
    assemble_device_wire(&access_seed, &presentation, spec)
}

/// Pure envelope assembly (unit-testable): sign the SBO message with the
/// ACCESS key (`access_seed`) and attach the presentation as `Auth-Cert` —
/// the daemon's device-attribution path requires the envelope signer key to
/// equal the presentation's access-cert key.
fn assemble_device_wire(
    access_seed: &[u8; 32],
    presentation: &str,
    spec: &WriteSpec,
) -> Result<Vec<u8>> {
    let key = SigningKey::from_bytes(access_seed);
    let content_hash = ContentHash::sha256(&spec.payload);
    let mut msg = Message {
        action: spec.action.clone(),
        path: Path::parse(&spec.path).map_err(|e| anyhow!("bad path '{}': {e}", spec.path))?,
        id: Id::new(&spec.id).map_err(|e| anyhow!("bad id '{}': {e}", spec.id))?,
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]), // overwritten by sign()
        content_type: Some(spec.content_type.clone()),
        content_hash: Some(content_hash),
        payload: Some(spec.payload.clone()),
        owner: Some(Id::new(&spec.owner).map_err(|e| anyhow!("bad owner '{}': {e}", spec.owner))?),
        creator: None,
        content_encoding: None,
        content_schema: Some(spec.schema.clone()),
        policy_ref: None,
        related: None,
        hlc: spec.hlc.clone(),
        prev: None,
        auth_cert: Some(presentation.to_string()),
        auth_evidence: None,
        auth_warrant: None,
    };
    msg.sign(&key);
    Ok(wire::serialize(&msg))
}

// ===========================================================================
// `mingo post` — the demonstration authenticated write
// ===========================================================================

pub struct PostArgs {
    pub community: String,
    pub space: String,
    pub text: String,
    pub audience: String,
    pub daemon: String,
    pub execute: bool,
}

#[derive(Deserialize)]
struct ObjectView {
    creator: String,
    #[serde(default)]
    owner_ref: Option<String>,
    #[serde(default)]
    confirmed: bool,
}

pub fn post(args: &PostArgs) -> Result<()> {
    let stored = StoredDeviceLogin::load()?;
    let agent = stored.agent()?; // errors with a re-login hint when absent
    let user = agent.email().to_string();

    let now_ms = chrono::Utc::now().timestamp_millis();
    let path = format!("/communities/{}/spaces/{}/", args.community, args.space);
    let id = crate::seed::derive_id('p', &format!("post:{}:{}:{}", args.community, args.space, now_ms));
    let payload = serde_json::to_vec(&serde_json::json!({
        "body": args.text,
        "parent": null,
        "created_at": now_ms,
    }))?;
    let spec = WriteSpec {
        action: Action::Post,
        path: path.clone(),
        id: id.clone(),
        schema: "post.v1".to_string(),
        content_type: "application/json".to_string(),
        payload,
        owner: user.clone(),
        hlc: None,
    };
    let wire_bytes = tokio::runtime::Runtime::new()
        .context("starting async runtime")?
        .block_on(sign_as_logged_in_user(&stored, &args.audience, &spec))?;

    println!("Write plan:");
    println!("  path:      {path}");
    println!("  id:        {id}");
    println!("  owner:     {user}   (the warrant identifier — attribution lands on you)");
    println!("  audience:  {}", args.audience);
    println!("  schema:    post.v1");
    println!("  wire:      {} bytes (device presentation in Auth-Cert)", wire_bytes.len());

    if !args.execute {
        println!("\nDry run — nothing submitted. Re-run with --execute to post to {}.", args.daemon);
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    println!("\nSubmitting to {}/v1/submit …", args.daemon);
    let resp = client
        .post(format!("{}/v1/submit", args.daemon.trim_end_matches('/')))
        .header("Content-Type", "application/octet-stream")
        .body(wire_bytes)
        .send()
        .context("submitting write")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("submit failed (HTTP {status}): {body}");
    }
    println!("✓ accepted by the DA layer: {body}");

    // Read back from head to confirm attribution. DA inclusion is asynchronous,
    // so poll a bounded window; a timeout is not a failure.
    println!("\nConfirming attribution (reading {path}{id} back)…");
    for attempt in 1..=20 {
        std::thread::sleep(Duration::from_secs(6));
        match read_object(&client, &args.daemon, &path, &id) {
            Ok(Some(view)) => {
                let attributed = view.owner_ref.as_deref().unwrap_or(&view.creator);
                println!(
                    "  read: creator={} owner_ref={:?} confirmed={}",
                    view.creator, view.owner_ref, view.confirmed
                );
                if attributed == user {
                    println!("\n✓ attribution confirmed: authored by {user} (the logged-in user).");
                } else {
                    println!("\n⚠ object present but attributed to '{attributed}', not '{user}'.");
                }
                return Ok(());
            }
            Ok(None) => {
                println!("  (attempt {attempt}/20) not confirmed on-chain yet…");
            }
            Err(e) => {
                println!("  (attempt {attempt}/20) read error: {e}");
            }
        }
    }
    println!(
        "\n⏳ not confirmed within the polling window — DA inclusion can lag. The write was accepted; \
         re-read later:  curl '{}/v1/object?path={}&id={}'",
        args.daemon, path, id
    );
    Ok(())
}

fn read_object(
    client: &reqwest::blocking::Client,
    daemon: &str,
    path: &str,
    id: &str,
) -> Result<Option<ObjectView>> {
    let resp = client
        .get(format!("{}/v1/object", daemon.trim_end_matches('/')))
        .query(&[("path", path), ("id", id)])
        .send()
        .context("GET /v1/object")?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Ok(None);
    }
    Ok(Some(resp.json::<ObjectView>().context("decoding object view")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::device::{
        AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose,
        Warrant as DeviceWarrant,
    };
    use browserid_core::{Assertion, KeyPair};
    use chrono::Duration;

    #[test]
    fn scopes_post_preset_has_no_as_scope() {
        let s = scopes_for(ScopePreset::Post);
        assert!(s.contains(&"action:post".to_string()));
        assert!(s.iter().any(|x| x.starts_with("path:")));
        // Holder model: no `as:` — attribution lands on the user directly.
        assert!(!s.iter().any(|x| x.starts_with("as:")));
        assert!(!s.contains(&"action:delete".to_string()));
    }

    #[test]
    fn scopes_admin_preset_adds_delete() {
        let s = scopes_for(ScopePreset::Admin);
        assert!(s.contains(&"action:delete".to_string()));
    }

    // Build a real device presentation and assert the assembled envelope
    // matches the daemon's device-attribution shape: signed by the ACCESS key
    // (envelope-key binding), presentation in Auth-Cert, no Auth-Warrant,
    // Owner = the user (the warrant identifier).
    #[test]
    fn assembled_envelope_matches_daemon_device_shape() {
        let idp = KeyPair::generate();
        let access = KeyPair::generate();
        let config = KeyPair::generate();
        let user_email = "dan@mingo.place";
        let audience = DEFAULT_AUDIENCE;
        let holder = "agpfx.cli1";

        let access_cert = AccessCert::create(
            "mingo.place", user_email, Holder::new(holder).unwrap(), &access.public_key(),
            Duration::hours(24), &idp, None,
        )
        .unwrap();
        let config_cert = DeviceCert::create(
            "mingo.place", &config.public_key(), Purpose::Authorization,
            Holder::new(holder).unwrap(), vec![user_email.to_string()],
            Duration::days(90), &idp, None,
        )
        .unwrap();
        let warrant = DeviceWarrant::create(
            user_email, HolderMatcher::new(holder).unwrap(), audience,
            scopes_for(ScopePreset::Post), Duration::days(90), &config, None,
        )
        .unwrap();
        let assertion = Assertion::create(audience, Duration::minutes(5), &access).unwrap();
        let presentation = AccessPresentation {
            access_cert, assertion, warrant, config_cert,
        }
        .encode();

        let spec = WriteSpec {
            action: Action::Post,
            path: "/communities/cooks/spaces/general/".to_string(),
            id: "ptest".to_string(),
            schema: "post.v1".to_string(),
            content_type: "application/json".to_string(),
            payload: serde_json::to_vec(&serde_json::json!({"body":"hi","parent":null})).unwrap(),
            owner: user_email.to_string(),
            hlc: None,
        };

        let wire_bytes =
            assemble_device_wire(access.secret_bytes(), &presentation, &spec).unwrap();

        // Re-parse and assert the daemon-visible shape.
        let msg = sbo_core::wire::parse(&wire_bytes).expect("wire parses");
        // Envelope-key binding: signed by the presentation's access key.
        assert_eq!(msg.signing_key, SigningKey::from_bytes(access.secret_bytes()).public_key());
        sbo_core::message::verify_message(&msg).expect("signature verifies");
        // Owner = the user (the warrant identifier under the holder model).
        assert_eq!(msg.owner.as_ref().map(|o| o.to_string()), Some(user_email.to_string()));
        // The presentation rides Auth-Cert; the classic Auth-Warrant is unused.
        let attached = msg.auth_cert.expect("auth_cert present");
        assert!(msg.auth_warrant.is_none());
        let pres = AccessPresentation::parse(&attached).expect("presentation parses");
        let verified = pres
            .verify(audience, |_| Ok(idp.public_key()))
            .expect("presentation verifies");
        assert_eq!(verified.email, user_email);
    }
}
