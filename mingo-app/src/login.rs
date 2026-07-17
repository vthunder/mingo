//! `mingo login` / `mingo whoami` / `mingo post` — first-class command-line auth
//! against browserid, reusing the existing agent-identity + device-grant +
//! per-audience warrant primitives (bean browserid-ng-wmgb, option 1). Nothing
//! here is new auth: the RFC 8628 device-code flow, the delegated
//! `AgentCredential`, and the scoped warrant are all browserid's; this module is
//! the CLI *product* layer (a login command, local credential storage, and a
//! demonstration `as:` write).
//!
//! The flow:
//!   1. Device-code provisioning — generate a provisioning keypair locally, POST
//!      its public half to the broker's `/agent-provision/request`, print the
//!      `verification_uri_complete` (`/account?provision=<code>`) + user_code, and
//!      poll `/agent-provision/poll` until the human approves in the browser
//!      (their identity key signs a `U_cert~P_cert` delegation over the pubkey).
//!      The poll returns the delegation → an [`AgentCredential`].
//!   2. Mint an agent identity from that credential ([`AgentIdentity::provision`]):
//!      `agent = <handle>@<idp>`, `parent = <the logged-in user>`.
//!   3. Obtain a per-audience **warrant** for the mingo repo
//!      (`sbo+raw://avail:turing:506/`) carrying `as:<user>` so the daemon
//!      attributes writes to the user (the delegator). A second, deliberate
//!      browser consent.
//!   4. Store the credential + identity under `~/.mingo/` (0600) for silent reuse.
//!
//! A signed write then presents `Auth-Cert` (the agent cert) + `Auth-Warrant`
//! (the user-signed warrant); the daemon's `as:` path
//! (`sbo_core::authorize::agent_effective_email`, via
//! `sbo-daemon/src/validate.rs::resolve_agent_effective`) resolves the effective
//! author to the delegator. This is exactly the server-side mingo-poster shape
//! (`mingo-idp/src/poster.rs`), moved client-side.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use browserid_agent::{AgentCredential, AgentIdentity};
use browserid_core::KeyPair;
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;
use serde::Deserialize;

/// Production broker/registrar (endorses provisioning, hosts the consent pages).
pub const DEFAULT_BROKER: &str = "https://browserid.me";
/// The mingo SBO database a warrant must be audienced to. A **bare**
/// `sbo+raw://chain:appId/` reference (NOT `sbo://…` — DNS audiences are rejected
/// by `audience_identifies_db`). Matches `MINGO_SBO_DB_AUDIENCE` (mingo-idp) and
/// the daemon's `DbIdentity.uri` for the live repo (chain `avail`, appId 506).
pub const DEFAULT_AUDIENCE: &str = "sbo+raw://avail:turing:506/";
/// Live SBO daemon (reads + `/v1/submit`).
pub const DEFAULT_DAEMON: &str = "https://da.sandmill.org";

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ===========================================================================
// Local credential storage (~/.mingo/{credential,identity}.json, 0600)
// ===========================================================================

fn mingo_home() -> Result<PathBuf> {
    let home = std::env::var("MINGO_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".mingo")))
        .ok_or_else(|| anyhow!("cannot locate home dir (set $HOME or $MINGO_HOME)"))?;
    Ok(home)
}

fn credential_path() -> Result<PathBuf> {
    Ok(mingo_home()?.join("credential.json"))
}

fn identity_path() -> Result<PathBuf> {
    Ok(mingo_home()?.join("identity.json"))
}

/// Write `contents` to `path` with 0600 perms, creating the parent dir (0700).
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
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

/// Load the stored login: the [`AgentCredential`] (holds the provisioning
/// secret) plus the rehydrated [`AgentIdentity`] (agent key + cert + warrants).
/// The reusable entry point every authenticated command starts from.
pub fn load_login_credential() -> Result<(AgentCredential, AgentIdentity)> {
    let cpath = credential_path()?;
    let ipath = identity_path()?;
    if !cpath.exists() || !ipath.exists() {
        bail!(
            "not logged in (no {} / {}). Run `mingo login` first.",
            cpath.display(),
            ipath.display()
        );
    }
    let credential = AgentCredential::load(&cpath)
        .map_err(|e| anyhow!("reading {}: {e}", cpath.display()))?;
    let agent = AgentIdentity::load(&ipath, &credential)
        .map_err(|e| anyhow!("reading {}: {e}", ipath.display()))?;
    Ok((credential, agent))
}

// ===========================================================================
// Delegator (the logged-in user) extraction
// ===========================================================================

/// Decode a JWT's payload claims (no signature check — the delegation is already
/// verified end to end by the broker that signed it and by the daemon on replay).
fn jwt_claims(jwt: &str) -> Option<serde_json::Value> {
    let payload = jwt.split('.').nth(1)?;
    serde_json::from_slice(&B64URL.decode(payload).ok()?).ok()
}

/// The **delegator** email (the logged-in user) — the `iss` of the `P_cert` in
/// the credential's `U_cert~P_cert` delegation bundle. This is the identity the
/// user approved provisioning as, and the one a post attributes to via `as:`.
pub fn delegator_email(credential: &AgentCredential) -> Result<String> {
    let (_u, p) = credential
        .delegation
        .split_once('~')
        .ok_or_else(|| anyhow!("malformed delegation (expected U_cert~P_cert)"))?;
    let claims = jwt_claims(p).ok_or_else(|| anyhow!("cannot decode delegation P_cert"))?;
    claims
        .get("iss")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("delegation P_cert has no issuer (delegator)"))
}

// ===========================================================================
// Warrant scopes
// ===========================================================================

/// Scope preset requested for the warrant. `Post` is the normal-user default;
/// `Admin` is reserved for the operator-CLI use case (bean browserid-ng-wmgb
/// §admin-CLI) and left un-minted here beyond a broad action set — the daemon /
/// on-chain policy still gates what admin can actually do.
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

/// The warrant scopes for `user`. Mirrors `mingo-idp/src/poster.rs::default_scopes`
/// (the shape the daemon already validates): `action:post`, the mingo content
/// schemas, the community + user path scopes, and `as:<user>` (which needs at
/// least one `path:` scope to be honored — the daemon's on-behalf guardrail,
/// satisfied here).
pub fn scopes_for(preset: ScopePreset, user: &str) -> Vec<String> {
    let mut scopes = vec![
        "action:post".to_string(),
        "schema:post.v1".to_string(),
        "schema:comment.v1".to_string(),
        "schema:reaction.v1".to_string(),
        "path:/communities/**".to_string(),
        format!("path:/u/{user}/**"),
        format!("as:{user}"),
    ];
    if preset == ScopePreset::Admin {
        // Broaden the action set for the operator CLI; the daemon + root policy
        // remain the real authority (this is not a bypass, just a wider request).
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
    pub handle: Option<String>,
}

#[derive(Deserialize)]
struct DeviceRequestResp {
    #[allow(dead_code)]
    success: bool,
    code: String,
    verification_uri: String,
    verification_uri_complete: String,
    user_code: String,
    fingerprint: String,
    expires_in: i64,
    interval: i64,
}

/// Run the device-code provisioning against `broker` and return the resulting
/// [`AgentCredential`]. Blocks (async, but with a foreground poll loop) until the
/// human approves at the printed URL, or the request expires.
async fn device_provision(
    http: &reqwest::Client,
    broker: &str,
    label: &str,
) -> Result<AgentCredential> {
    let provisioning_key = KeyPair::generate();
    let pubkey_b64 = provisioning_key.public_key().to_base64();

    let req = http
        .post(format!("{}/agent-provision/request", broker.trim_end_matches('/')))
        .json(&serde_json::json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": pubkey_b64 },
            "label": label,
        }))
        .send()
        .await
        .context("POST /agent-provision/request")?;
    let status = req.status();
    if !status.is_success() {
        let body = req.text().await.unwrap_or_default();
        bail!("device provision request failed ({status}): {body}");
    }
    let resp: DeviceRequestResp = req.json().await.context("decoding request response")?;

    println!("\nTo authorize this CLI, open:\n");
    println!("    {}\n", resp.verification_uri_complete);
    println!(
        "  or go to {} and enter code:  {}",
        resp.verification_uri, resp.user_code
    );
    println!("  confirm the key fingerprint matches:  {}\n", resp.fingerprint);
    println!("Waiting for approval (expires in {}s)…", resp.expires_in);

    let interval = resp.interval.max(1) as u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(resp.expires_in.max(0) as u64);
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let poll = http
            .post(format!("{}/agent-provision/poll", broker.trim_end_matches('/')))
            .json(&serde_json::json!({ "code": resp.code }))
            .send()
            .await
            .context("POST /agent-provision/poll")?;
        if poll.status().as_u16() == 410 {
            bail!("provisioning request expired before approval");
        }
        let value: serde_json::Value = poll.json().await.unwrap_or_default();
        match value["status"].as_str() {
            Some("pending") => {}
            Some("denied") => bail!("provisioning was denied in the browser"),
            Some("failed") => {
                bail!(
                    "provisioning failed: {}",
                    value["reason"].as_str().unwrap_or("no reason given")
                )
            }
            Some("completed") => {
                let cred = &value["credential"];
                let delegation = cred["delegation"]
                    .as_str()
                    .ok_or_else(|| anyhow!("poll response missing credential.delegation"))?
                    .to_string();
                let broker_url = cred["broker"].as_str().unwrap_or(broker).to_string();
                let idp = cred["idp"]
                    .as_str()
                    .ok_or_else(|| anyhow!("poll response missing credential.idp"))?
                    .to_string();
                return Ok(AgentCredential {
                    secret_key: B64URL.encode(provisioning_key.secret_bytes()),
                    delegation,
                    broker: broker_url,
                    idp,
                });
            }
            _ => bail!("unexpected poll status: {value}"),
        }
        if std::time::Instant::now() > deadline {
            bail!("provisioning request expired before approval");
        }
    }
}

async fn login_async(args: &LoginArgs) -> Result<()> {
    let preset = ScopePreset::parse(&args.scope)?;
    let http = reqwest::Client::new();

    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| hostname_fallback())
        .unwrap_or_else(|| "cli".to_string());
    let label = format!("mingo CLI on {hostname}");

    println!("Step 1/2 — authorize the CLI (device provisioning)");
    let mut credential = device_provision(&http, &args.broker, &label).await?;
    if let Some(idp) = &args.idp {
        credential.idp = idp.clone();
    }

    let user = delegator_email(&credential)?;
    println!("\n✓ authorized as {user}. Minting the agent identity…");

    let mut agent = AgentIdentity::provision(&credential, args.handle.as_deref())
        .await
        .map_err(|e| anyhow!("provisioning agent identity: {e}"))?;
    println!("✓ agent identity: {} (acting for {user})", agent.email());

    println!("\nStep 2/2 — authorize a warrant for the mingo repo");
    println!("  audience: {}", args.audience);
    let scopes = scopes_for(preset, &user);
    for s in &scopes {
        println!("    scope: {s}");
    }
    agent
        .obtain_warrant(&args.audience, Some(scopes), |handle| {
            println!("\n  ==> approve the warrant at: {}\n", handle.verification_uri);
            println!("  Waiting for warrant approval…");
        })
        .await
        .map_err(|e| anyhow!("obtaining warrant: {e}"))?;

    // Persist: credential (with the provisioning secret) + identity (agent key,
    // cert, warrants). Both 0600.
    let cpath = credential_path()?;
    let ipath = identity_path()?;
    write_private(&cpath, &serde_json::to_string_pretty(&credential)?)?;
    agent
        .save(&ipath)
        .map_err(|e| anyhow!("saving identity to {}: {e}", ipath.display()))?;
    // save() uses default perms; tighten to 0600.
    tighten_perms(&ipath)?;

    println!("\n✓ logged in as {user}");
    println!("  agent:      {}", agent.email());
    println!("  audience:   {}", args.audience);
    println!("  credential: {}", cpath.display());
    println!("  identity:   {}", ipath.display());
    println!("\nTry:  mingo whoami");
    Ok(())
}

fn tighten_perms(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod 600 {}", path.display()))?;
    Ok(())
}

/// Best-effort hostname without pulling a dependency: read /etc/hostname.
fn hostname_fallback() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn login(args: &LoginArgs) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("starting async runtime")?
        .block_on(login_async(args))
}

// ===========================================================================
// `mingo whoami`
// ===========================================================================

pub fn whoami() -> Result<()> {
    let (credential, agent) = load_login_credential()?;
    let cert = agent.certificate();
    let user = cert
        .agent_parent()
        .map(str::to_string)
        .or_else(|| delegator_email(&credential).ok())
        .unwrap_or_else(|| "<unknown>".to_string());

    let exp = cert.claims().exp;
    let now = chrono::Utc::now().timestamp();
    let cert_state = if exp <= now {
        "expired (re-mints automatically on next use)".to_string()
    } else {
        let mins = (exp - now) / 60;
        format!("valid for ~{mins} more minutes")
    };

    println!("logged in as:  {user}");
    println!("  agent:       {}", agent.email());
    println!("  broker:      {}", credential.broker);
    println!("  idp:         {}", credential.idp);
    println!("  agent cert:  {cert_state}");
    let auds = agent.warranted_audiences();
    if auds.is_empty() {
        println!("  warrants:    none — run `mingo login` to authorize an audience");
    } else {
        println!("  warrants for:");
        for a in auds {
            println!("    {a}");
        }
    }
    if !cert.is_agent() {
        println!(
            "  note: stored cert is not an agent cert — attribution via `as:` will not apply"
        );
    }
    Ok(())
}

// ===========================================================================
// Signing writes as the logged-in user (`as:` attribution)
// ===========================================================================

/// One SBO write to be signed as the logged-in user. The daemon resolves the
/// effective author to `owner` (the delegator) via the warrant's `as:` scope.
pub struct WriteSpec {
    pub action: Action,
    pub path: String,
    pub id: String,
    pub schema: String,
    pub content_type: String,
    pub payload: Vec<u8>,
    /// The object owner — the delegating (logged-in) user.
    pub owner: String,
    pub hlc: Option<String>,
}

/// Sign `spec` as the logged-in user: sign the SBO envelope with the **agent**
/// key and attach `Auth-Cert` (the agent cert) + `Auth-Warrant` (the user-signed
/// warrant for `audience`). Produces the exact wire the daemon accepts on the
/// `as:` path — `Auth-Evidence` is omitted so the daemon resolves both issuers'
/// on-chain `/sys/dnssec/<issuer>` proofs (the same choice mingo-poster makes).
pub fn sign_as_logged_in_user(
    agent: &AgentIdentity,
    audience: &str,
    spec: &WriteSpec,
) -> Result<Vec<u8>> {
    let warrant = agent
        .warrant_for(audience)
        .ok_or_else(|| anyhow!("no warrant held for audience {audience} — run `mingo login`"))?;
    let cert = agent.certificate();
    assemble_agent_wire(
        agent.keypair().secret_bytes(),
        &cert.encoded().to_string(),
        &warrant.encoded().to_string(),
        spec,
    )
}

/// Pure envelope assembly (unit-testable without a live provisioning flow):
/// sign the SBO message with the agent key (`agent_secret`, a 32-byte Ed25519
/// seed) and attach `Auth-Cert` + `Auth-Warrant`. Mirrors
/// `mingo-idp/src/poster.rs::assemble_agent_write`.
fn assemble_agent_wire(
    agent_secret: &[u8; 32],
    cert_encoded: &str,
    warrant_encoded: &str,
    spec: &WriteSpec,
) -> Result<Vec<u8>> {
    let key = SigningKey::from_bytes(agent_secret);
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
        auth_cert: Some(cert_encoded.to_string()),
        auth_evidence: None,
        auth_warrant: Some(warrant_encoded.to_string()),
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
    let (credential, mut agent) = load_login_credential()?;
    let user = cert_user(&credential, &agent);

    // Ensure a warrant covers this audience+action (obtains one via the browser
    // consent if missing — normally already held from `mingo login`).
    if agent.warrant_for(&args.audience).is_none() {
        println!("No warrant held for {} — requesting one…", args.audience);
        let scopes = scopes_for(ScopePreset::Post, &user);
        tokio::runtime::Runtime::new()?
            .block_on(agent.obtain_warrant(&args.audience, Some(scopes), |h| {
                println!("\n  ==> approve at: {}\n", h.verification_uri);
            }))
            .map_err(|e| anyhow!("obtaining warrant: {e}"))?;
        // Persist the freshly obtained warrant.
        let _ = agent.save(identity_path()?).map_err(|e| anyhow!("{e}"));
    }

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
    let wire_bytes = sign_as_logged_in_user(&agent, &args.audience, &spec)?;

    println!("Write plan:");
    println!("  path:      {path}");
    println!("  id:        {id}");
    println!("  owner:     {user}   (effective author via warrant `as:`)");
    println!("  signer:    {}  (agent key)", agent.email());
    println!("  audience:  {}", args.audience);
    println!("  schema:    post.v1");
    println!("  wire:      {} bytes (Auth-Cert + Auth-Warrant attached)", wire_bytes.len());

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
    // so poll a bounded window; a timeout is not a failure of the `as:` path.
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
                    println!(
                        "\n✓ attribution confirmed: the object is authored by {user} (the logged-in user), \
                         proving the client-side `as:` path landed."
                    );
                } else {
                    println!(
                        "\n⚠ object present but attributed to '{attributed}', not '{user}'."
                    );
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

/// The logged-in user email — the cert's agent-parent, falling back to the
/// delegation's delegator.
fn cert_user(credential: &AgentCredential, agent: &AgentIdentity) -> String {
    agent
        .certificate()
        .agent_parent()
        .map(str::to_string)
        .or_else(|| delegator_email(credential).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::{Certificate, KeyPair, Warrant};
    use chrono::Duration;

    #[test]
    fn scopes_post_preset_carries_as_and_path_and_action() {
        let s = scopes_for(ScopePreset::Post, "danmills@sandmill.org");
        assert!(s.contains(&"action:post".to_string()));
        assert!(s.contains(&"as:danmills@sandmill.org".to_string()));
        // The `as:` guardrail requires at least one path scope.
        assert!(s.iter().any(|x| x.starts_with("path:")));
        // Post preset does not request delete.
        assert!(!s.contains(&"action:delete".to_string()));
    }

    #[test]
    fn scopes_admin_preset_adds_delete() {
        let s = scopes_for(ScopePreset::Admin, "op@sandmill.org");
        assert!(s.contains(&"action:delete".to_string()));
    }

    // Build a real agent cert + user-signed warrant and assert the assembled
    // envelope matches what the daemon's `as:` path expects: agent-signed, with
    // Auth-Cert (an agent cert, parent = the user) + Auth-Warrant (audience +
    // `as:<user>` scopes), Owner = the user (the delegator / effective author).
    #[test]
    fn assembled_envelope_matches_daemon_as_path_shape() {
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let agent_kp = KeyPair::generate();
        let user_email = "danmills@sandmill.org";
        let agent_email = "svc+abcd@browserid.me";
        let audience = DEFAULT_AUDIENCE;

        let parent_cert = Certificate::create(
            "browserid.me",
            user_email,
            &user.public_key(),
            Duration::hours(24),
            &idp,
        )
        .unwrap();
        let agent_cert = Certificate::create_agent(
            "browserid.me",
            agent_email,
            user_email,
            &agent_kp.public_key(),
            Duration::hours(24),
            &idp,
            Some("https://browserid.me".to_string()),
        )
        .unwrap();
        assert!(agent_cert.is_agent());
        assert_eq!(agent_cert.agent_parent(), Some(user_email));

        let scopes = scopes_for(ScopePreset::Post, user_email);
        let warrant = Warrant::create(
            &parent_cert,
            agent_email,
            audience,
            Some(scopes.clone()),
            Duration::days(90),
            &user,
        )
        .unwrap();

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

        let wire_bytes = assemble_agent_wire(
            agent_kp.secret_bytes(),
            &agent_cert.encoded().to_string(),
            &warrant.encoded().to_string(),
            &spec,
        )
        .unwrap();

        // Re-parse and assert the daemon-visible shape.
        let msg = sbo_core::wire::parse(&wire_bytes).expect("wire parses");
        // Signed by the agent key.
        assert_eq!(
            msg.signing_key,
            SigningKey::from_bytes(agent_kp.secret_bytes()).public_key()
        );
        // Signature is valid over the envelope.
        sbo_core::message::verify_message(&msg).expect("signature verifies");
        // Owner = the delegator (the effective author under `as:`).
        assert_eq!(msg.owner.as_ref().map(|o| o.to_string()), Some(user_email.to_string()));
        // Both agent-write credentials are attached.
        let attached_cert = msg.auth_cert.expect("auth_cert present");
        let attached_warrant = msg.auth_warrant.expect("auth_warrant present");
        // The attached warrant names this agent, this audience, and carries `as:`.
        let w = Warrant::parse(&attached_warrant).unwrap();
        assert_eq!(w.agent(), agent_email);
        assert_eq!(w.audience(), audience);
        assert!(w
            .claims()
            .scopes
            .as_ref()
            .unwrap()
            .contains(&format!("as:{user_email}")));
        // The attached cert is the agent cert (parent = the user).
        let c = Certificate::parse(&attached_cert).unwrap();
        assert_eq!(c.agent_parent(), Some(user_email));
    }
}
