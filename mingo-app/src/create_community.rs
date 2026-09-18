//! `mingo create-community` — create a community and its spaces on the LIVE
//! chain, rather than baking them into a genesis.
//!
//! `genesis` seeds the starter communities, and nothing else could create one
//! afterwards — so every new community meant a regenesis, which destroys the
//! chain. This writes exactly what genesis writes for a community, signed by
//! the admin key, as ordinary governed writes:
//!
//!   /communities/<id>/         ID `community`  community.v1  (the descriptor)
//!   /communities/<id>/         ID `root`       policy.v2     (its own policy)
//!   /communities/<id>/spaces/<space>/  ID `_config`  collection.v1  (per space)
//!
//! The descriptor carries no logic: membership, roles and bans are attestations
//! and access control is policy, so a community is those three object kinds and
//! nothing more.
//!
//! Only the admin key can do it — the root policy grants `govern` on `/**` to
//! admin, which is what authorizes writing a community's own policy object.
//!
//! Dry-run by default; `--execute` submits.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use sbo_core::crypto::{SigningKey, Signature};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;

use crate::genesis::{community, community_policy_open, community_policy};
use crate::seed::load_signing_key_file;

/// A signed `Delete` for one object. `signed_object` only builds `Post`, and a
/// community that was created policy-first has to be cleared before it can be
/// written correctly (see the ordering note below).
fn signed_delete(key: &SigningKey, path: &str, id: &str) -> Vec<u8> {
    let mut msg = Message {
        action: Action::Delete,
        path: Path::parse(path).expect("path"),
        id: Id::new(id).expect("id"),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: None, content_hash: None, payload: None,
        owner: None, creator: None, content_encoding: None, content_schema: None,
        policy_ref: None, related: None, hlc: None, prev: None,
        auth_cert: None, auth_evidence: None, auth_warrant: None,
    };
    msg.sign(key);
    wire::serialize(&msg)
}

pub struct CreateCommunityArgs {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Attestation issuer for membership/bans, e.g. `agents@mingo.place`.
    pub issuer: String,
    /// Space names to create, in order.
    pub spaces: Vec<String>,
    /// Open membership (anyone may self-issue) vs issuer-attested.
    pub open: bool,
    pub daemon: String,
    pub repo: String,
    pub sys_key_file: String,
    pub execute: bool,
    /// Delete an existing community's descriptor and policy first, then write
    /// it again. Only for a community with nothing in it.
    pub replace: bool,
}

fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest),
        None => path.to_string(),
    }
}

/// Is there already a community at this id? Creating over one would replace its
/// descriptor and policy, which is never what you want by accident.
fn exists(client: &reqwest::blocking::Client, daemon: &str, repo: &str, id: &str) -> Result<bool> {
    let resp = client
        .get(format!("{}/v1/object", daemon.trim_end_matches('/')))
        .query(&[("path", &format!("/communities/{id}/")), ("id", &"community".to_string()), ("repo", &repo.to_string())])
        .send()
        .context("checking whether the community exists")?;
    Ok(resp.status().is_success())
}

fn submit(client: &reqwest::blocking::Client, args: &CreateCommunityArgs, batch: Vec<u8>, what: &str) -> Result<String> {
    let resp = client
        .post(format!("{}/v1/submit", args.daemon.trim_end_matches('/')))
        .query(&[("repo", &args.repo)])
        .header("Content-Type", "application/octet-stream")
        .body(batch)
        .send()
        .with_context(|| what.to_string())?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("ABORT — {what} failed: HTTP {status}: {body}");
    }
    let _: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    Ok(body)
}

pub fn run(args: &CreateCommunityArgs) -> Result<()> {
    if args.id.is_empty() || args.spaces.is_empty() {
        bail!("--id and at least one --space are required");
    }
    for s in &args.spaces {
        if !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            bail!("space `{s}`: use lowercase letters, digits and hyphens — it becomes a path segment");
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    if exists(&client, &args.daemon, &args.repo, &args.id)? && !args.replace {
        bail!(
            "/communities/{}/community already exists — refusing to overwrite a live community's \
             descriptor and policy. Pick another id, or edit the existing one deliberately.",
            args.id
        );
    }

    println!("community  /communities/{}/", args.id);
    println!("  name       {}", args.name);
    println!("  issuer     {}", args.issuer);
    println!("  membership {}", if args.open { "OPEN — anyone may self-issue `membership:<id>`" } else { "attested by the issuer" });
    println!("  bans       always the issuer's, either way");
    if let Some(d) = &args.description { println!("  about      {d}"); }
    for s in &args.spaces {
        println!("  space      /communities/{}/spaces/{}/", args.id, s);
    }

    if !args.execute {
        println!("\nDry run — nothing submitted. Re-run with --execute to create it.");
        return Ok(());
    }

    let sys_key = load_signing_key_file(&expand_tilde(&args.sys_key_file))
        .with_context(|| format!("loading admin key {}", args.sys_key_file))?;

    // Same shapes genesis writes, so a community created here is
    // indistinguishable from one born in a genesis.
    let policy_path = format!("/communities/{}/", args.id);
    // TWO PHASES, not one batch. Batch order is honoured when a block is
    // replayed, but `/v1/submit` validates each message against CURRENT state —
    // so a delete and a write that depends on it cannot travel together. Sent
    // as one batch, the space configs are still judged against the old
    // community policy and refused (observed 2026-09-18).
    if args.replace {
        let mut clear: Vec<u8> = Vec::new();
        clear.extend(signed_delete(&sys_key, &policy_path, "root"));
        clear.extend(signed_delete(&sys_key, &policy_path, "community"));
        submit(&client, args, clear, "clearing the old community")?;
        println!("  cleared; waiting for it to leave state before rewriting…");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
        while exists(&client, &args.daemon, &args.repo, &args.id)? {
            if std::time::Instant::now() > deadline {
                bail!("the old community is still present after 5 minutes — stopping rather than writing over it");
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }
    let mut batch: Vec<u8> = Vec::new();
    batch.extend(community(
        &sys_key, &args.id, &args.name, &args.issuer, &policy_path,
        args.description.as_deref(), args.open, Some(chrono::Utc::now().timestamp()),
    ));
    // ORDER MATTERS: the space configs go in BEFORE the community policy.
    //
    // Messages in a batch are validated in order against evolving state. Once
    // `/communities/<id>/root` lands it governs `/communities/<id>/spaces/**`,
    // and it grants `create` there only to `role: member` — the admin key is
    // not one, and the hub root's admin `post` on `/**` does not reach past the
    // nearer policy. Written policy-first, every space config is refused with
    // "No matching grant" while the descriptor and policy succeed, leaving a
    // community with no spaces (observed 2026-09-18).
    //
    // genesis gets away with the opposite order only because genesis mode
    // bypasses validation entirely.
    for s in &args.spaces {
        let path = format!("/communities/{}/spaces/{}/", args.id, s);
        batch.extend(sbo_core::presets::collection_config(
            &sys_key, &path, true, Some(5), Some(24 * 60 * 60), Some("post.v1"),
        ));
    }
    batch.extend(if args.open {
        community_policy_open(&sys_key, &args.id, &args.issuer)
    } else {
        community_policy(&sys_key, &args.id, &args.issuer)
    });

    let body = submit(&client, args, batch, "submitting the community")?;
    println!("\n✓ submitted\n  {body}");
    println!("\nIt is live once the daemon syncs past the block carrying it.");
    Ok(())
}
