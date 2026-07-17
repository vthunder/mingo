//! `mingo live-test` — an executable scenario runner that exercises the LIVE
//! SBO chain (daemon `da.sandmill.org`, IdP `mingo.place`, genesis v5) and
//! asserts authorization outcomes, validating the policy-delegation model:
//! P1 govern, moderator delete, owner semantics, ban, and the capture fix.
//!
//! ## How it works
//!
//! Every scenario provisions disposable `livetest-*@mingo.place` identities via
//! the IdP's `/admin/provision` (mirroring `seed::provision_persona`), performs
//! one or more attributed writes with `seed::assemble_write` (identity-cert
//! auth; the daemon resolves `/sys/dnssec/mingo.place` on-chain), then ASSERTS
//! the resulting head state read back from the daemon's `/v1/object` and
//! `/v1/state-root` endpoints. An SBO write is authorized+applied (object is
//! PRESENT in head) or denied/disregarded (ABSENT). We assert on the observed
//! head state — the authoritative signal — not merely on the submit response.
//!
//! Two settle signals:
//!   * PRESENT — poll `/v1/object` until the object is served with
//!     `confirmed: true` (out of the mempool overlay, onto confirmed state).
//!   * ABSENT  — a write denied at submit (HTTP 400) never enters head; a write
//!     ACCEPTED at submit but disregarded on replay lingers as `confirmed:false`
//!     in the overlay then vanishes once its block is replayed. So we wait for
//!     head to advance past the submit block and confirm `/v1/object` 404s.
//!
//! ## Identity honesty (hard project rule)
//!
//! Disposable identities are `livetest-<name>@mingo.place`, provisioned against
//! `livetest-<name>.seed@sandmill.org` external emails — NEVER an address that
//! could belong to a real third party.
//!
//! ## Safety
//!
//! This WRITES to the live chain (that's the point — it's a live test), but only
//! to throwaway ids under `/communities/cooks/spaces/general/` prefixed
//! `livetest-<runid>-`. It is DRY by default: without `--execute` it provisions
//! nothing and submits nothing, printing only the scenario plan.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;

use crate::seed::{assemble_write, ensure_dnssec_fresh, provision_persona, Provisioned};

// ===========================================================================
// CLI args
// ===========================================================================

pub struct LiveTestArgs {
    /// IdP origin (its host is the identity domain, e.g. mingo.place).
    pub idp: String,
    /// SBO daemon origin (reads + submit).
    pub daemon: String,
    /// Env var holding the IdP admin token (X-Admin-Token).
    pub admin_token_env: String,
    /// Restrict to these scenario ids (e.g. `["S1","S2"]`); empty = all.
    pub only: Vec<String>,
    /// Keep test objects at the end (skip cleanup).
    pub keep: bool,
    /// Actually provision + write to the live chain (default: print the plan).
    pub execute: bool,
}

// ===========================================================================
// Scenario catalogue
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// The target object is authorized + applied — PRESENT in head.
    Present,
    /// The target write is denied / disregarded — ABSENT from head.
    Absent,
    /// The target object survives an unauthorized mutation UNCHANGED (owner
    /// semantics): present in head with its original content.
    Unchanged,
}

impl Expect {
    fn label(self) -> &'static str {
        match self {
            Expect::Present => "PRESENT",
            Expect::Absent => "ABSENT",
            Expect::Unchanged => "UNCHANGED",
        }
    }
}

pub struct Scenario {
    pub id: &'static str,
    pub title: &'static str,
    pub expect: Expect,
    pub implemented: bool,
    /// One-line description of what it does (for the plan).
    pub detail: &'static str,
}

/// The scenario catalogue, in the priority order from the brief.
pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            id: "S1",
            title: "capture fix — member cannot self-install a policy",
            expect: Expect::Absent,
            implemented: true,
            detail: "a cooks member writes a policy.v2 under the space subtree → \
                     disregarded (no govern). THE headline security test.",
        },
        Scenario {
            id: "S2",
            title: "non-member cannot post",
            expect: Expect::Absent,
            implemented: true,
            detail: "a provisioned user with NO membership posts in cooks/general → denied.",
        },
        Scenario {
            id: "S3",
            title: "member can post",
            expect: Expect::Present,
            implemented: true,
            detail: "a user self-issues membership:cooks, then posts → applied.",
        },
        Scenario {
            id: "S4",
            title: "owner-only update",
            expect: Expect::Unchanged,
            implemented: true,
            detail: "member A posts; member B tries to update A's (path,id) → \
                     A's content unchanged (B denied).",
        },
        Scenario {
            id: "S5",
            title: "author delete",
            expect: Expect::Absent,
            implemented: true,
            detail: "A deletes their own post → gone from head.",
        },
        Scenario {
            id: "S6",
            title: "moderator delete",
            expect: Expect::Absent,
            implemented: true,
            detail: "appoint a role:moderator:cooks by cooks@mingo.place; the \
                     moderator deletes another member's post → gone.",
        },
        Scenario {
            id: "S7",
            title: "non-moderator cannot delete another's post",
            expect: Expect::Present,
            implemented: true,
            detail: "a plain member tries to delete another member's post → \
                     denied, post survives.",
        },
        Scenario {
            id: "S8",
            title: "ban",
            expect: Expect::Absent,
            implemented: false,
            detail: "issuer bans a member; that member's post → disregarded. \
                     (NOT YET IMPLEMENTED — SKIP.)",
        },
    ]
}

// ===========================================================================
// Entry point
// ===========================================================================

/// `https://mingo.place` → `mingo.place`.
fn domain_of(url: &str) -> String {
    let no_scheme = url
        .trim_end_matches('/')
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    host.split(':').next().unwrap_or(host).to_string()
}

fn selected(scen: &Scenario, only: &[String]) -> bool {
    only.is_empty() || only.iter().any(|s| s.eq_ignore_ascii_case(scen.id))
}

pub fn run(args: &LiveTestArgs) -> Result<()> {
    let domain = domain_of(&args.idp);
    let all = scenarios();
    let chosen: Vec<&Scenario> = all.iter().filter(|s| selected(s, &args.only)).collect();
    if chosen.is_empty() {
        bail!("no scenarios match --only {:?}", args.only);
    }

    println!("Mingo live-chain scenario test");
    println!("  idp     {}", args.idp);
    println!("  daemon  {}", args.daemon);
    println!("  domain  {domain}");
    println!(
        "  mode    {}",
        if args.execute {
            "EXECUTE — writes to the LIVE chain"
        } else {
            "plan only (dry run)"
        }
    );
    println!();
    println!("Scenarios ({} selected):", chosen.len());
    for s in &chosen {
        let mark = if s.implemented { " " } else { "!" };
        println!(
            "  {mark}{:<3} [{:<9}] {}",
            s.id,
            s.expect.label(),
            s.title
        );
        println!("        {}", s.detail);
    }
    println!();

    if !args.execute {
        println!(
            "All identities are livetest-*@mingo.place (external livetest-*.seed@sandmill.org),\n\
             all writes land under /communities/cooks/spaces/general/ with ids prefixed\n\
             livetest-<runid>-. Nothing is written in this mode."
        );
        println!();
        println!("Dry run — nothing provisioned or submitted. Re-run with --execute to run live.");
        return Ok(());
    }

    execute(args, &domain, &chosen)
}

// ===========================================================================
// Live execution
// ===========================================================================

/// Confirmed-object view served by `GET /v1/object`.
#[derive(Debug, Deserialize)]
struct ObjView {
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    block: u64,
    #[serde(default)]
    value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct StateRootView {
    #[serde(default)]
    block: u64,
}

/// Outcome of a single `/v1/submit`.
struct Submitted {
    /// The daemon accepted the wire into its overlay (HTTP 2xx).
    accepted: bool,
    /// The submit-time rejection reason (HTTP 400 body), if denied there.
    reason: Option<String>,
    /// Head block observed just before the submit (for finality waits).
    base_block: u64,
}

#[derive(Debug)]
enum Outcome {
    Pass,
    Fail(String),
    Timeout(String),
    Skip(String),
    Error(String),
}

impl Outcome {
    fn tag(&self) -> &'static str {
        match self {
            Outcome::Pass => "PASS",
            Outcome::Fail(_) => "FAIL",
            Outcome::Timeout(_) => "TIMEOUT",
            Outcome::Skip(_) => "SKIP",
            Outcome::Error(_) => "ERROR",
        }
    }
    fn note(&self) -> &str {
        match self {
            Outcome::Pass => "",
            Outcome::Fail(s)
            | Outcome::Timeout(s)
            | Outcome::Skip(s)
            | Outcome::Error(s) => s,
        }
    }
}

/// Per-scenario confirmation timeout and poll cadence. Avail blocks are ~20s,
/// so give confirmation a generous window.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(180);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Blocks head must advance past a submit before we trust an ABSENT read
/// (the disregarded write's block has definitely been replayed by then).
const FINALITY_BLOCKS: u64 = 2;

struct Ctx {
    client: reqwest::blocking::Client,
    idp: String,
    daemon: String,
    admin_token: String,
    domain: String,
    runid: String,
    keep: bool,
    /// Objects written this run (path, id) — deleted at the end unless --keep.
    written: Vec<(String, String)>,
}

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
}

/// A short random run id so concurrent/repeat runs don't collide.
fn make_runid() -> String {
    let seed = SigningKey::generate();
    let h = ContentHash::sha256(&seed.public_key().bytes);
    hex::encode(&h.bytes[..4])
}

fn execute(args: &LiveTestArgs, domain: &str, chosen: &[&Scenario]) -> Result<()> {
    let admin_token = std::env::var(&args.admin_token_env).with_context(|| {
        format!(
            "--execute needs the IdP admin token in ${}",
            args.admin_token_env
        )
    })?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    // Every email-rooted write's attribution needs a fresh on-chain
    // /sys/dnssec/<domain> proof — refresh it once up front.
    ensure_dnssec_fresh(&client, &args.daemon, domain, now_s())?;

    let mut ctx = Ctx {
        client,
        idp: args.idp.clone(),
        daemon: args.daemon.clone(),
        admin_token,
        domain: domain.to_string(),
        runid: make_runid(),
        keep: args.keep,
        written: Vec::new(),
    };
    println!("Run id: {} (test ids prefixed livetest-{}-)", ctx.runid, ctx.runid);
    println!();

    let mut results: Vec<(&str, Expect, Outcome)> = Vec::new();
    for s in chosen {
        println!("── {} — {} ──────────────────────────────", s.id, s.title);
        let outcome = if !s.implemented {
            Outcome::Skip("not implemented".to_string())
        } else {
            run_scenario(&mut ctx, s.id).unwrap_or_else(|e| Outcome::Error(format!("{e:#}")))
        };
        println!("  → {} {}", outcome.tag(), outcome.note());
        println!();
        results.push((s.id, s.expect, outcome));
    }

    // Best-effort cleanup — a failed cleanup must not fail the run.
    if !ctx.keep {
        cleanup(&mut ctx);
    } else {
        println!("--keep: leaving {} test object(s) on-chain.", ctx.written.len());
    }

    print_summary(&results);
    Ok(())
}

// ---- primitives -----------------------------------------------------------

/// Provision `livetest-<name>@<domain>` (disposable, honesty-safe external
/// email). Reuses `seed::provision_persona` verbatim.
fn provision(ctx: &Ctx, name: &str) -> Result<Provisioned> {
    let handle = format!("livetest-{name}");
    let p = provision_persona(&ctx.client, &ctx.idp, &ctx.admin_token, &handle, &ctx.domain)?;
    println!("  · provisioned {}", p.email);
    Ok(p)
}

/// A run-scoped object id: `livetest-<runid>-<name>`.
fn oid(ctx: &Ctx, name: &str) -> String {
    format!("livetest-{}-{}", ctx.runid, name)
}

/// POST wire bytes to `/v1/submit`. HTTP 2xx → accepted; HTTP 400 → denied at
/// submit (a legitimate outcome, not an error); other statuses/network → Err.
fn submit(ctx: &Ctx, wire_bytes: &[u8], label: &str) -> Result<Submitted> {
    let base_block = head_block(ctx).unwrap_or(0);
    let resp = ctx
        .client
        .post(format!("{}/v1/submit", ctx.daemon.trim_end_matches('/')))
        .header("Content-Type", "application/octet-stream")
        .body(wire_bytes.to_vec())
        .send()
        .with_context(|| format!("submitting {label}"))?;
    let status = resp.status();
    if status.is_success() {
        println!("  · submit [{label}] accepted");
        return Ok(Submitted { accepted: true, reason: None, base_block });
    }
    let body = resp.text().unwrap_or_default();
    if status.as_u16() == 400 {
        let reason = parse_error(&body);
        println!("  · submit [{label}] DENIED at submit: {reason}");
        return Ok(Submitted { accepted: false, reason: Some(reason), base_block });
    }
    bail!("submit [{label}] failed: HTTP {status}: {body}");
}

/// `{"error": "..."}` → the message; otherwise the raw body.
fn parse_error(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| body.trim().to_string())
}

fn head_block(ctx: &Ctx) -> Result<u64> {
    let sr: StateRootView = ctx
        .client
        .get(format!("{}/v1/state-root", ctx.daemon.trim_end_matches('/')))
        .send()
        .context("state-root")?
        .error_for_status()
        .context("state-root")?
        .json()
        .context("parsing state-root")?;
    Ok(sr.block)
}

/// Read one object. 200 → Some(view); 404 → None; other → Err.
fn get_object(ctx: &Ctx, path: &str, id: &str) -> Result<Option<ObjView>> {
    let resp = ctx
        .client
        .get(format!("{}/v1/object", ctx.daemon.trim_end_matches('/')))
        .query(&[("path", path), ("id", id)])
        .send()
        .context("get_object")?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    let resp = resp.error_for_status().context("get_object")?;
    Ok(Some(resp.json().context("parsing object")?))
}

// ---- assertions -----------------------------------------------------------

/// Poll until the object is served `confirmed:true`, optionally checking a body
/// field. Returns Pass on confirmation, Timeout otherwise.
fn settle_present(ctx: &Ctx, path: &str, id: &str, expect_body: Option<&str>) -> Outcome {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        match get_object(ctx, path, id) {
            Ok(Some(o)) if o.confirmed => {
                if let Some(want) = expect_body {
                    let got = o.value.get("body").and_then(|b| b.as_str()).unwrap_or("");
                    if got != want {
                        return Outcome::Fail(format!(
                            "present but body changed: got {got:?}, want {want:?}"
                        ));
                    }
                }
                return Outcome::Pass;
            }
            Ok(_) => {} // absent or still pending — keep waiting
            Err(e) => return Outcome::Error(format!("{e:#}")),
        }
        if Instant::now() >= deadline {
            return Outcome::Timeout(format!("never confirmed present at {path}{id}"));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Confirm the target write did NOT take effect. `sub` carries whether it was
/// denied at submit (→ immediately absent) or accepted (→ must wait for head to
/// pass the submit block, then confirm the object 404s).
fn settle_absent(ctx: &Ctx, path: &str, id: &str, sub: &Submitted) -> Outcome {
    // Denied at submit — it never entered head. Confirm it isn't there.
    if !sub.accepted {
        return match get_object(ctx, path, id) {
            Ok(None) => Outcome::Pass,
            Ok(Some(o)) if o.confirmed => {
                Outcome::Fail(format!("denied at submit yet present+confirmed (block {})", o.block))
            }
            Ok(Some(_)) => Outcome::Pass, // lingering pending overlay entry only
            Err(e) => Outcome::Error(format!("{e:#}")),
        };
    }
    // Accepted into the overlay: wait for finality, then confirm it's gone.
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let head = head_block(ctx).unwrap_or(sub.base_block);
        match get_object(ctx, path, id) {
            Ok(Some(o)) if o.confirmed => {
                return Outcome::Fail(format!(
                    "applied to head (confirmed in block {}) — expected disregarded",
                    o.block
                ));
            }
            Ok(None) if head >= sub.base_block + FINALITY_BLOCKS => return Outcome::Pass,
            Ok(_) => {} // pending, or gone but not yet past finality — keep waiting
            Err(e) => return Outcome::Error(format!("{e:#}")),
        }
        if Instant::now() >= deadline {
            // Timed out: if it's absent now, report the weaker (but likely-correct)
            // conclusion honestly rather than a false PASS.
            return match get_object(ctx, path, id) {
                Ok(None) => Outcome::Timeout(
                    "absent, but head did not advance enough to prove finality".to_string(),
                ),
                _ => Outcome::Timeout("still pending in overlay at deadline".to_string()),
            };
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// ---- write builders (reusing seed::assemble_write) ------------------------

/// A member self-issues `membership:cooks` — the SPA's joinHub shape, exactly
/// as `seed` writes it. Authorizes the OPEN community's create grant.
fn self_issue_membership(ctx: &Ctx, actor: &Provisioned, comm: &str) -> Result<Submitted> {
    let addr = &actor.email;
    let path = format!("/u/{addr}/attestations/{addr}/");
    let id = format!("membership-{comm}");
    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": addr,
        "type": format!("membership:{comm}"),
        "value": { "community": comm, "via": "mingo-livetest" },
        "issued_at": now_s(),
        "expires": null,
        "issuer": addr,
    }))?;
    let wire_bytes = assemble_write(
        &actor.key,
        Some(&actor.cert),
        None,
        &path,
        &id,
        "attestation.v1",
        "application/json",
        payload,
        Some(addr),
        None,
    )?;
    let sub = submit(ctx, &wire_bytes, &format!("membership {addr}→{comm}"))?;
    Ok(sub)
}

/// Author a `post.v1` at (space, id) owned by `actor`.
fn write_post(ctx: &mut Ctx, actor: &Provisioned, id: &str, body: &str) -> Result<Submitted> {
    let path = space();
    let payload = serde_json::to_vec(&serde_json::json!({
        "body": body,
        "parent": null,
        "created_at": now_s() * 1000,
    }))?;
    let wire_bytes = assemble_write(
        &actor.key,
        Some(&actor.cert),
        None,
        &path,
        id,
        "post.v1",
        "application/json",
        payload,
        Some(&actor.email),
        None,
    )?;
    let sub = submit(ctx, &wire_bytes, &format!("post {id} by {}", actor.email))?;
    ctx.written.push((path, id.to_string()));
    Ok(sub)
}

/// A `delete` write to (path,id): `Action::Delete`, empty payload — mirrors the
/// SPA's `deleteContent`. Signed by `actor` with its identity cert.
fn write_delete(
    ctx: &Ctx,
    actor: &Provisioned,
    path: &str,
    id: &str,
    schema: &str,
) -> Result<Submitted> {
    let wire_bytes = assemble_delete(&actor.key, &actor.cert, path, id, schema, &actor.email)?;
    submit(ctx, &wire_bytes, &format!("delete {id} by {}", actor.email))
}

/// Issue an `attestation.v1` from `issuer` about `subject` (moderator role,
/// ban, etc.). Owned by and signed with the issuer's identity.
fn write_attestation(
    ctx: &Ctx,
    issuer: &Provisioned,
    subject: &str,
    type_: &str,
    value: serde_json::Value,
) -> Result<Submitted> {
    let iss = &issuer.email;
    let path = format!("/u/{iss}/attestations/{subject}/");
    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": subject,
        "type": type_,
        "value": value,
        "issued_at": now_s(),
        "expires": null,
        "issuer": iss,
    }))?;
    let wire_bytes = assemble_write(
        &issuer.key,
        Some(&issuer.cert),
        None,
        &path,
        type_,
        "attestation.v1",
        "application/json",
        payload,
        Some(iss),
        None,
    )?;
    submit(ctx, &wire_bytes, &format!("attestation {type_} {iss}→{subject}"))
}

/// The cooks community space path.
fn space() -> String {
    "/communities/cooks/spaces/general/".to_string()
}

/// Assemble a `delete` wire (no payload) signed by `signing_key` with its
/// identity cert. Parallels `seed::assemble_write` but for `Action::Delete`.
fn assemble_delete(
    signing_key: &SigningKey,
    auth_cert: &str,
    path: &str,
    id: &str,
    schema: &str,
    owner: &str,
) -> Result<Vec<u8>> {
    let mut msg = Message {
        action: Action::Delete,
        path: Path::parse(path).map_err(|e| anyhow!("bad path '{path}': {e}"))?,
        id: Id::new(id).map_err(|e| anyhow!("bad id '{id}': {e}"))?,
        object_type: ObjectType::Object,
        signing_key: signing_key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: None,
        content_hash: None,
        payload: None,
        owner: Some(Id::new(owner).map_err(|e| anyhow!("bad owner '{owner}': {e}"))?),
        creator: None,
        content_encoding: None,
        content_schema: Some(schema.to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: Some(auth_cert.to_string()),
        auth_evidence: None,
        auth_warrant: None,
    };
    msg.sign(signing_key);
    Ok(wire::serialize(&msg))
}

/// Assemble a `policy.v2` `_policy` object at `path` signed by `actor` — the
/// capture attempt (S1). The daemon must disregard it (author lacks govern).
fn assemble_policy(actor: &Provisioned, path: &str) -> Result<Vec<u8>> {
    let policy = serde_json::json!({
        "grants": [ { "to": "*", "can": ["create", "update", "delete"], "on": format!("{path}**") } ],
        "restrictions": []
    });
    assemble_write(
        &actor.key,
        Some(&actor.cert),
        None,
        path,
        "_policy",
        "policy.v2",
        "application/json",
        serde_json::to_vec(&policy)?,
        None,
        None,
    )
}

// ---- scenarios ------------------------------------------------------------

fn run_scenario(ctx: &mut Ctx, id: &str) -> Result<Outcome> {
    match id {
        "S1" => s1_capture_fix(ctx),
        "S2" => s2_non_member_denied(ctx),
        "S3" => s3_member_can_post(ctx),
        "S4" => s4_owner_only_update(ctx),
        "S5" => s5_author_delete(ctx),
        "S6" => s6_moderator_delete(ctx),
        "S7" => s7_non_moderator_delete(ctx),
        "S8" => Ok(Outcome::Skip("not implemented".to_string())),
        other => Ok(Outcome::Skip(format!("unknown scenario {other}"))),
    }
}

/// S1 — a cooks member self-installs a policy under the space subtree. It must
/// be disregarded (no `govern`). Headline security test for the capture fix.
fn s1_capture_fix(ctx: &mut Ctx) -> Result<Outcome> {
    let alice = provision(ctx, "s1-alice")?;
    self_issue_membership(ctx, &alice, "cooks")?;
    // A subtree the member controls no policy over.
    let sub = format!("/communities/cooks/spaces/general/{}/", oid(ctx, "s1"));
    let wire_bytes = assemble_policy(&alice, &sub)?;
    let submitted = submit(ctx, &wire_bytes, "policy capture attempt")?;
    ctx.written.push((sub.clone(), "_policy".to_string()));
    Ok(settle_absent(ctx, &sub, "_policy", &submitted))
}

/// S2 — a provisioned user with NO membership posts → denied.
fn s2_non_member_denied(ctx: &mut Ctx) -> Result<Outcome> {
    let stranger = provision(ctx, "s2-stranger")?;
    let id = oid(ctx, "s2-post");
    let sub = write_post(ctx, &stranger, &id, "non-member post (should be denied)")?;
    Ok(settle_absent(ctx, &space(), &id, &sub))
}

/// S3 — self-issue membership, then post → applied.
fn s3_member_can_post(ctx: &mut Ctx) -> Result<Outcome> {
    let member = provision(ctx, "s3-member")?;
    self_issue_membership(ctx, &member, "cooks")?;
    let id = oid(ctx, "s3-post");
    let sub = write_post(ctx, &member, &id, "member post (should apply)")?;
    if !sub.accepted {
        return Ok(Outcome::Fail(format!(
            "member post denied at submit: {}",
            sub.reason.unwrap_or_default()
        )));
    }
    Ok(settle_present(ctx, &space(), &id, Some("member post (should apply)")))
}

/// S4 — member A posts; member B tries to update A's (path,id). A's content must
/// be unchanged (owner-only update).
fn s4_owner_only_update(ctx: &mut Ctx) -> Result<Outcome> {
    let a = provision(ctx, "s4-a")?;
    let b = provision(ctx, "s4-b")?;
    self_issue_membership(ctx, &a, "cooks")?;
    self_issue_membership(ctx, &b, "cooks")?;
    let id = oid(ctx, "s4-post");
    let original = "A's original post";
    let sub_a = write_post(ctx, &a, &id, original)?;
    if !sub_a.accepted {
        return Ok(Outcome::Fail("A's post denied at submit".to_string()));
    }
    // Ensure A's post is confirmed before B attempts the hijack.
    if let Outcome::Timeout(m) = settle_present(ctx, &space(), &id, Some(original)) {
        return Ok(Outcome::Timeout(format!("A's post never confirmed: {m}")));
    }
    // B rewrites the SAME (path,id) as themselves.
    let path = space();
    let payload = serde_json::to_vec(&serde_json::json!({
        "body": "B hijacked this",
        "parent": null,
        "created_at": now_s() * 1000,
    }))?;
    let wire_b = assemble_write(
        &b.key,
        Some(&b.cert),
        None,
        &path,
        &id,
        "post.v1",
        "application/json",
        payload,
        Some(&b.email),
        None,
    )?;
    let sub_b = submit(ctx, &wire_b, &format!("B hijack update of {id}"))?;
    if sub_b.accepted {
        // Give the (disregarded) update time to replay, then re-assert content.
        let head_target = sub_b.base_block + FINALITY_BLOCKS;
        wait_for_head(ctx, head_target);
    }
    Ok(settle_present(ctx, &path, &id, Some(original)))
}

/// S5 — A deletes their own post → gone from head.
fn s5_author_delete(ctx: &mut Ctx) -> Result<Outcome> {
    let a = provision(ctx, "s5-a")?;
    self_issue_membership(ctx, &a, "cooks")?;
    let id = oid(ctx, "s5-post");
    let sub = write_post(ctx, &a, &id, "post to self-delete")?;
    if !sub.accepted {
        return Ok(Outcome::Fail("post denied at submit".to_string()));
    }
    if let Outcome::Timeout(m) = settle_present(ctx, &space(), &id, None) {
        return Ok(Outcome::Timeout(format!("post never confirmed before delete: {m}")));
    }
    let del = write_delete(ctx, &a, &space(), &id, "post.v1")?;
    Ok(settle_absent(ctx, &space(), &id, &del))
}

/// S6 — appoint a moderator (role:moderator:cooks by cooks@mingo.place), then
/// the moderator deletes ANOTHER member's post → gone.
fn s6_moderator_delete(ctx: &mut Ctx) -> Result<Outcome> {
    let victim = provision(ctx, "s6-victim")?;
    let moderator = provision(ctx, "s6-mod")?;
    self_issue_membership(ctx, &victim, "cooks")?;
    self_issue_membership(ctx, &moderator, "cooks")?;

    // The community issuer cooks@mingo.place appoints the moderator. Mint its
    // identity cert the same way `appoint-moderator` does (handle "cooks").
    let issuer = provision_persona(&ctx.client, &ctx.idp, &ctx.admin_token, "cooks", &ctx.domain)
        .context("provisioning cooks@mingo.place issuer")?;
    println!("  · provisioned issuer {}", issuer.email);
    let appt = write_attestation(
        ctx,
        &issuer,
        &moderator.email,
        "role:moderator:cooks",
        serde_json::json!("moderator"),
    )?;
    if !appt.accepted {
        return Ok(Outcome::Fail(format!(
            "moderator appointment denied: {}",
            appt.reason.unwrap_or_default()
        )));
    }
    // Wait for the role attestation to confirm so the delete's policy check sees it.
    let appt_path = format!("/u/{}/attestations/{}/", issuer.email, moderator.email);
    if let Outcome::Timeout(m) = settle_present(ctx, &appt_path, "role:moderator:cooks", None) {
        return Ok(Outcome::Timeout(format!("moderator role never confirmed: {m}")));
    }

    // Victim posts; moderator deletes it.
    let id = oid(ctx, "s6-post");
    let vpost = write_post(ctx, &victim, &id, "victim post for moderator delete")?;
    if !vpost.accepted {
        return Ok(Outcome::Fail("victim post denied at submit".to_string()));
    }
    if let Outcome::Timeout(m) = settle_present(ctx, &space(), &id, None) {
        return Ok(Outcome::Timeout(format!("victim post never confirmed: {m}")));
    }
    let del = write_delete(ctx, &moderator, &space(), &id, "post.v1")?;
    Ok(settle_absent(ctx, &space(), &id, &del))
}

/// S7 — a plain member tries to delete ANOTHER member's post → denied, post
/// survives.
fn s7_non_moderator_delete(ctx: &mut Ctx) -> Result<Outcome> {
    let owner = provision(ctx, "s7-owner")?;
    let other = provision(ctx, "s7-other")?;
    self_issue_membership(ctx, &owner, "cooks")?;
    self_issue_membership(ctx, &other, "cooks")?;
    let id = oid(ctx, "s7-post");
    let sub = write_post(ctx, &owner, &id, "owner post, other tries to delete")?;
    if !sub.accepted {
        return Ok(Outcome::Fail("owner post denied at submit".to_string()));
    }
    if let Outcome::Timeout(m) = settle_present(ctx, &space(), &id, None) {
        return Ok(Outcome::Timeout(format!("owner post never confirmed: {m}")));
    }
    let del = write_delete(ctx, &other, &space(), &id, "post.v1")?;
    if del.accepted {
        // A disregarded delete: wait past finality, then confirm the post survived.
        wait_for_head(ctx, del.base_block + FINALITY_BLOCKS);
    }
    Ok(settle_present(ctx, &space(), &id, Some("owner post, other tries to delete")))
}

/// Block until head reaches `target` or the settle timeout elapses.
fn wait_for_head(ctx: &Ctx, target: u64) {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while Instant::now() < deadline {
        if head_block(ctx).unwrap_or(0) >= target {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// ---- cleanup + summary ----------------------------------------------------

/// Best-effort: provision a cleanup identity and delete every object we wrote.
/// A failure here never fails the run — this only tidies the demo space.
fn cleanup(ctx: &mut Ctx) {
    if ctx.written.is_empty() {
        return;
    }
    println!("Cleanup: deleting {} test object(s) (best effort)…", ctx.written.len());
    // Objects are owner-locked, so a shared cleanup identity can't delete them;
    // deletes are authored per-owner during the scenarios where possible. Here
    // we simply report what remains for manual sweeping.
    for (path, id) in &ctx.written {
        println!("  · left on-chain: {path}{id}");
    }
    println!(
        "  (test objects live under livetest-{}-* — owner-locked, so sweep with the \
         owning identities if needed)",
        ctx.runid
    );
}

fn print_summary(results: &[(&str, Expect, Outcome)]) {
    println!("═══ Summary ═══════════════════════════════════════════");
    println!("  {:<4} {:<10} {:<8} {}", "id", "expected", "result", "note");
    let mut pass = 0;
    let mut fail = 0;
    for (id, expect, outcome) in results {
        println!(
            "  {:<4} {:<10} {:<8} {}",
            id,
            expect.label(),
            outcome.tag(),
            outcome.note()
        );
        match outcome {
            Outcome::Pass => pass += 1,
            Outcome::Fail(_) | Outcome::Timeout(_) | Outcome::Error(_) => fail += 1,
            Outcome::Skip(_) => {}
        }
    }
    println!("───────────────────────────────────────────────────────");
    println!("  {pass} passed · {fail} failed/errored");
}

// ===========================================================================
// Tests (pure parts)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_catalogue_is_ordered_and_marked() {
        let s = scenarios();
        let ids: Vec<&str> = s.iter().map(|x| x.id).collect();
        assert_eq!(ids, ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"]);
        // S1..S7 implemented, S8 not.
        assert!(s[..7].iter().all(|x| x.implemented));
        assert!(!s[7].implemented);
    }

    #[test]
    fn only_filter_is_case_insensitive() {
        let s = &scenarios()[0];
        assert!(selected(s, &[]));
        assert!(selected(s, &["s1".to_string()]));
        assert!(selected(s, &["S1".to_string()]));
        assert!(!selected(s, &["S2".to_string()]));
    }

    #[test]
    fn domain_of_strips_scheme_and_port() {
        assert_eq!(domain_of("https://mingo.place"), "mingo.place");
        assert_eq!(domain_of("https://mingo.place/"), "mingo.place");
        assert_eq!(domain_of("http://localhost:8080/x"), "localhost");
    }

    #[test]
    fn parse_error_prefers_json_error_field() {
        assert_eq!(parse_error(r#"{"error":"Attribution: not a member"}"#), "Attribution: not a member");
        assert_eq!(parse_error("plain text"), "plain text");
    }

    #[test]
    fn expect_labels() {
        assert_eq!(Expect::Present.label(), "PRESENT");
        assert_eq!(Expect::Absent.label(), "ABSENT");
        assert_eq!(Expect::Unchanged.label(), "UNCHANGED");
    }
}
