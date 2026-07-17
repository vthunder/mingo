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
    /// Sys key file for the P2-P4 policy scenarios (S9-S13).
    pub sys_key_file: String,
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
        // P2-P4 policy-delegation scenarios. Sys-signed policy objects installed
        // under a throwaway /livetest-p234-<runid>-*/ subtree (need --sys-key-file).
        Scenario {
            id: "S9",
            title: "P2 pinning immunity (sovereignty vs revocable)",
            expect: Expect::Present,
            implemented: true,
            detail: "ancestor A grants sys govern; child C pins A@v1, sibling D \
                     tracks. Amend A→v2 removing sys govern. Update C (pinned) \
                     APPLIES; update D (tracking) DENIED.",
        },
        Scenario {
            id: "S10",
            title: "P2 creation pin must be latest",
            expect: Expect::Present,
            implemented: true,
            detail: "with A at latest, a child pinned to a STALE A hash is \
                     REJECTED; a child pinned to the latest hash is ACCEPTED.",
        },
        Scenario {
            id: "S11",
            title: "P2 forward-only pin advance",
            expect: Expect::Present,
            implemented: true,
            detail: "child pinned to A@v2; amend A→v3. Update child pin→v3 \
                     (forward) ACCEPTED; update pin→older (backward) REJECTED.",
        },
        Scenario {
            id: "S12",
            title: "P3 descendant-constraint (subset grants + mandated restriction)",
            expect: Expect::Present,
            implemented: true,
            detail: "A templates allowed_grants G + mandated restriction R. Child \
                     with grant exceeding G REJECTED; child missing R REJECTED; \
                     child subset-of-G carrying R ACCEPTED.",
        },
        Scenario {
            id: "S13",
            title: "P4 no-pin (forbid_pinning)",
            expect: Expect::Present,
            implemented: true,
            detail: "A sets descendant_constraint.forbid_pinning. A PINNED child \
                     REJECTED; an unpinned (tracking) child ACCEPTED.",
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
    #[serde(default)]
    object_hash: String,
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
    /// Sys signing key + its `ed25519:<hex>` owner string, for the P2-P4 policy
    /// scenarios. None when no sys key file loaded (S9-S13 then SKIP).
    sys: Option<SysKey>,
    /// Sys-owned policy objects installed this run (path, id) — swept in cleanup.
    written_policies: Vec<(String, String)>,
}

/// The sys identity for key-rooted policy writes: the signing key (admin role /
/// govern on `/**`) and its owner reference (`ed25519:<hex pubkey>`).
struct SysKey {
    key: SigningKey,
    owner: String,
}

/// Load the sys key from a file (same formats as `seed --sys-key`), deriving its
/// `ed25519:<hex>` owner string. `~` is expanded to $HOME.
fn load_sys_key(path: &str) -> Result<SysKey> {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest)
    } else {
        path.to_string()
    };
    let key = crate::seed::load_signing_key_file(&expanded)?;
    let owner = format!("ed25519:{}", hex::encode(key.public_key().bytes));
    Ok(SysKey { key, owner })
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

    // Load the sys key for the P2-P4 policy scenarios (best-effort: if it's
    // absent, S9-S13 SKIP rather than aborting the identity scenarios).
    let sys = match load_sys_key(&args.sys_key_file) {
        Ok(s) => {
            println!("Sys key loaded ({}) for P2-P4 policy scenarios", s.owner);
            Some(s)
        }
        Err(e) => {
            println!("Sys key not loaded ({e:#}) — P2-P4 scenarios (S9-S13) will SKIP");
            None
        }
    };

    let mut ctx = Ctx {
        client,
        idp: args.idp.clone(),
        daemon: args.daemon.clone(),
        admin_token,
        domain: domain.to_string(),
        runid: make_runid(),
        keep: args.keep,
        written: Vec::new(),
        sys,
        written_policies: Vec::new(),
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
        println!(
            "--keep: leaving {} content + {} policy object(s) on-chain.",
            ctx.written.len(),
            ctx.written_policies.len()
        );
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

/// Poll until a delete-that-should-succeed has removed the object from head
/// (`/v1/object` 404s). The object is expected to START present (confirmed) and
/// disappear; during the delete's confirmation window the daemon still serves it
/// as `confirmed:false`, so we keep waiting until it is truly gone. A delete
/// denied at submit fails fast.
fn wait_deleted(ctx: &Ctx, path: &str, id: &str, sub: &Submitted) -> Outcome {
    if !sub.accepted {
        return Outcome::Fail(format!(
            "delete denied at submit: {}",
            sub.reason.clone().unwrap_or_default()
        ));
    }
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        match get_object(ctx, path, id) {
            Ok(None) => return Outcome::Pass,
            Ok(Some(_)) => {} // still present (pending delete or not yet applied) — wait
            Err(e) => return Outcome::Error(format!("{e:#}")),
        }
        if Instant::now() >= deadline {
            return Outcome::Timeout(format!(
                "object still present at {path}{id} — delete never took effect"
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Gate a dependent step on a prerequisite write being CONFIRMED in head (a
/// membership, an attestation, a post a later step deletes). Errors if it never
/// confirms — a broken precondition is a runner error, not a product FAIL.
fn require_present(ctx: &Ctx, path: &str, id: &str, what: &str) -> Result<()> {
    match settle_present(ctx, path, id, None) {
        Outcome::Pass => {
            println!("  · confirmed {what} in head");
            Ok(())
        }
        other => bail!("{what} never confirmed in head: {}", other.note()),
    }
}

/// Self-issue `membership:<comm>` and block until it is confirmed in head, so a
/// subsequent post/delete is authorized at submit-time validation.
fn join_and_confirm(ctx: &Ctx, actor: &Provisioned, comm: &str) -> Result<()> {
    let sub = self_issue_membership(ctx, actor, comm)?;
    if !sub.accepted {
        bail!(
            "membership self-issue denied at submit: {}",
            sub.reason.unwrap_or_default()
        );
    }
    let addr = &actor.email;
    let path = format!("/u/{addr}/attestations/{addr}/");
    require_present(ctx, &path, &format!("membership-{comm}"), &format!("{addr} membership:{comm}"))
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
    let wire_bytes = assemble_delete(&actor.key, Some(&actor.cert), path, id, schema, &actor.email)?;
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
    auth_cert: Option<&str>,
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
        auth_cert: auth_cert.map(str::to_string),
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
        "S9" => s9_pinning_immunity(ctx),
        "S10" => s10_creation_pin_latest(ctx),
        "S11" => s11_forward_only(ctx),
        "S12" => s12_descendant_constraint(ctx),
        "S13" => s13_no_pin(ctx),
        other => Ok(Outcome::Skip(format!("unknown scenario {other}"))),
    }
}

// ---- P2-P4 policy primitives (sys-signed, key-rooted) ---------------------

/// Install (or amend) a sys-signed `policy.v2` object at (path,id). Key-rooted:
/// Owner = the sys pubkey, signed by the sys key, no cert (the root policy
/// grants the sys admin key `govern` on `/**`). Returns the submit outcome and
/// the policy's on-chain content-hash (`sha256:<hex>` of the payload — what a
/// child PINS), computed exactly as the daemon indexes it.
fn sys_install(
    ctx: &mut Ctx,
    path: &str,
    id: &str,
    policy: &serde_json::Value,
    label: &str,
) -> Result<(Submitted, String)> {
    let (wire_bytes, content_hash) = {
        let sys = ctx.sys.as_ref().ok_or_else(|| anyhow!("no sys key loaded"))?;
        let payload = serde_json::to_vec(policy)?;
        let content_hash = ContentHash::sha256(&payload).to_string();
        let wire = assemble_write(
            &sys.key,
            None,
            None,
            path,
            id,
            "policy.v2",
            "application/json",
            payload,
            Some(&sys.owner),
            None,
        )?;
        (wire, content_hash)
    };
    let sub = submit(ctx, &wire_bytes, label)?;
    ctx.written_policies.push((path.to_string(), id.to_string()));
    Ok((sub, content_hash))
}

/// The current on-chain `object_hash` of an object, or None if absent. Used to
/// tell an APPLIED policy amendment (hash changed) from a DENIED one (unchanged).
fn object_hash(ctx: &Ctx, path: &str, id: &str) -> Result<Option<String>> {
    Ok(get_object(ctx, path, id)?.map(|o| o.object_hash))
}

/// Poll until the object's `object_hash` differs from `old` and is confirmed —
/// proof a policy amendment/update was APPLIED. Timeout otherwise.
fn wait_version_change(ctx: &Ctx, path: &str, id: &str, old: &str) -> Outcome {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        match get_object(ctx, path, id) {
            Ok(Some(o)) if o.confirmed && o.object_hash != old => return Outcome::Pass,
            Ok(_) => {}
            Err(e) => return Outcome::Error(format!("{e:#}")),
        }
        if Instant::now() >= deadline {
            return Outcome::Timeout(format!("policy at {path}{id} never changed version"));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// A sys `govern` grant over `<base>**` (lets sys install child policies there).
fn sys_govern_grant(ctx: &Ctx, base: &str) -> serde_json::Value {
    let owner = &ctx.sys.as_ref().expect("sys key present").owner;
    serde_json::json!({ "to": { "key": owner }, "can": ["govern"], "on": format!("{base}**") })
}

/// The throwaway subtree root for a P2-P4 scenario: `/livetest-p234-<runid>-<tag>/`.
fn p234_base(ctx: &Ctx, tag: &str) -> String {
    format!("/livetest-p234-{}-{}/", ctx.runid, tag)
}

/// Guard: the P2-P4 scenarios need a sys key. Returns Skip when absent.
fn need_sys(ctx: &Ctx) -> Option<Outcome> {
    if ctx.sys.is_none() {
        Some(Outcome::Skip("no --sys-key-file loaded".to_string()))
    } else {
        None
    }
}

/// S1 — a cooks member self-installs a policy under the space subtree. It must
/// be disregarded (no `govern`). Headline security test for the capture fix.
fn s1_capture_fix(ctx: &mut Ctx) -> Result<Outcome> {
    let alice = provision(ctx, "s1-alice")?;
    join_and_confirm(ctx, &alice, "cooks")?;
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
    join_and_confirm(ctx, &member, "cooks")?;
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
    join_and_confirm(ctx, &a, "cooks")?;
    join_and_confirm(ctx, &b, "cooks")?;
    let id = oid(ctx, "s4-post");
    let original = "A's original post";
    let sub_a = write_post(ctx, &a, &id, original)?;
    if !sub_a.accepted {
        return Ok(Outcome::Fail("A's post denied at submit".to_string()));
    }
    // Ensure A's post is confirmed before B attempts the hijack.
    require_present(ctx, &space(), &id, "A's post")?;
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
    join_and_confirm(ctx, &a, "cooks")?;
    let id = oid(ctx, "s5-post");
    let sub = write_post(ctx, &a, &id, "post to self-delete")?;
    if !sub.accepted {
        return Ok(Outcome::Fail("post denied at submit".to_string()));
    }
    // The post must be CONFIRMED before the author deletes it (the delete's
    // owner check reads confirmed head state).
    require_present(ctx, &space(), &id, "post to delete")?;
    let del = write_delete(ctx, &a, &space(), &id, "post.v1")?;
    Ok(wait_deleted(ctx, &space(), &id, &del))
}

/// S6 — appoint a moderator (role:moderator:cooks by cooks@mingo.place), then
/// the moderator deletes ANOTHER member's post → gone.
fn s6_moderator_delete(ctx: &mut Ctx) -> Result<Outcome> {
    let victim = provision(ctx, "s6-victim")?;
    let moderator = provision(ctx, "s6-mod")?;
    join_and_confirm(ctx, &victim, "cooks")?;
    join_and_confirm(ctx, &moderator, "cooks")?;

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
    // The role attestation MUST be confirmed in head before the moderator's
    // delete — otherwise submit-time validation sees no role and denies it
    // (the S6 failure the first live run hit).
    let appt_path = format!("/u/{}/attestations/{}/", issuer.email, moderator.email);
    require_present(ctx, &appt_path, "role:moderator:cooks", "moderator role attestation")?;

    // Victim posts; the post must confirm before the moderator deletes it.
    let id = oid(ctx, "s6-post");
    let vpost = write_post(ctx, &victim, &id, "victim post for moderator delete")?;
    if !vpost.accepted {
        return Ok(Outcome::Fail("victim post denied at submit".to_string()));
    }
    require_present(ctx, &space(), &id, "victim post")?;
    let del = write_delete(ctx, &moderator, &space(), &id, "post.v1")?;
    Ok(wait_deleted(ctx, &space(), &id, &del))
}

/// S7 — a plain member tries to delete ANOTHER member's post → denied, post
/// survives.
fn s7_non_moderator_delete(ctx: &mut Ctx) -> Result<Outcome> {
    let owner = provision(ctx, "s7-owner")?;
    let other = provision(ctx, "s7-other")?;
    join_and_confirm(ctx, &owner, "cooks")?;
    join_and_confirm(ctx, &other, "cooks")?;
    let id = oid(ctx, "s7-post");
    let sub = write_post(ctx, &owner, &id, "owner post, other tries to delete")?;
    if !sub.accepted {
        return Ok(Outcome::Fail("owner post denied at submit".to_string()));
    }
    require_present(ctx, &space(), &id, "owner post")?;
    let del = write_delete(ctx, &other, &space(), &id, "post.v1")?;
    if del.accepted {
        // A disregarded delete: wait past finality, then confirm the post survived.
        wait_for_head(ctx, del.base_block + FINALITY_BLOCKS);
    }
    Ok(settle_present(ctx, &space(), &id, Some("owner post, other tries to delete")))
}

// ---- P2-P4 scenarios ------------------------------------------------------

/// S9 — pinning immunity (sovereignty vs revocable). Child C pins ancestor A@v1;
/// sibling D tracks A. After A is amended to remove sys govern, updating C (whose
/// governance is frozen at v1) still APPLIES, while updating D (tracking latest)
/// is DENIED.
fn s9_pinning_immunity(ctx: &mut Ctx) -> Result<Outcome> {
    if let Some(skip) = need_sys(ctx) {
        return Ok(skip);
    }
    let base = p234_base(ctx, "s9");
    let child_a = format!("{base}childA/");
    let child_b = format!("{base}childB/");

    // A_v1: grants sys govern over the subtree.
    let a_v1 = serde_json::json!({ "grants": [ sys_govern_grant(ctx, &base) ] });
    let (sub_a, h_a1) = sys_install(ctx, &base, "root", &a_v1, "A_v1 install")?;
    if !sub_a.accepted {
        return Ok(Outcome::Fail(format!("A_v1 install denied: {}", sub_a.reason.unwrap_or_default())));
    }
    require_present(ctx, &base, "root", "ancestor A")?;

    // C pinned to A@v1 (sovereign).
    let c_v1 = serde_json::json!({ "pin": { "ancestor": base, "hash": h_a1 }, "grants": [] });
    let (sub_c, _) = sys_install(ctx, &child_a, "root", &c_v1, "C pinned@A_v1")?;
    if !sub_c.accepted {
        return Ok(Outcome::Fail(format!("C install denied: {}", sub_c.reason.unwrap_or_default())));
    }
    require_present(ctx, &child_a, "root", "child C")?;

    // D unpinned (tracks A).
    let d_v1 = serde_json::json!({ "grants": [] });
    let (sub_d, _) = sys_install(ctx, &child_b, "root", &d_v1, "D unpinned")?;
    if !sub_d.accepted {
        return Ok(Outcome::Fail(format!("D install denied: {}", sub_d.reason.unwrap_or_default())));
    }
    require_present(ctx, &child_b, "root", "child D")?;

    // Amend A -> v2, REMOVING sys govern (hand govern to a throwaway key).
    let a_oh = object_hash(ctx, &base, "root")?.unwrap_or_default();
    let throwaway = SigningKey::generate();
    let rand_owner = format!("ed25519:{}", hex::encode(throwaway.public_key().bytes));
    let a_v2 = serde_json::json!({
        "grants": [ { "to": { "key": rand_owner }, "can": ["govern"], "on": format!("{base}**") } ]
    });
    let (sub_a2, _) = sys_install(ctx, &base, "root", &a_v2, "A_v2 (revoke sys govern)")?;
    if !sub_a2.accepted {
        return Ok(Outcome::Fail(format!("A_v2 amend denied: {}", sub_a2.reason.unwrap_or_default())));
    }
    if let Outcome::Timeout(m) = wait_version_change(ctx, &base, "root", &a_oh) {
        return Ok(Outcome::Timeout(format!("A_v2 never applied: {m}")));
    }

    // Update C — still pinned to A@v1 (keeping the frozen pin). Should APPLY.
    let c_oh = object_hash(ctx, &child_a, "root")?.unwrap_or_default();
    let c_v2 = serde_json::json!({
        "pin": { "ancestor": base, "hash": h_a1 },
        "grants": [],
        "deny": [ format!("{child_a}zzz*") ]
    });
    let (sub_cu, _) = sys_install(ctx, &child_a, "root", &c_v2, "update C (pinned@v1)")?;
    let c_applied = sub_cu.accepted
        && matches!(wait_version_change(ctx, &child_a, "root", &c_oh), Outcome::Pass);

    // Update D — tracks A_v2, which no longer grants sys govern. Should DENY.
    let d_oh = object_hash(ctx, &child_b, "root")?.unwrap_or_default();
    let d_v2 = serde_json::json!({ "grants": [], "deny": [ format!("{child_b}zzz*") ] });
    let (sub_du, _) = sys_install(ctx, &child_b, "root", &d_v2, "update D (tracking v2)")?;
    let d_now = object_hash(ctx, &child_b, "root")?.unwrap_or_default();
    let d_denied = !sub_du.accepted && d_now == d_oh;

    match (c_applied, d_denied) {
        (true, true) => Ok(Outcome::Pass),
        (false, _) => Ok(Outcome::Fail(
            "pinned child C update was NOT applied — sovereignty broken (frozen v1 should still grant sys govern)".to_string(),
        )),
        (_, false) => Ok(Outcome::Fail(format!(
            "tracking child D update was NOT denied — revocation broken (submit accepted={}, reason={:?})",
            sub_du.accepted, sub_du.reason
        ))),
    }
}

/// S10 — creation pin must equal the current latest ancestor version.
fn s10_creation_pin_latest(ctx: &mut Ctx) -> Result<Outcome> {
    if let Some(skip) = need_sys(ctx) {
        return Ok(skip);
    }
    let base = p234_base(ctx, "s10");
    // A_v1 then amend to A_v2 so v1's hash is STALE.
    let a_v1 = serde_json::json!({ "grants": [ sys_govern_grant(ctx, &base) ] });
    let (sa, h_stale) = sys_install(ctx, &base, "root", &a_v1, "A_v1")?;
    if !sa.accepted {
        return Ok(Outcome::Fail("A_v1 denied".to_string()));
    }
    require_present(ctx, &base, "root", "ancestor A")?;
    let a_oh = object_hash(ctx, &base, "root")?.unwrap_or_default();
    let a_v2 = serde_json::json!({ "grants": [ sys_govern_grant(ctx, &base) ], "deny": [ format!("{base}zzz*") ] });
    let (sa2, h_latest) = sys_install(ctx, &base, "root", &a_v2, "A_v2 (new latest)")?;
    if !sa2.accepted || matches!(wait_version_change(ctx, &base, "root", &a_oh), Outcome::Timeout(_)) {
        return Ok(Outcome::Fail("A_v2 amend not applied".to_string()));
    }

    // Child pinned to the STALE hash — must be REJECTED.
    let stale_path = format!("{base}childStale/");
    let stale = serde_json::json!({ "pin": { "ancestor": base, "hash": h_stale }, "grants": [] });
    let (sub_stale, _) = sys_install(ctx, &stale_path, "root", &stale, "child pinned@STALE")?;
    let stale_absent = matches!(settle_absent(ctx, &stale_path, "root", &sub_stale), Outcome::Pass);

    // Child pinned to the LATEST hash — must be ACCEPTED.
    let latest_path = format!("{base}childLatest/");
    let latest = serde_json::json!({ "pin": { "ancestor": base, "hash": h_latest }, "grants": [] });
    let (sub_latest, _) = sys_install(ctx, &latest_path, "root", &latest, "child pinned@LATEST")?;
    let latest_present = sub_latest.accepted
        && matches!(settle_present(ctx, &latest_path, "root", None), Outcome::Pass);

    match (stale_absent, latest_present) {
        (true, true) => Ok(Outcome::Pass),
        (false, _) => Ok(Outcome::Fail("stale-pinned child was NOT rejected".to_string())),
        (_, false) => Ok(Outcome::Fail(format!(
            "latest-pinned child was NOT accepted (submit accepted={}, reason={:?})",
            sub_latest.accepted, sub_latest.reason
        ))),
    }
}

/// S11 — forward-only pin advance: a child may re-pin to the current latest
/// ancestor version, never to an older one.
fn s11_forward_only(ctx: &mut Ctx) -> Result<Outcome> {
    if let Some(skip) = need_sys(ctx) {
        return Ok(skip);
    }
    let base = p234_base(ctx, "s11");
    let child = format!("{base}child/");
    let grant = sys_govern_grant(ctx, &base);

    // A_v1 → A_v2 (child will be created pinned to v2).
    let (s1, _h1) = sys_install(ctx, &base, "root", &serde_json::json!({ "grants": [grant.clone()] }), "A_v1")?;
    if !s1.accepted {
        return Ok(Outcome::Fail("A_v1 denied".to_string()));
    }
    require_present(ctx, &base, "root", "ancestor A")?;
    let oh1 = object_hash(ctx, &base, "root")?.unwrap_or_default();
    let (s2, h2) = sys_install(ctx, &base, "root",
        &serde_json::json!({ "grants": [grant.clone()], "deny": [ format!("{base}a*") ] }), "A_v2")?;
    if !s2.accepted || matches!(wait_version_change(ctx, &base, "root", &oh1), Outcome::Timeout(_)) {
        return Ok(Outcome::Fail("A_v2 not applied".to_string()));
    }

    // Child pinned to A@v2.
    let (sc, _) = sys_install(ctx, &child, "root",
        &serde_json::json!({ "pin": { "ancestor": base, "hash": h2 }, "grants": [] }), "child pinned@v2")?;
    if !sc.accepted {
        return Ok(Outcome::Fail(format!("child install denied: {}", sc.reason.unwrap_or_default())));
    }
    require_present(ctx, &child, "root", "child")?;

    // Amend A → v3.
    let oh2 = object_hash(ctx, &base, "root")?.unwrap_or_default();
    let (s3, h3) = sys_install(ctx, &base, "root",
        &serde_json::json!({ "grants": [grant.clone()], "deny": [ format!("{base}a*"), format!("{base}b*") ] }), "A_v3")?;
    if !s3.accepted || matches!(wait_version_change(ctx, &base, "root", &oh2), Outcome::Timeout(_)) {
        return Ok(Outcome::Fail("A_v3 not applied".to_string()));
    }

    // Forward: re-pin child to v3 (== latest) — ACCEPT.
    let ch_oh = object_hash(ctx, &child, "root")?.unwrap_or_default();
    let (sf, _) = sys_install(ctx, &child, "root",
        &serde_json::json!({ "pin": { "ancestor": base, "hash": h3 }, "grants": [] }), "child re-pin→v3 (forward)")?;
    let forward_ok = sf.accepted
        && matches!(wait_version_change(ctx, &child, "root", &ch_oh), Outcome::Pass);

    // Backward: re-pin child to v2 (older than latest v3) — REJECT.
    let ch_oh2 = object_hash(ctx, &child, "root")?.unwrap_or_default();
    let (sb, _) = sys_install(ctx, &child, "root",
        &serde_json::json!({ "pin": { "ancestor": base, "hash": h2 }, "grants": [] }), "child re-pin→v2 (backward)")?;
    let backward_now = object_hash(ctx, &child, "root")?.unwrap_or_default();
    let backward_denied = !sb.accepted && backward_now == ch_oh2;

    match (forward_ok, backward_denied) {
        (true, true) => Ok(Outcome::Pass),
        (false, _) => Ok(Outcome::Fail("forward re-pin (→latest) was NOT accepted".to_string())),
        (_, false) => Ok(Outcome::Fail(format!(
            "backward re-pin (→older) was NOT rejected (submit accepted={}, reason={:?})",
            sb.accepted, sb.reason
        ))),
    }
}

/// S12 — descendant-constraint: a child must keep its grants within the parent's
/// `allowed_grants` template and carry every mandated restriction verbatim.
fn s12_descendant_constraint(ctx: &mut Ctx) -> Result<Outcome> {
    if let Some(skip) = need_sys(ctx) {
        return Ok(skip);
    }
    let base = p234_base(ctx, "s12");
    let subtree = format!("{base}**");
    // Template grant G and mandated restriction R (byte-exact in valid children).
    let g = serde_json::json!({ "to": "*", "can": ["create"], "on": subtree });
    let r = serde_json::json!({ "on": subtree, "require": { "max_size": 65536 } });
    let a = serde_json::json!({
        "grants": [ sys_govern_grant(ctx, &base) ],
        "descendant_constraint": { "allowed_grants": [ g.clone() ], "mandated_restrictions": [ r.clone() ] }
    });
    let (sa, _) = sys_install(ctx, &base, "root", &a, "A (with descendant_constraint)")?;
    if !sa.accepted {
        return Ok(Outcome::Fail(format!("A install denied: {}", sa.reason.unwrap_or_default())));
    }
    require_present(ctx, &base, "root", "ancestor A")?;

    // Child whose grant EXCEEDS the template (adds `update`) — REJECT.
    let bad_path = format!("{base}childBad/");
    let bad = serde_json::json!({
        "grants": [ { "to": "*", "can": ["create", "update"], "on": subtree } ],
        "restrictions": [ r.clone() ]
    });
    let (sub_bad, _) = sys_install(ctx, &bad_path, "root", &bad, "child grant exceeds template")?;
    let bad_absent = matches!(settle_absent(ctx, &bad_path, "root", &sub_bad), Outcome::Pass);

    // Child MISSING the mandated restriction — REJECT.
    let miss_path = format!("{base}childMissing/");
    let miss = serde_json::json!({ "grants": [ g.clone() ] });
    let (sub_miss, _) = sys_install(ctx, &miss_path, "root", &miss, "child missing mandated restriction")?;
    let miss_absent = matches!(settle_absent(ctx, &miss_path, "root", &sub_miss), Outcome::Pass);

    // Child subset-of-G AND carrying R — ACCEPT.
    let good_path = format!("{base}childGood/");
    let good = serde_json::json!({ "grants": [ g.clone() ], "restrictions": [ r.clone() ] });
    let (sub_good, _) = sys_install(ctx, &good_path, "root", &good, "child within template")?;
    let good_present = sub_good.accepted
        && matches!(settle_present(ctx, &good_path, "root", None), Outcome::Pass);

    match (bad_absent, miss_absent, good_present) {
        (true, true, true) => Ok(Outcome::Pass),
        (false, _, _) => Ok(Outcome::Fail("over-broad-grant child was NOT rejected".to_string())),
        (_, false, _) => Ok(Outcome::Fail("child missing mandated restriction was NOT rejected".to_string())),
        (_, _, false) => Ok(Outcome::Fail(format!(
            "compliant child was NOT accepted (submit accepted={}, reason={:?})",
            sub_good.accepted, sub_good.reason
        ))),
    }
}

/// S13 — no-pin: a parent that forbids pinning rejects any pinned child; an
/// unpinned (tracking) child is accepted.
fn s13_no_pin(ctx: &mut Ctx) -> Result<Outcome> {
    if let Some(skip) = need_sys(ctx) {
        return Ok(skip);
    }
    let base = p234_base(ctx, "s13");
    // forbid_pinning ⇒ empty allowed_grants ⇒ children may grant nothing.
    let a = serde_json::json!({
        "grants": [ sys_govern_grant(ctx, &base) ],
        "descendant_constraint": { "forbid_pinning": true }
    });
    let (sa, h_a) = sys_install(ctx, &base, "root", &a, "A (forbid_pinning)")?;
    if !sa.accepted {
        return Ok(Outcome::Fail(format!("A install denied: {}", sa.reason.unwrap_or_default())));
    }
    require_present(ctx, &base, "root", "ancestor A")?;

    // Pinned child (pin to latest, so ONLY the no-pin rule can reject) — REJECT.
    let pinned_path = format!("{base}childPinned/");
    let pinned = serde_json::json!({ "pin": { "ancestor": base, "hash": h_a }, "grants": [] });
    let (sub_pin, _) = sys_install(ctx, &pinned_path, "root", &pinned, "pinned child (parent forbids)")?;
    let pinned_absent = matches!(settle_absent(ctx, &pinned_path, "root", &sub_pin), Outcome::Pass);

    // Unpinned tracking child, no grants — ACCEPT.
    let open_path = format!("{base}childOpen/");
    let open = serde_json::json!({ "grants": [] });
    let (sub_open, _) = sys_install(ctx, &open_path, "root", &open, "unpinned tracking child")?;
    let open_present = sub_open.accepted
        && matches!(settle_present(ctx, &open_path, "root", None), Outcome::Pass);

    match (pinned_absent, open_present) {
        (true, true) => Ok(Outcome::Pass),
        (false, _) => Ok(Outcome::Fail("pinned child was NOT rejected under forbid_pinning".to_string())),
        (_, false) => Ok(Outcome::Fail(format!(
            "unpinned child was NOT accepted (submit accepted={}, reason={:?})",
            sub_open.accepted, sub_open.reason
        ))),
    }
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

/// Best-effort cleanup. Sys-owned policy objects (S9-S13) CAN be swept — sys
/// holds `govern` at their parent — so we delete them, children before parents.
/// Content objects (S1-S7) are owner-locked to disposable per-scenario identities
/// we no longer hold keys for, so those are only reported. A failure here never
/// fails the run.
fn cleanup(ctx: &mut Ctx) {
    // Sweep sys-owned policies (reverse install order ≈ children before parents).
    if ctx.sys.is_some() && !ctx.written_policies.is_empty() {
        let policies = ctx.written_policies.clone();
        println!("Cleanup: deleting {} sys-owned policy object(s) (best effort)…", policies.len());
        for (path, id) in policies.iter().rev() {
            match sys_delete_policy(ctx, path, id) {
                Ok(sub) if sub.accepted => println!("  · deleted policy {path}{id}"),
                Ok(sub) => println!("  · could not delete {path}{id}: {}", sub.reason.unwrap_or_default()),
                Err(e) => println!("  · could not delete {path}{id}: {e:#}"),
            }
        }
    }
    // Report owner-locked content objects left behind.
    if !ctx.written.is_empty() {
        println!("Left on-chain (owner-locked, sweep with the owning identities if needed):");
        for (path, id) in &ctx.written {
            println!("  · {path}{id}");
        }
    }
}

/// Delete a sys-owned `policy.v2` object (key-rooted, no cert). Best-effort.
fn sys_delete_policy(ctx: &Ctx, path: &str, id: &str) -> Result<Submitted> {
    let sys = ctx.sys.as_ref().ok_or_else(|| anyhow!("no sys key"))?;
    let wire = assemble_delete(&sys.key, None, path, id, "policy.v2", &sys.owner)?;
    submit(ctx, &wire, &format!("delete policy {path}{id}"))
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
        assert_eq!(
            ids,
            ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13"]
        );
        // Only S8 (ban) is unimplemented; everything else is.
        assert!(s.iter().filter(|x| !x.implemented).map(|x| x.id).eq(["S8"]));
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
