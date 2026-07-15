//! `mingo seed` — seed a lived-in demo corpus into a running SBO daemon.
//!
//! Runs LOCALLY against production endpoints: provisions ~15 personas via the
//! IdP's `/admin/provision` (X-Admin-Token), then submits memberships, posts,
//! comments, upvotes, vouches and badges signed by each persona's own key with
//! the provisioned cert attached — the same non-agent write path the SPA uses
//! (`mingo-web/app.js`). Content writes carry backdated `HLC` headers so the UI
//! renders staggered ages; attestation writes under `/u/**` carry NO `HLC`
//! (those collections have no `_config`, so the daemon's authoring-lag bound
//! would reject anything but "now").
//!
//! Backdating limits: the genesis `collection.v1` `_config` for each
//! `/communities/<c>/spaces/general/` sets `max_authoring_lag_s = 86400` (24h).
//! With `--sys-key`, the seeder temporarily widens that to 45 days, seeds, then
//! restores the 24h config. Without it, ages are compressed to fit under 20h
//! (order-preserving) and the output says so.
//!
//! Everything is deterministic: object ids derive from corpus keys (not
//! timestamps), so a re-run overwrites via LWW instead of duplicating.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::Deserialize;

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;

/// The communities that exist on the production chain (genesis batch). The
/// seeder refuses to write anywhere else — creating communities is genesis
/// business, not seed business.
pub const LIVE_COMMUNITIES: [&str; 3] = ["cooks", "woodworking", "homelab"];

/// The embedded default corpus (override with `--corpus <file>`).
pub const DEFAULT_CORPUS: &str = include_str!("seed_corpus.json");

/// Handles the IdP reserves (mingo-idp `normalize_name` + reserved list).
const RESERVED_HANDLES: [&str; 3] = ["sys", "admin", "root"];

/// The genesis `max_authoring_lag_s` for `/communities/<c>/spaces/general/`
/// (genesis.rs posts `collection_config(.., Some(5), Some(86400), ..)`).
pub const GENESIS_LAG_S: i64 = 24 * 60 * 60;
/// The temporary widened lag while seeding with `--sys-key` (45 days).
pub const WIDENED_LAG_S: i64 = 45 * 24 * 60 * 60;

/// Without `--sys-key`, ages ≤ the knee pass through unchanged and ages above
/// it are compressed linearly into (knee, cap] — order-preserving, and the cap
/// keeps a 4h margin under the genesis 24h authoring-lag bound.
pub const CLAMP_KNEE_HOURS: f64 = 12.0;
pub const CLAMP_CAP_HOURS: f64 = 20.0;

/// Corpus ages beyond this can't be honored even with the widened config
/// (45d minus a 3-day inclusion/clock margin).
pub const MAX_CORPUS_AGE_HOURS: f64 = 42.0 * 24.0;

/// Delay between submits — don't hammer prod.
const SUBMIT_PACING_MS: u64 = 75;

// ===========================================================================
// Corpus (embedded JSON, overridable with --corpus)
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct Corpus {
    pub personas: Vec<Persona>,
    pub communities: Vec<CommunitySeed>,
    #[serde(default)]
    pub vouches: Vec<VouchSeed>,
    #[serde(default)]
    pub badges: Vec<BadgeSeed>,
}

#[derive(Debug, Deserialize)]
pub struct Persona {
    pub handle: String,
}

#[derive(Debug, Deserialize)]
pub struct CommunitySeed {
    pub id: String,
    pub posts: Vec<PostSeed>,
}

#[derive(Debug, Deserialize)]
pub struct PostSeed {
    /// Stable corpus key — object ids derive from it (idempotent re-runs).
    pub slug: String,
    pub author: String,
    pub age_hours: f64,
    pub body: String,
    #[serde(default)]
    pub comments: Vec<CommentSeed>,
    #[serde(default)]
    pub upvotes: Vec<UpvoteSeed>,
}

#[derive(Debug, Deserialize)]
pub struct CommentSeed {
    pub author: String,
    pub age_hours: f64,
    pub body: String,
}

#[derive(Debug, Deserialize)]
pub struct UpvoteSeed {
    pub by: String,
    pub age_hours: f64,
}

#[derive(Debug, Deserialize)]
pub struct VouchSeed {
    pub from: String,
    pub to: String,
    pub age_hours: f64,
}

#[derive(Debug, Deserialize)]
pub struct BadgeSeed {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub age_hours: f64,
}

/// Corpus counts for the plan header (and the caller's report).
#[derive(Debug, PartialEq, Eq)]
pub struct CorpusStats {
    pub personas: usize,
    pub communities: usize,
    pub posts: usize,
    pub comments: usize,
    pub reactions: usize,
    pub vouches: usize,
    pub badges: usize,
}

impl Corpus {
    /// Parse + validate a corpus. Every referenced handle must be a declared
    /// persona; ages must be positive, within limits, and causally ordered
    /// (comments/upvotes younger than their post); communities must be the
    /// live ones; comments/upvotes must come from personas other than the
    /// post's author.
    pub fn parse(json: &str) -> Result<Corpus> {
        let corpus: Corpus = serde_json::from_str(json).context("parsing corpus JSON")?;
        corpus.validate()?;
        Ok(corpus)
    }

    fn validate(&self) -> Result<()> {
        if self.personas.is_empty() {
            bail!("corpus has no personas");
        }
        let mut handles = BTreeSet::new();
        for p in &self.personas {
            check_handle(&p.handle)?;
            if !handles.insert(p.handle.as_str()) {
                bail!("duplicate persona handle: {}", p.handle);
            }
        }
        let known = |h: &str, what: &str| -> Result<()> {
            if handles.contains(h) {
                Ok(())
            } else {
                bail!("{what} references unknown persona: {h}")
            }
        };
        let check_age = |age: f64, what: &str| -> Result<()> {
            if !(age > 0.0 && age <= MAX_CORPUS_AGE_HOURS) {
                bail!("{what}: age_hours {age} out of range (0, {MAX_CORPUS_AGE_HOURS}]");
            }
            Ok(())
        };

        let mut comm_ids = BTreeSet::new();
        for c in &self.communities {
            if !LIVE_COMMUNITIES.contains(&c.id.as_str()) {
                bail!(
                    "community '{}' is not live on-chain (live: {})",
                    c.id,
                    LIVE_COMMUNITIES.join(", ")
                );
            }
            if !comm_ids.insert(c.id.as_str()) {
                bail!("duplicate community: {}", c.id);
            }
            let mut slugs = BTreeSet::new();
            for p in &c.posts {
                let ctx = format!("post {}/{}", c.id, p.slug);
                if !slugs.insert(p.slug.as_str()) {
                    bail!("duplicate slug in {}: {}", c.id, p.slug);
                }
                known(&p.author, &ctx)?;
                check_age(p.age_hours, &ctx)?;
                if p.body.trim().is_empty() {
                    bail!("{ctx}: empty body");
                }
                for (i, cm) in p.comments.iter().enumerate() {
                    let cctx = format!("{ctx} comment #{i}");
                    known(&cm.author, &cctx)?;
                    check_age(cm.age_hours, &cctx)?;
                    if cm.age_hours >= p.age_hours {
                        bail!("{cctx}: comment (age {}) must be younger than its post (age {})",
                            cm.age_hours, p.age_hours);
                    }
                    if cm.author == p.author {
                        bail!("{cctx}: comments must come from personas other than the author");
                    }
                    if cm.body.trim().is_empty() {
                        bail!("{cctx}: empty body");
                    }
                }
                let mut voters = BTreeSet::new();
                for u in &p.upvotes {
                    let uctx = format!("{ctx} upvote by {}", u.by);
                    known(&u.by, &uctx)?;
                    check_age(u.age_hours, &uctx)?;
                    if u.age_hours >= p.age_hours {
                        bail!("{uctx}: upvote (age {}) must be younger than its post (age {})",
                            u.age_hours, p.age_hours);
                    }
                    if u.by == p.author {
                        bail!("{uctx}: upvotes must come from personas other than the author");
                    }
                    if !voters.insert(u.by.as_str()) {
                        bail!("{uctx}: duplicate upvote");
                    }
                }
            }
        }

        let mut vouch_pairs = BTreeSet::new();
        for v in &self.vouches {
            let ctx = format!("vouch {} → {}", v.from, v.to);
            known(&v.from, &ctx)?;
            known(&v.to, &ctx)?;
            check_age(v.age_hours, &ctx)?;
            if v.from == v.to {
                bail!("{ctx}: self-vouch");
            }
            if !vouch_pairs.insert((v.from.as_str(), v.to.as_str())) {
                bail!("{ctx}: duplicate vouch");
            }
        }
        let mut badge_keys = BTreeSet::new();
        for b in &self.badges {
            let ctx = format!("badge {} {} → {}", b.type_, b.from, b.to);
            known(&b.from, &ctx)?;
            known(&b.to, &ctx)?;
            check_age(b.age_hours, &ctx)?;
            if b.from == b.to {
                bail!("{ctx}: self-badge");
            }
            if b.type_.is_empty()
                || b.type_ == "vouch"
                || b.type_ == "ban"
                || b.type_.starts_with("membership")
                || !b.type_.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                bail!("{ctx}: badge type must be a lowercase slug and not vouch/ban/membership*");
            }
            if !badge_keys.insert((b.from.as_str(), b.to.as_str(), b.type_.as_str())) {
                bail!("{ctx}: duplicate badge");
            }
        }
        Ok(())
    }

    /// The oldest age in the corpus **content** (posts/comments/upvotes) —
    /// the input to the clamping map. Attestations carry no HLC so their ages
    /// don't constrain anything.
    pub fn max_age_hours(&self) -> f64 {
        self.communities
            .iter()
            .flat_map(|c| c.posts.iter().map(|p| p.age_hours))
            .fold(0.0, f64::max)
    }

    pub fn stats(&self) -> CorpusStats {
        CorpusStats {
            personas: self.personas.len(),
            communities: self.communities.len(),
            posts: self.communities.iter().map(|c| c.posts.len()).sum(),
            comments: self
                .communities
                .iter()
                .flat_map(|c| &c.posts)
                .map(|p| p.comments.len())
                .sum(),
            reactions: self
                .communities
                .iter()
                .flat_map(|c| &c.posts)
                .map(|p| p.upvotes.len())
                .sum(),
            vouches: self.vouches.len(),
            badges: self.badges.len(),
        }
    }
}

/// The IdP's handle rules (mingo-idp `normalize_name`): lowercase
/// `[a-z0-9._-]`, 1–31 chars, alphanumeric start, nothing reserved.
fn check_handle(h: &str) -> Result<()> {
    if h.is_empty() || h.len() > 31 {
        bail!("handle '{h}' must be 1–31 chars");
    }
    if h != h.to_lowercase() {
        bail!("handle '{h}' must be lowercase");
    }
    let mut chars = h.chars();
    if !chars.next().unwrap().is_ascii_alphanumeric() {
        bail!("handle '{h}' must start with a letter or digit");
    }
    if !h
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        bail!("handle '{h}' has a disallowed character");
    }
    if RESERVED_HANDLES.contains(&h) || h.starts_with("sys-") {
        bail!("handle '{h}' is reserved");
    }
    Ok(())
}

// ===========================================================================
// Ages → HLC
// ===========================================================================

/// Map a corpus age to the age actually stamped on the write. With `clamp`
/// (no `--sys-key`): ages ≤ [`CLAMP_KNEE_HOURS`] pass through; older ages
/// compress linearly into (knee, [`CLAMP_CAP_HOURS`]] so ordering (and recent
/// freshness) is preserved while everything fits the genesis 24h bound.
pub fn effective_age_hours(age: f64, max_age: f64, clamp: bool) -> f64 {
    if !clamp || max_age <= CLAMP_CAP_HOURS || age <= CLAMP_KNEE_HOURS {
        return age;
    }
    CLAMP_KNEE_HOURS
        + (age - CLAMP_KNEE_HOURS) * (CLAMP_CAP_HOURS - CLAMP_KNEE_HOURS)
            / (max_age - CLAMP_KNEE_HOURS)
}

/// Wire-form HLC (`<physical-ms>.<counter>`) for "age_hours before now_ms".
pub fn hlc_at(now_ms: i64, age_hours: f64) -> String {
    format!("{}.0", physical_ms(now_ms, age_hours))
}

/// The HLC physical component (Unix ms) for "age_hours before now_ms". Also
/// used as `created_at` in content payloads (the SPA passes `Date.now()`).
pub fn physical_ms(now_ms: i64, age_hours: f64) -> i64 {
    now_ms - (age_hours * 3_600_000.0) as i64
}

// ===========================================================================
// Deterministic ids
// ===========================================================================

fn b36(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("base36 digits are ascii")
}

/// `<prefix>-<base36>` derived from a stable corpus key — matches the SPA's
/// `p-`/`c-`/`r-` id style but is content-addressed, not time-based, so a
/// re-run writes the same (path, id) and LWW overwrites instead of duplicating.
pub fn derive_id(prefix: char, key: &str) -> String {
    let h = ContentHash::sha256(key.as_bytes());
    let n = u64::from_be_bytes(h.bytes[..8].try_into().expect("sha256 has ≥ 8 bytes"));
    format!("{prefix}-{}", b36(n))
}

// ===========================================================================
// Plan (pure — no keys, no network)
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Membership,
    Post,
    Comment,
    Reaction,
    Vouch,
    Badge,
}

impl ItemKind {
    fn as_str(self) -> &'static str {
        match self {
            ItemKind::Membership => "membership",
            ItemKind::Post => "post",
            ItemKind::Comment => "comment",
            ItemKind::Reaction => "reaction",
            ItemKind::Vouch => "vouch",
            ItemKind::Badge => "badge",
        }
    }
}

/// One write the seeder will submit, fully determined except for the signing
/// key + cert (which exist only after provisioning).
#[derive(Debug)]
pub struct PlanItem {
    pub kind: ItemKind,
    /// The persona handle whose key signs (and whose email owns) the write.
    pub signer: String,
    pub path: String,
    pub id: String,
    pub owner: String,
    pub schema: &'static str,
    pub content_type: &'static str,
    pub payload: Vec<u8>,
    pub hlc: Option<String>,
    /// Effective (possibly compressed) age, for display.
    pub age_hours: Option<f64>,
    pub label: String,
}

#[derive(Debug)]
pub struct Plan {
    pub domain: String,
    /// In submit order: memberships → posts → comments → reactions → vouches → badges.
    pub items: Vec<PlanItem>,
    /// Handles to provision, in corpus order.
    pub personas: Vec<String>,
    /// Communities whose `_config` gets widened/restored when a sys key is given.
    pub communities: Vec<String>,
    pub clamped: bool,
    pub max_age_hours: f64,
}

/// Build the full, deterministic write plan. `clamp` compresses ages to fit
/// the genesis 24h authoring-lag bound (i.e. run without `--sys-key`).
pub fn build_plan(corpus: &Corpus, domain: &str, now_ms: i64, clamp: bool) -> Result<Plan> {
    let max_age = corpus.max_age_hours();
    let email = |handle: &str| format!("{handle}@{domain}");
    let now_s = now_ms / 1000;
    let eff = |age: f64| effective_age_hours(age, max_age, clamp);

    let mut memberships: Vec<PlanItem> = Vec::new();
    let mut posts: Vec<PlanItem> = Vec::new();
    let mut comments: Vec<PlanItem> = Vec::new();
    let mut reactions: Vec<PlanItem> = Vec::new();

    // (community, handle) → oldest raw participation age (memberships are
    // derived from participation; issued_at predates the first activity).
    let mut participants: BTreeMap<(String, String), f64> = BTreeMap::new();
    let mut note = |comm: &str, handle: &str, age: f64| {
        let key = (comm.to_string(), handle.to_string());
        let e = participants.entry(key).or_insert(age);
        *e = e.max(age);
    };

    for c in &corpus.communities {
        let space = format!("/communities/{}/spaces/general/", c.id);
        for p in &c.posts {
            note(&c.id, &p.author, p.age_hours);
            let post_id = derive_id('p', &format!("post:{}:{}", c.id, p.slug));
            let post_uri = format!("{space}{post_id}");
            let age = eff(p.age_hours);
            posts.push(PlanItem {
                kind: ItemKind::Post,
                signer: p.author.clone(),
                path: space.clone(),
                id: post_id.clone(),
                owner: email(&p.author),
                schema: "post.v1",
                content_type: "application/json",
                payload: serde_json::to_vec(&serde_json::json!({
                    "body": p.body,
                    "parent": null,
                    "created_at": physical_ms(now_ms, age),
                }))?,
                hlc: Some(hlc_at(now_ms, age)),
                age_hours: Some(age),
                label: format!("post {}/{} by {}", c.id, p.slug, p.author),
            });
            for (i, cm) in p.comments.iter().enumerate() {
                note(&c.id, &cm.author, cm.age_hours);
                let age = eff(cm.age_hours);
                comments.push(PlanItem {
                    kind: ItemKind::Comment,
                    signer: cm.author.clone(),
                    path: space.clone(),
                    id: derive_id('c', &format!("comment:{}:{}:{}", c.id, p.slug, i)),
                    owner: email(&cm.author),
                    schema: "comment.v1",
                    content_type: "application/json",
                    payload: serde_json::to_vec(&serde_json::json!({
                        "body": cm.body,
                        "parent": post_uri,
                        "created_at": physical_ms(now_ms, age),
                    }))?,
                    hlc: Some(hlc_at(now_ms, age)),
                    age_hours: Some(age),
                    label: format!("comment on {}/{} by {}", c.id, p.slug, cm.author),
                });
            }
            for u in &p.upvotes {
                note(&c.id, &u.by, u.age_hours);
                let age = eff(u.age_hours);
                reactions.push(PlanItem {
                    kind: ItemKind::Reaction,
                    signer: u.by.clone(),
                    path: space.clone(),
                    id: derive_id('r', &format!("reaction:{}:{}:{}", c.id, p.slug, u.by)),
                    owner: email(&u.by),
                    schema: "reaction.v1",
                    content_type: "application/json",
                    payload: serde_json::to_vec(&serde_json::json!({
                        "target": post_uri,
                        "kind": "upvote",
                        "state": true,
                    }))?,
                    hlc: Some(hlc_at(now_ms, age)),
                    age_hours: Some(age),
                    label: format!("upvote on {}/{} by {}", c.id, p.slug, u.by),
                });
            }
        }
    }

    // Memberships: self-issued attestations, exactly the SPA's joinHub shape.
    // NO HLC (no `_config` under /u/**); issued_at (cosmetic) predates the
    // persona's first activity in the community.
    for ((comm, handle), oldest_age) in &participants {
        let addr = email(handle);
        memberships.push(PlanItem {
            kind: ItemKind::Membership,
            signer: handle.clone(),
            path: format!("/u/{addr}/attestations/{addr}/"),
            id: format!("membership-{comm}"),
            owner: addr.clone(),
            schema: "attestation.v1",
            content_type: "application/json",
            payload: serde_json::to_vec(&serde_json::json!({
                "subject": addr,
                "type": format!("membership:{comm}"),
                "value": { "community": comm, "via": "mingo-seed" },
                "issued_at": now_s - ((oldest_age + 0.5) * 3600.0) as i64,
                "expires": null,
                "issuer": addr,
            }))?,
            hlc: None,
            age_hours: None,
            label: format!("membership {handle} → {comm}"),
        });
    }

    // Vouches + badges: cross-persona attestations in the ISSUER's namespace
    // (getPassport matches on payload.subject across namespaces). No HLC.
    let attestation = |kind: ItemKind,
                       from: &str,
                       to: &str,
                       type_: &str,
                       id: String,
                       age: f64,
                       label: String|
     -> Result<PlanItem> {
        let issuer = email(from);
        let subject = email(to);
        Ok(PlanItem {
            kind,
            signer: from.to_string(),
            path: format!("/u/{issuer}/attestations/{subject}/"),
            id,
            owner: issuer.clone(),
            schema: "attestation.v1",
            content_type: "application/json",
            payload: serde_json::to_vec(&serde_json::json!({
                "subject": subject,
                "type": type_,
                "value": { "via": "mingo-seed" },
                "issued_at": now_s - (age * 3600.0) as i64,
                "expires": null,
                "issuer": issuer,
            }))?,
            hlc: None,
            age_hours: None,
            label,
        })
    };
    let mut vouches = Vec::new();
    for v in &corpus.vouches {
        vouches.push(attestation(
            ItemKind::Vouch,
            &v.from,
            &v.to,
            "vouch",
            "vouch".to_string(),
            v.age_hours,
            format!("vouch {} → {}", v.from, v.to),
        )?);
    }
    let mut badges = Vec::new();
    for b in &corpus.badges {
        badges.push(attestation(
            ItemKind::Badge,
            &b.from,
            &b.to,
            &b.type_,
            b.type_.clone(),
            b.age_hours,
            format!("badge {} {} → {}", b.type_, b.from, b.to),
        )?);
    }

    // Oldest-first within each phase reads naturally and keeps inclusion order
    // roughly matching authoring order.
    let by_age_desc = |a: &PlanItem, b: &PlanItem| {
        b.age_hours
            .unwrap_or(0.0)
            .partial_cmp(&a.age_hours.unwrap_or(0.0))
            .expect("ages are finite")
    };
    posts.sort_by(by_age_desc);
    comments.sort_by(by_age_desc);
    reactions.sort_by(by_age_desc);

    let mut items = memberships;
    items.extend(posts);
    items.extend(comments);
    items.extend(reactions);
    items.extend(vouches);
    items.extend(badges);

    Ok(Plan {
        domain: domain.to_string(),
        items,
        personas: corpus.personas.iter().map(|p| p.handle.clone()).collect(),
        communities: corpus.communities.iter().map(|c| c.id.clone()).collect(),
        clamped: clamp && max_age > CLAMP_CAP_HOURS,
        max_age_hours: max_age,
    })
}

// ===========================================================================
// Wire assembly
// ===========================================================================

/// Assemble one persona-signed write (mirrors `mingo-idp/src/poster.rs`
/// `assemble_agent_write`, minus the agent cert/warrant): signed by the
/// persona's own key, `Owner` = the persona email, `Auth-Cert` = the
/// provisioned browserid cert, no warrant/evidence (the daemon resolves the
/// issuer's on-chain `/sys/dnssec` proof).
#[allow(clippy::too_many_arguments)]
pub fn assemble_write(
    signing_key: &SigningKey,
    auth_cert: Option<&str>,
    path: &str,
    id: &str,
    schema: &str,
    content_type: &str,
    payload: Vec<u8>,
    owner: Option<&str>,
    hlc: Option<&str>,
) -> Result<Vec<u8>> {
    let content_hash = ContentHash::sha256(&payload);
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).map_err(|e| anyhow!("bad path '{path}': {e}"))?,
        id: Id::new(id).map_err(|e| anyhow!("bad id '{id}': {e}"))?,
        object_type: ObjectType::Object,
        signing_key: signing_key.public_key(),
        signature: Signature([0u8; 64]), // overwritten by sign()
        content_type: Some(content_type.to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload),
        owner: owner
            .map(|o| Id::new(o).map_err(|e| anyhow!("bad owner '{o}': {e}")))
            .transpose()?,
        creator: None,
        content_encoding: None,
        content_schema: Some(schema.to_string()),
        policy_ref: None,
        related: None,
        hlc: hlc.map(str::to_string),
        prev: None,
        auth_cert: auth_cert.map(str::to_string),
        auth_evidence: None,
        auth_warrant: None,
    };
    msg.sign(signing_key);
    Ok(wire::serialize(&msg))
}

/// Load a signing key from a file in either format used around here:
/// the keyring export `ed25519:<hex 32-byte seed>` (what
/// `sbo key export` writes, e.g. `~/secure-backup/mingo-sys.key`) or the
/// checkpoint-key JSON `{"secret_key": "<hex>"}`.
pub fn load_signing_key_file(path: &str) -> Result<SigningKey> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let trimmed = contents.trim();
    let hex_seed = if let Some(rest) = trimmed.strip_prefix("ed25519:") {
        rest.trim().to_string()
    } else {
        let v: serde_json::Value =
            serde_json::from_str(trimmed).with_context(|| {
                format!("{path}: expected `ed25519:<hex>` or JSON {{\"secret_key\": <hex>}}")
            })?;
        v.get("secret_key")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow!("{path}: JSON key file missing `secret_key`"))?
            .trim()
            .to_string()
    };
    let raw = hex::decode(&hex_seed).with_context(|| format!("{path}: decoding hex seed"))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{path}: seed must be exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

// ===========================================================================
// Runner (dry-run print / execute against live endpoints)
// ===========================================================================

pub struct SeedArgs {
    pub idp: String,
    pub daemon: String,
    pub corpus: Option<String>,
    pub sys_key: Option<String>,
    pub execute: bool,
    pub admin_token_env: String,
}

/// `https://mingo.place` → `mingo.place` (the IdP origin is the identity domain).
fn domain_of(url: &str) -> String {
    let no_scheme = url
        .trim_end_matches('/')
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    host.split(':').next().unwrap_or(host).to_string()
}

fn fmt_age(hours: f64) -> String {
    if hours >= 48.0 {
        format!("{:.1}d", hours / 24.0)
    } else {
        format!("{hours:.1}h")
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i64
}

pub fn run(args: &SeedArgs) -> Result<()> {
    let corpus_json = match &args.corpus {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?,
        None => DEFAULT_CORPUS.to_string(),
    };
    let corpus = Corpus::parse(&corpus_json)?;
    let domain = domain_of(&args.idp);
    let now_ms = now_unix_ms();
    let clamp = args.sys_key.is_none();
    let plan = build_plan(&corpus, &domain, now_ms, clamp)?;
    let stats = corpus.stats();

    println!("Seed plan for {} (daemon {})", args.idp, args.daemon);
    println!(
        "  {} personas · {} communities · {} posts · {} comments · {} upvotes · {} vouches · {} badges",
        stats.personas, stats.communities, stats.posts, stats.comments, stats.reactions,
        stats.vouches, stats.badges
    );
    let memberships = plan
        .items
        .iter()
        .filter(|i| i.kind == ItemKind::Membership)
        .count();
    println!(
        "  {} derived memberships · {} writes total",
        memberships,
        plan.items.len()
    );
    if plan.clamped {
        println!(
            "  NOTE: no --sys-key — content ages compressed to ≤ {}h (corpus max {}) to fit the \
             genesis 24h authoring-lag bound. Pass --sys-key to seed true ages.",
            CLAMP_CAP_HOURS,
            fmt_age(plan.max_age_hours)
        );
    }
    println!();
    println!("Steps:");
    println!("  1. DNSSEC freshness: GET {}/v1/dnssec?domain={domain} (+ key-rooted refresh write if stale)", args.daemon);
    println!(
        "  2. Provision {} personas via {}/admin/provision (X-Admin-Token from ${})",
        plan.personas.len(),
        args.idp,
        args.admin_token_env
    );
    if let Some(k) = &args.sys_key {
        println!(
            "  3. Widen _config to max_authoring_lag_s={WIDENED_LAG_S} for: {} (sys key {k})",
            plan.communities.join(", ")
        );
        println!("  4. Submit the {} writes below", plan.items.len());
        println!("  5. Restore _config to max_authoring_lag_s={GENESIS_LAG_S}");
    } else {
        println!("  3. Submit the {} writes below", plan.items.len());
    }
    println!();

    if !args.execute {
        for item in &plan.items {
            let age = item
                .age_hours
                .map(|a| format!("  age={}", fmt_age(a)))
                .unwrap_or_default();
            println!(
                "  {:<10} {}{}  owner={}{}",
                item.kind.as_str(),
                item.path,
                item.id,
                item.owner,
                age
            );
        }
        println!();
        println!("Dry run — nothing submitted. Re-run with --execute to seed.");
        return Ok(());
    }

    execute(args, &plan, &domain, now_ms)
}

// ---- live execution -------------------------------------------------------

#[derive(Deserialize)]
struct DnssecResp {
    #[serde(default)]
    needs_refresh: bool,
    #[serde(default)]
    proof_b64: Option<String>,
}

#[derive(Deserialize)]
struct ProvisionResp {
    #[serde(default)]
    success: bool,
    cert: String,
}

struct Provisioned {
    email: String,
    key: SigningKey,
    cert: String,
}

fn execute(args: &SeedArgs, plan: &Plan, domain: &str, now_ms: i64) -> Result<()> {
    let admin_token = std::env::var(&args.admin_token_env).with_context(|| {
        format!(
            "--execute needs the IdP admin token in ${}",
            args.admin_token_env
        )
    })?;
    let sys_key = args
        .sys_key
        .as_deref()
        .map(load_signing_key_file)
        .transpose()?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    // 1. DNSSEC freshness — attribution of every email-rooted write below
    // depends on a valid on-chain /sys/dnssec/<domain> proof.
    ensure_dnssec_fresh(&client, &args.daemon, domain, now_ms / 1000)?;

    // 2. Provision personas (idempotent per (external_email, handle); a fresh
    // key per run is fine — writes are owned by the email, not the key).
    let mut personas: BTreeMap<String, Provisioned> = BTreeMap::new();
    for handle in &plan.personas {
        let p = provision_persona(&client, &args.idp, &admin_token, handle, domain)?;
        println!("✓ provisioned {}", p.email);
        personas.insert(handle.clone(), p);
    }

    // 3. Widen each community's spaces/general _config so backdated HLCs pass.
    if let Some(sys) = &sys_key {
        for comm in &plan.communities {
            submit(
                &client,
                &args.daemon,
                &space_config(sys, comm, WIDENED_LAG_S),
                &format!("_config widen ({comm})"),
            )?;
            println!("✓ widened _config for {comm} (max_authoring_lag_s={WIDENED_LAG_S})");
        }
    }

    // 4. Submit everything, in dependency order. On failure, abort — but
    // still restore the configs first.
    let result = submit_items(&client, args, plan, &personas);

    // 5. Restore the genesis 24h configs (even when a submit failed).
    if let Some(sys) = &sys_key {
        for comm in &plan.communities {
            submit(
                &client,
                &args.daemon,
                &space_config(sys, comm, GENESIS_LAG_S),
                &format!("_config restore ({comm})"),
            )?;
            println!("✓ restored _config for {comm} (max_authoring_lag_s={GENESIS_LAG_S})");
        }
    }
    result?;

    println!();
    println!(
        "Seeded {} writes across {} — https://{}",
        plan.items.len(),
        plan.communities.join(", "),
        domain
    );
    Ok(())
}

fn submit_items(
    client: &reqwest::blocking::Client,
    args: &SeedArgs,
    plan: &Plan,
    personas: &BTreeMap<String, Provisioned>,
) -> Result<()> {
    for item in &plan.items {
        let p = personas
            .get(&item.signer)
            .ok_or_else(|| anyhow!("no provisioned persona for {}", item.signer))?;
        debug_assert_eq!(p.email, item.owner);
        let wire_bytes = assemble_write(
            &p.key,
            Some(&p.cert),
            &item.path,
            &item.id,
            item.schema,
            item.content_type,
            item.payload.clone(),
            Some(&item.owner),
            item.hlc.as_deref(),
        )?;
        submit(client, &args.daemon, &wire_bytes, &item.label)?;
        println!("✓ {} ({}{})", item.label, item.path, item.id);
        std::thread::sleep(std::time::Duration::from_millis(SUBMIT_PACING_MS));
    }
    Ok(())
}

/// POST wire bytes to `<daemon>/v1/submit`. A 400 carries `{stage}: {reason}`
/// in the body — surface it with the failing item and stop (the caller aborts
/// rather than spraying more errors into prod).
fn submit(
    client: &reqwest::blocking::Client,
    daemon: &str,
    wire_bytes: &[u8],
    label: &str,
) -> Result<()> {
    let resp = client
        .post(format!("{}/v1/submit", daemon.trim_end_matches('/')))
        .header("Content-Type", "application/octet-stream")
        .body(wire_bytes.to_vec())
        .send()
        .with_context(|| format!("submitting {label}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("ABORT — submit failed for [{label}]: HTTP {status}: {body}");
    }
    Ok(())
}

/// Mirror the SPA's `ensureDnssecFresh`: ask the daemon whether the on-chain
/// proof covers now+margin; if not, submit the returned proof as a KEY-ROOTED
/// write (throwaway key, no owner, no cert — the proof authorizes itself).
fn ensure_dnssec_fresh(
    client: &reqwest::blocking::Client,
    daemon: &str,
    domain: &str,
    now_s: i64,
) -> Result<()> {
    let url = format!(
        "{}/v1/dnssec?domain={domain}&needed_by={now_s}&margin=3600",
        daemon.trim_end_matches('/')
    );
    let resp: DnssecResp = client
        .get(&url)
        .send()
        .context("dnssec freshness check")?
        .error_for_status()
        .context("dnssec freshness check")?
        .json()
        .context("parsing dnssec response")?;
    let Some(proof_b64) = resp.proof_b64.filter(|_| resp.needs_refresh) else {
        println!("✓ /sys/dnssec/{domain} is fresh");
        return Ok(());
    };
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&proof_b64)
        .context("decoding dnssec proof")?;
    let throwaway = SigningKey::generate();
    let wire_bytes = assemble_write(
        &throwaway,
        None,
        "/sys/dnssec/",
        domain,
        "dnssec.v1",
        "application/octet-stream",
        proof,
        None,
        None,
    )?;
    submit(client, daemon, &wire_bytes, &format!("dnssec refresh ({domain})"))?;
    println!("✓ refreshed /sys/dnssec/{domain}");
    Ok(())
}

/// The `collection.v1` `_config` for a community's general space — identical
/// to the genesis one (`genesis.rs`) except for the authoring lag.
fn space_config(sys_key: &SigningKey, community: &str, max_authoring_lag_s: i64) -> Vec<u8> {
    sbo_core::presets::collection_config(
        sys_key,
        &format!("/communities/{community}/spaces/general/"),
        true,
        Some(5),
        Some(max_authoring_lag_s),
        Some("post.v1"),
    )
}

/// Provision (or re-provision) one persona at the IdP: binds
/// `<handle>.seed@sandmill.org` ↔ `<handle>` and mints a 24h cert for a fresh
/// per-run key. Sentinel external emails keep the handles reserved against
/// real signups without touching real mailboxes.
fn provision_persona(
    client: &reqwest::blocking::Client,
    idp: &str,
    admin_token: &str,
    handle: &str,
    domain: &str,
) -> Result<Provisioned> {
    let key = SigningKey::generate();
    let pubkey_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().bytes);
    let resp = client
        .post(format!("{}/admin/provision", idp.trim_end_matches('/')))
        .header("X-Admin-Token", admin_token)
        .json(&serde_json::json!({
            "external_email": format!("{handle}.seed@sandmill.org"),
            "handle": handle,
            "pubkey": { "algorithm": "Ed25519", "publicKey": pubkey_b64 },
        }))
        .send()
        .with_context(|| format!("provisioning {handle}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("ABORT — provisioning '{handle}' failed: HTTP {status}: {body}");
    }
    let parsed: ProvisionResp = resp
        .json()
        .with_context(|| format!("parsing provision response for {handle}"))?;
    if !parsed.success {
        bail!("ABORT — provisioning '{handle}' returned success=false");
    }
    Ok(Provisioned {
        email: format!("{handle}@{domain}"),
        key,
        cert: parsed.cert,
    })
}

// ===========================================================================
// Tests (pure parts)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: i64 = 1_800_000_000_000;

    fn default_corpus() -> Corpus {
        Corpus::parse(DEFAULT_CORPUS).expect("embedded corpus parses and validates")
    }

    #[test]
    fn embedded_corpus_parses_and_meets_spec_ranges() {
        let c = default_corpus();
        let s = c.stats();
        assert_eq!(s.personas, 15);
        assert_eq!(s.communities, 3);
        for comm in &c.communities {
            assert!(
                (6..=9).contains(&comm.posts.len()),
                "{}: {} posts, want 6-9",
                comm.id,
                comm.posts.len()
            );
            for p in &comm.posts {
                assert!(p.comments.len() <= 6, "{}: too many comments", p.slug);
            }
        }
        assert!((10..=15).contains(&s.vouches), "vouches: {}", s.vouches);
        assert!((4..=6).contains(&s.badges), "badges: {}", s.badges);
        // Staggered: oldest ~30d, newest ≤ a few hours.
        assert!(c.max_age_hours() > 600.0 && c.max_age_hours() <= MAX_CORPUS_AGE_HOURS);
        let min_age = c
            .communities
            .iter()
            .flat_map(|c| c.posts.iter().map(|p| p.age_hours))
            .fold(f64::MAX, f64::min);
        assert!(min_age <= 6.0, "newest post should be hours old, got {min_age}h");
    }

    #[test]
    fn corpus_rejects_comment_older_than_post() {
        let json = r#"{
            "personas": [{"handle": "a"}, {"handle": "b"}],
            "communities": [{"id": "cooks", "posts": [{
                "slug": "x", "author": "a", "age_hours": 5, "body": "hi",
                "comments": [{"author": "b", "age_hours": 6, "body": "older than post"}]
            }]}]
        }"#;
        let err = Corpus::parse(json).unwrap_err().to_string();
        assert!(err.contains("younger than its post"), "{err}");
    }

    #[test]
    fn corpus_rejects_unknown_persona_dead_community_and_self_vouch() {
        let unknown = r#"{
            "personas": [{"handle": "a"}],
            "communities": [{"id": "cooks", "posts": [{
                "slug": "x", "author": "ghost", "age_hours": 5, "body": "hi"
            }]}]
        }"#;
        assert!(Corpus::parse(unknown).unwrap_err().to_string().contains("unknown persona"));

        let dead = r#"{
            "personas": [{"handle": "a"}],
            "communities": [{"id": "gardening", "posts": []}]
        }"#;
        assert!(Corpus::parse(dead).unwrap_err().to_string().contains("not live"));

        let selfv = r#"{
            "personas": [{"handle": "a"}],
            "communities": [],
            "vouches": [{"from": "a", "to": "a", "age_hours": 1}]
        }"#;
        assert!(Corpus::parse(selfv).unwrap_err().to_string().contains("self-vouch"));
    }

    #[test]
    fn handle_rules_match_idp() {
        for ok in ["a", "tomas.b", "helena-k", "kelvin0", "a_b"] {
            assert!(check_handle(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", "-lead", ".lead", "UPPER", "sys", "sys-x", "admin", "root", "sp ace",
            "waaaaaaaaaaaaaaaaaaaaaaaaaaaay-too-long-handle"]
        {
            assert!(check_handle(bad).is_err(), "{bad} should be invalid");
        }
    }

    #[test]
    fn age_compression_is_monotone_capped_and_identity_when_unneeded() {
        let max = 720.0;
        // Identity below the knee and when clamping is off.
        assert_eq!(effective_age_hours(3.0, max, true), 3.0);
        assert_eq!(effective_age_hours(700.0, max, false), 700.0);
        assert_eq!(effective_age_hours(700.0, 18.0, true), 700.0); // max ≤ cap: no-op
        // Monotone and capped.
        let ages = [0.5, 2.0, 12.0, 13.0, 48.0, 200.0, 719.0, 720.0];
        let mut prev = 0.0;
        for a in ages {
            let e = effective_age_hours(a, max, true);
            assert!(e >= prev, "not monotone at {a}");
            assert!(e <= CLAMP_CAP_HOURS + 1e-9, "over cap at {a}: {e}");
            prev = e;
        }
        assert!((effective_age_hours(720.0, max, true) - CLAMP_CAP_HOURS).abs() < 1e-9);
    }

    #[test]
    fn hlc_is_wire_form_and_backdated() {
        let h = hlc_at(NOW_MS, 24.0);
        let parsed = sbo_core::hlc::Hlc::parse(&h).expect("wire-form HLC");
        assert_eq!(parsed.physical, NOW_MS - 24 * 3_600_000);
        assert_eq!(h, format!("{}.0", NOW_MS - 24 * 3_600_000));
    }

    #[test]
    fn derived_ids_are_stable_prefixed_and_distinct() {
        let a = derive_id('p', "post:cooks:dutch-oven-bread");
        let b = derive_id('p', "post:cooks:dutch-oven-bread");
        let c = derive_id('p', "post:cooks:knife-sharpening");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("p-"));
        assert!(a.len() <= 15);
        assert!(Id::new(&a).is_ok());
    }

    #[test]
    fn plan_orders_phases_and_derives_memberships_from_participation() {
        let corpus = default_corpus();
        let plan = build_plan(&corpus, "mingo.place", NOW_MS, false).unwrap();
        // Phase order: memberships → posts → comments → reactions → vouches → badges.
        let phase = |k: ItemKind| match k {
            ItemKind::Membership => 0,
            ItemKind::Post => 1,
            ItemKind::Comment => 2,
            ItemKind::Reaction => 3,
            ItemKind::Vouch => 4,
            ItemKind::Badge => 5,
        };
        let phases: Vec<u8> = plan.items.iter().map(|i| phase(i.kind)).collect();
        let mut sorted = phases.clone();
        sorted.sort_unstable();
        assert_eq!(phases, sorted, "items must be in dependency order");

        // Every content signer has a membership in that community.
        let memberships: BTreeSet<(String, String)> = plan
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Membership)
            .map(|i| (i.id.trim_start_matches("membership-").to_string(), i.signer.clone()))
            .collect();
        for item in &plan.items {
            if matches!(item.kind, ItemKind::Post | ItemKind::Comment | ItemKind::Reaction) {
                let comm = item
                    .path
                    .strip_prefix("/communities/")
                    .and_then(|r| r.split('/').next())
                    .unwrap()
                    .to_string();
                assert!(
                    memberships.contains(&(comm.clone(), item.signer.clone())),
                    "{} posts in {} without membership",
                    item.signer,
                    comm
                );
            }
        }

        // Content carries HLC; /u/** attestations must NOT (no _config there).
        for item in &plan.items {
            match item.kind {
                ItemKind::Post | ItemKind::Comment | ItemKind::Reaction => {
                    assert!(item.hlc.is_some(), "{} missing HLC", item.label);
                    assert!(item.path.starts_with("/communities/"));
                }
                _ => {
                    assert!(item.hlc.is_none(), "{} must not carry HLC", item.label);
                    assert!(item.path.starts_with("/u/"), "{}", item.path);
                }
            }
        }

        // All (path, id) pairs unique — deterministic ids must not collide.
        let mut seen = BTreeSet::new();
        for item in &plan.items {
            assert!(
                seen.insert((item.path.clone(), item.id.clone())),
                "duplicate (path, id): {}{}",
                item.path,
                item.id
            );
        }
    }

    #[test]
    fn clamped_plan_fits_genesis_bound_unclamped_preserves_ages() {
        let corpus = default_corpus();
        let clamped = build_plan(&corpus, "mingo.place", NOW_MS, true).unwrap();
        assert!(clamped.clamped);
        for item in &clamped.items {
            if let Some(h) = &item.hlc {
                let hlc = sbo_core::hlc::Hlc::parse(h).unwrap();
                let age_ms = NOW_MS - hlc.physical;
                assert!(
                    age_ms <= (CLAMP_CAP_HOURS * 3_600_000.0) as i64,
                    "{}: {}ms exceeds clamp cap",
                    item.label,
                    age_ms
                );
            }
        }
        let full = build_plan(&corpus, "mingo.place", NOW_MS, false).unwrap();
        assert!(!full.clamped);
        let oldest = full
            .items
            .iter()
            .filter_map(|i| i.hlc.as_deref())
            .map(|h| sbo_core::hlc::Hlc::parse(h).unwrap().physical)
            .min()
            .unwrap();
        assert_eq!(oldest, NOW_MS - (corpus.max_age_hours() * 3_600_000.0) as i64);
    }

    #[test]
    fn membership_payload_matches_spa_join_shape() {
        let corpus = default_corpus();
        let plan = build_plan(&corpus, "mingo.place", NOW_MS, false).unwrap();
        let m = plan
            .items
            .iter()
            .find(|i| i.kind == ItemKind::Membership)
            .unwrap();
        let comm = m.id.trim_start_matches("membership-");
        let email = &m.owner;
        assert_eq!(m.path, format!("/u/{email}/attestations/{email}/"));
        let v: serde_json::Value = serde_json::from_slice(&m.payload).unwrap();
        assert_eq!(v["subject"], serde_json::json!(email));
        assert_eq!(v["issuer"], serde_json::json!(email));
        assert_eq!(v["type"], serde_json::json!(format!("membership:{comm}")));
        assert_eq!(v["value"]["community"], serde_json::json!(comm));
        assert_eq!(v["expires"], serde_json::Value::Null);
        assert!(v["issued_at"].is_i64());

        // The /u/<email>/… path (with '@' and '.') survives assembly — the
        // dry-run never parses paths, so guard it here for every item kind.
        let key = SigningKey::generate();
        for item in &plan.items {
            let wire_bytes = assemble_write(
                &key,
                Some("fake.cert.jws"),
                &item.path,
                &item.id,
                item.schema,
                item.content_type,
                item.payload.clone(),
                Some(&item.owner),
                item.hlc.as_deref(),
            )
            .unwrap_or_else(|e| panic!("{} fails to assemble: {e}", item.label));
            let msg = wire::parse(&wire_bytes).expect("assembled item parses");
            sbo_core::message::verify_message(&msg).expect("assembled item verifies");
        }
    }

    #[test]
    fn vouch_lives_in_issuer_namespace_with_subject_payload() {
        let corpus = default_corpus();
        let plan = build_plan(&corpus, "mingo.place", NOW_MS, false).unwrap();
        let v = plan.items.iter().find(|i| i.kind == ItemKind::Vouch).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&v.payload).unwrap();
        let issuer = payload["issuer"].as_str().unwrap();
        let subject = payload["subject"].as_str().unwrap();
        assert_ne!(issuer, subject);
        assert_eq!(v.owner, issuer);
        assert_eq!(v.path, format!("/u/{issuer}/attestations/{subject}/"));
        assert_eq!(payload["type"], serde_json::json!("vouch"));
    }

    #[test]
    fn content_payloads_match_kit_field_names() {
        let corpus = default_corpus();
        let plan = build_plan(&corpus, "mingo.place", NOW_MS, false).unwrap();
        let post = plan.items.iter().find(|i| i.kind == ItemKind::Post).unwrap();
        let pv: serde_json::Value = serde_json::from_slice(&post.payload).unwrap();
        assert!(pv["body"].is_string());
        assert_eq!(pv["parent"], serde_json::Value::Null);
        // created_at is Unix ms and equals the HLC physical.
        let hlc = sbo_core::hlc::Hlc::parse(post.hlc.as_deref().unwrap()).unwrap();
        assert_eq!(pv["created_at"].as_i64().unwrap(), hlc.physical);

        let comment = plan.items.iter().find(|i| i.kind == ItemKind::Comment).unwrap();
        let cv: serde_json::Value = serde_json::from_slice(&comment.payload).unwrap();
        let parent = cv["parent"].as_str().unwrap();
        assert!(parent.starts_with("/communities/") && parent.contains("/spaces/general/p-"));
        // Comment's parent post is in the plan, in the same collection.
        assert!(plan.items.iter().any(|i| i.kind == ItemKind::Post
            && format!("{}{}", i.path, i.id) == parent));

        let reaction = plan.items.iter().find(|i| i.kind == ItemKind::Reaction).unwrap();
        let rv: serde_json::Value = serde_json::from_slice(&reaction.payload).unwrap();
        assert_eq!(rv["kind"], serde_json::json!("upvote"));
        assert_eq!(rv["state"], serde_json::json!(true));
        assert!(plan.items.iter().any(|i| i.kind == ItemKind::Post
            && format!("{}{}", i.path, i.id) == rv["target"].as_str().unwrap()));
    }

    #[test]
    fn assembled_write_round_trips_and_verifies() {
        let key = SigningKey::generate();
        let payload = br#"{"body":"hi","parent":null,"created_at":1}"#.to_vec();
        let wire_bytes = assemble_write(
            &key,
            Some("fake.cert.jws"),
            "/communities/cooks/spaces/general/",
            "p-abc123",
            "post.v1",
            "application/json",
            payload.clone(),
            Some("marisol@mingo.place"),
            Some("1799913600000.0"),
        )
        .unwrap();
        let msg = wire::parse(&wire_bytes).expect("wire round-trips");
        sbo_core::message::verify_message(&msg).expect("signature verifies");
        assert_eq!(msg.path.to_string(), "/communities/cooks/spaces/general/");
        assert_eq!(msg.id.as_str(), "p-abc123");
        assert_eq!(msg.owner.as_ref().unwrap().as_str(), "marisol@mingo.place");
        assert_eq!(msg.auth_cert.as_deref(), Some("fake.cert.jws"));
        assert_eq!(msg.hlc.as_deref(), Some("1799913600000.0"));
        assert_eq!(msg.auth_warrant, None);
        assert_eq!(msg.auth_evidence, None);
        assert_eq!(msg.payload.as_deref(), Some(payload.as_slice()));

        // Key-rooted variant (dnssec refresh): no owner, no cert.
        let kr = assemble_write(
            &key, None, "/sys/dnssec/", "mingo.place", "dnssec.v1",
            "application/octet-stream", vec![1, 2, 3], None, None,
        )
        .unwrap();
        let msg = wire::parse(&kr).unwrap();
        sbo_core::message::verify_message(&msg).unwrap();
        assert_eq!(msg.owner, None);
        assert_eq!(msg.auth_cert, None);
        assert_eq!(msg.hlc, None);
    }

    #[test]
    fn sys_key_loader_accepts_both_formats() {
        let dir = std::env::temp_dir().join(format!("mingo-seed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = [7u8; 32];
        let expect = SigningKey::from_bytes(&seed).public_key();

        let hex_path = dir.join("key.hex");
        std::fs::write(&hex_path, format!("ed25519:{}\n", hex::encode(seed))).unwrap();
        let k = load_signing_key_file(hex_path.to_str().unwrap()).unwrap();
        assert_eq!(k.public_key().bytes, expect.bytes);

        let json_path = dir.join("key.json");
        std::fs::write(
            &json_path,
            format!("{{\"secret_key\":\"{}\"}}", hex::encode(seed)),
        )
        .unwrap();
        let k = load_signing_key_file(json_path.to_str().unwrap()).unwrap();
        assert_eq!(k.public_key().bytes, expect.bytes);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn domain_of_extracts_host() {
        assert_eq!(domain_of("https://mingo.place"), "mingo.place");
        assert_eq!(domain_of("https://mingo.place/"), "mingo.place");
        assert_eq!(domain_of("http://localhost:8080/x"), "localhost");
    }
}
