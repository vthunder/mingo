//! `mingo add-policy-layer` — merge an application's grants and restrictions
//! into the LIVE root policy (`/sys/policies/` id `root`).
//!
//! This chain is a shared base chain: more than one application may keep
//! objects on it, and the root policy is a SINGLE object. An application that
//! published its own policy would delete this one — the community governance,
//! the checkpointer grant, `/u/$owner/**` — in a single write. So an
//! application's needs are ADDED here, never written over.
//!
//! **Only the chain admin key can do it.** The root policy grants `govern` on
//! `/**` to admin, and admin is keyed to the sys pubkey. A policy write signed
//! by an application's own key is refused.
//!
//! Defensive in the same shape as `set_root_admin`:
//!
//! 1. **Fetch** the live policy; never construct one.
//! 2. **Append only.** Entries already present (by exact JSON equality) are
//!    skipped, so re-running is a no-op rather than a duplicate.
//! 3. **Prove preservation**: every pre-existing grant and restriction must
//!    still be present, in order, and nothing outside `grants`/`restrictions`
//!    may change — asserted by a hash of the rest of the policy.
//! 4. **Dry-run by default**; `--execute` submits.
//!
//! The layer file is whatever the application's own tooling emits.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use sbo_core::crypto::ContentHash;

use crate::seed::{assemble_write, load_signing_key_file};

const ROOT_PATH: &str = "/sys/policies/";
const ROOT_ID: &str = "root";

pub struct AddPolicyLayerArgs {
    /// JSON file with `{ "grants": [...], "restrictions": [...] }`. Both
    /// optional; anything else in the file is rejected rather than ignored.
    pub layer_file: String,
    pub daemon: String,
    /// Repo selector for the daemon (it follows several databases).
    pub repo: String,
    pub sys_key_file: String,
    pub execute: bool,
}

#[derive(Debug, Deserialize)]
struct ObjResp {
    #[serde(default)]
    value: Value,
    #[serde(default)]
    owner_ref: Option<String>,
    #[serde(default)]
    confirmed: bool,
}

/// Everything in the policy EXCEPT `grants` and `restrictions`, hashed. Computed
/// before and after; identical is the proof that nothing else moved — in
/// particular `roles.admin`, which is the authority to make this edit at all.
pub fn rest_hash(policy: &Value) -> String {
    let mut v = policy.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("grants");
        o.remove("restrictions");
    }
    let bytes = serde_json::to_vec(&v).unwrap_or_default();
    format!("sha256:{}", hex::encode(ContentHash::sha256(&bytes).bytes))
}

/// Append the layer's entries to the policy's, skipping any already present.
/// Returns the merged policy and what was actually added.
pub fn merge(policy: &Value, layer: &Value) -> Result<(Value, Vec<String>)> {
    for k in layer.as_object().ok_or_else(|| anyhow!("layer is not a JSON object"))?.keys() {
        if k != "grants" && k != "restrictions" {
            bail!("layer carries `{k}`; only `grants` and `restrictions` may be merged. \
                   Roles, deny rules and anything else are mingo's own and must be edited deliberately.");
        }
    }
    let mut out = policy.clone();
    let obj = out.as_object_mut().ok_or_else(|| anyhow!("root policy is not a JSON object"))?;
    let mut added = Vec::new();
    for key in ["grants", "restrictions"] {
        let Some(items) = layer.get(key).and_then(Value::as_array) else { continue };
        let target = obj.entry(key).or_insert_with(|| Value::Array(vec![]));
        let target = target.as_array_mut().ok_or_else(|| anyhow!("policy `{key}` is not an array"))?;
        for item in items {
            if target.iter().any(|e| e == item) {
                continue; // already installed — re-running must not duplicate
            }
            added.push(format!("{key}: {}", serde_json::to_string(item).unwrap_or_default()));
            target.push(item.clone());
        }
    }
    Ok((out, added))
}

fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest),
        None => path.to_string(),
    }
}

pub fn run(args: &AddPolicyLayerArgs) -> Result<()> {
    let layer_raw = std::fs::read_to_string(expand_tilde(&args.layer_file))
        .with_context(|| format!("reading layer file {}", args.layer_file))?;
    let layer: Value = serde_json::from_str(&layer_raw).context("parsing layer file as JSON")?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let resp = client
        .get(format!("{}/v1/object", args.daemon.trim_end_matches('/')))
        .query(&[("path", ROOT_PATH), ("id", ROOT_ID), ("repo", &args.repo)])
        .send()
        .context("fetching current root policy")?;
    if resp.status().as_u16() == 404 {
        bail!("root policy {ROOT_PATH}{ROOT_ID} not found on {} for repo {}", args.daemon, args.repo);
    }
    let obj: ObjResp = resp.error_for_status()?.json().context("parsing root policy object")?;
    let policy = obj.value;
    if !policy.is_object() {
        bail!("root policy `value` is not a JSON object; refusing to edit");
    }
    if !obj.confirmed {
        bail!("the root policy read back is UNCONFIRMED — refusing to build an update on a value that may not stick");
    }

    let before_grants = policy.get("grants").and_then(Value::as_array).cloned().unwrap_or_default();
    let before_restrictions = policy.get("restrictions").and_then(Value::as_array).cloned().unwrap_or_default();
    let before_rest = rest_hash(&policy);

    let (merged, added) = merge(&policy, &layer)?;

    // Preservation proof: every prior entry still present IN ORDER, and nothing
    // outside grants/restrictions touched.
    let after_grants = merged.get("grants").and_then(Value::as_array).cloned().unwrap_or_default();
    let after_restrictions = merged.get("restrictions").and_then(Value::as_array).cloned().unwrap_or_default();
    let prefix_ok = after_grants.starts_with(&before_grants) && after_restrictions.starts_with(&before_restrictions);
    let rest_ok = rest_hash(&merged) == before_rest;

    println!("root policy on {} ({})", args.repo, args.daemon);
    println!("  grants       {} -> {}", before_grants.len(), after_grants.len());
    println!("  restrictions {} -> {}", before_restrictions.len(), after_restrictions.len());
    println!("  everything else unchanged: {}  ({before_rest})", if rest_ok { "yes" } else { "NO" });
    println!("  prior entries preserved in order: {}", if prefix_ok { "yes" } else { "NO" });
    if added.is_empty() {
        println!("\nNothing to add — every entry in the layer is already installed.");
        return Ok(());
    }
    println!("\nAdding {} entr{}:", added.len(), if added.len() == 1 { "y" } else { "ies" });
    for a in &added {
        println!("  + {a}");
    }
    if !prefix_ok || !rest_ok {
        bail!("ABORT — the merge did not preserve the existing policy; refusing to submit");
    }

    if !args.execute {
        println!("\nDry run — nothing submitted. Re-run with --execute to apply.");
        return Ok(());
    }

    let sys_key = load_signing_key_file(&expand_tilde(&args.sys_key_file))
        .with_context(|| format!("loading sys key {}", args.sys_key_file))?;
    let sys_owner = format!("ed25519:{}", hex::encode(sys_key.public_key().bytes));
    let payload = serde_json::to_vec(&merged).context("serializing merged policy")?;

    // KEY-ROOTED update, exactly as `set_root_admin` does: Owner preserved from
    // the current object, signed by the sys key, no cert, no `prev`.
    let owner = obj.owner_ref.as_deref().unwrap_or(&sys_owner);
    let wire_bytes = assemble_write(
        &sys_key, None, None, ROOT_PATH, ROOT_ID, "policy.v2", "application/json",
        payload, Some(owner), None,
    )?;

    let resp = client
        .post(format!("{}/v1/submit", args.daemon.trim_end_matches('/')))
        .query(&[("repo", &args.repo)])
        .header("Content-Type", "application/octet-stream")
        .body(wire_bytes)
        .send()
        .context("submitting root-policy update")?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("ABORT — submit failed: HTTP {status}: {body}");
    }
    println!("\n✓ submitted, signed by sys {sys_owner}\n  {body}");
    println!("\nThe policy governs only once the daemon has SYNCED PAST the block carrying it.");
    println!("Until then the old policy still applies, and any probe reports a false failure.");
    Ok(())
}
