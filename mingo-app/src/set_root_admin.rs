//! `mingo set-root-admin` — safely rewrite ONLY `roles.admin` in the LIVE root
//! policy (`/sys/policies/` id `root`) to migrate Mingo admin from the baked sys
//! key to an external email identity (and later to that email alone).
//!
//! This is a HIGH-STAKES root-policy edit: getting it wrong bricks admin. The
//! whole design is defensive:
//!
//! 1. **Fetch** the current root policy from the daemon (`GET /v1/object`),
//!    parsing its `value` as the `policy.v2` JSON.
//! 2. **Mutate only `roles.admin`** — every other field (grants, restrictions,
//!    other roles, deny, anything else) is round-tripped through `serde_json`
//!    untouched. serde_json's `Value` serializes with sorted keys, matching the
//!    daemon's canonical on-chain form.
//! 3. **Prove preservation**: a fingerprint (grant/restriction counts + a hash of
//!    the ENTIRE policy with `roles.admin` removed) is computed before and after
//!    and asserted identical, and printed in the dry-run so a human can see that
//!    nothing else moved.
//! 4. **Dry-run by default**: prints current vs proposed admin and the
//!    preservation proof, then STOPS. Only `--execute` submits.
//! 5. **Cutover guard**: if the proposed admin list drops the sys key (the
//!    irreversible step — the sys key can no longer edit the policy), it demands
//!    an explicit `--i-understand-cutover` before `--execute` will proceed.
//!
//! The re-post is KEY-ROOTED exactly like the genesis root policy and the
//! `livetest` P2-P4 policy writes: signed by the sys key, `Owner` = the sys
//! pubkey, no cert (the root policy grants the sys admin key `govern` on `/**`,
//! so it can UPDATE `/sys/policies/root` in place — no regenesis).

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use sbo_core::crypto::ContentHash;

use crate::seed::{assemble_write, load_signing_key_file};

pub struct SetRootAdminArgs {
    /// The FULL admin member list. Each entry is either a key
    /// (`ed25519:<hex>` or `key:<hex>` → `{"key": "ed25519:<hex>"}`) or an
    /// email/name → a bare string (`"danmills@sandmill.org"`, the untagged
    /// `Identity::Name` form). Repeatable.
    pub admin: Vec<String>,
    /// SBO daemon origin (read the current policy + submit the update).
    pub daemon: String,
    /// Sys key file (`ed25519:<hex>` export or JSON `{"secret_key": <hex>}`),
    /// `~` expanded. Holds admin-by-key → `govern` on `/**`; signs the update.
    pub sys_key_file: String,
    /// Actually submit the update (default is a dry-run print).
    pub execute: bool,
    /// Acknowledge that the proposed admin list drops the sys key — required to
    /// `--execute` the irreversible cutover.
    pub i_understand_cutover: bool,
}

/// Parse one `--admin <id>` into its policy member object.
///
/// - `ed25519:<hex>` / `key:<hex>` → `{"key": "ed25519:<hex>"}` (the on-chain
///   admin-by-key form; a `key:` prefix is normalized to `ed25519:`).
/// - anything else (an email like `danmills@sandmill.org`, or a bare name like
///   `sys`) → a bare JSON string. `Identity::Name` is an UNTAGGED string variant
///   in sbo's policy schema (`"danmills@sandmill.org"`), NOT `{"name": …}` —
///   emitting an object here makes the daemon reject the policy ("data did not
///   match any variant of untagged enum Identity").
pub fn parse_admin_member(spec: &str) -> Result<Value> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("empty --admin entry");
    }
    if let Some(hex) = spec
        .strip_prefix("ed25519:")
        .or_else(|| spec.strip_prefix("key:"))
    {
        let hex = hex.trim();
        // Validate it's real hex of a 32-byte ed25519 pubkey so we never install
        // an admin key that can never match a signer.
        let raw = hex::decode(hex).with_context(|| format!("--admin '{spec}': decoding key hex"))?;
        if raw.len() != 32 {
            bail!("--admin '{spec}': ed25519 pubkey must be 32 bytes ({} given)", raw.len());
        }
        Ok(serde_json::json!({ "key": format!("ed25519:{hex}") }))
    } else {
        // Identity::Name is an untagged bare string, not an object.
        Ok(Value::String(spec.to_string()))
    }
}

/// A key member's `ed25519:<hex>` string, if this member is a `{"key": ...}`.
fn member_key(m: &Value) -> Option<&str> {
    m.get("key").and_then(Value::as_str)
}

/// Return a copy of `policy` with `roles.admin` replaced by `admins`. Every
/// other field is preserved exactly (the value is cloned, only that one vector
/// is swapped). Errors if the policy isn't a JSON object.
pub fn mutate_admin(policy: &Value, admins: &[Value]) -> Result<Value> {
    let mut out = policy.clone();
    let obj = out
        .as_object_mut()
        .ok_or_else(|| anyhow!("root policy is not a JSON object"))?;
    let roles = obj
        .entry("roles")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let roles = roles
        .as_object_mut()
        .ok_or_else(|| anyhow!("policy `roles` is not a JSON object"))?;
    roles.insert("admin".to_string(), Value::Array(admins.to_vec()));
    Ok(out)
}

/// A preservation fingerprint of everything in the policy EXCEPT `roles.admin`.
/// Computed before and after the mutation; the two must be identical, which is
/// the machine-checkable proof that only `roles.admin` changed.
pub struct Fingerprint {
    pub grants: usize,
    pub restrictions: usize,
    /// Role names other than `admin`, sorted.
    pub other_roles: Vec<String>,
    /// `sha256:<hex>` of the whole policy with `roles.admin` removed.
    pub rest_hash: String,
}

pub fn fingerprint(policy: &Value) -> Fingerprint {
    let grants = policy.get("grants").and_then(Value::as_array).map_or(0, Vec::len);
    let restrictions = policy
        .get("restrictions")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let mut other_roles: Vec<String> = policy
        .get("roles")
        .and_then(Value::as_object)
        .map(|r| r.keys().filter(|k| *k != "admin").cloned().collect())
        .unwrap_or_default();
    other_roles.sort();

    // Hash the entire policy with `roles.admin` stripped — captures grants,
    // restrictions, deny, other roles, and any field we don't know about.
    let mut rest = policy.clone();
    if let Some(roles) = rest.get_mut("roles").and_then(Value::as_object_mut) {
        roles.remove("admin");
    }
    let bytes = serde_json::to_vec(&rest).expect("policy re-serialization");
    let rest_hash = ContentHash::sha256(&bytes).to_string();

    Fingerprint {
        grants,
        restrictions,
        other_roles,
        rest_hash,
    }
}

/// The subset of `GET /v1/object` we consume for the root policy.
#[derive(Debug, Deserialize)]
struct ObjResp {
    #[serde(default)]
    value: Value,
    #[serde(default)]
    owner_ref: Option<String>,
    #[serde(default)]
    object_hash: String,
    #[serde(default)]
    confirmed: bool,
}

const ROOT_PATH: &str = "/sys/policies/";
const ROOT_ID: &str = "root";

fn fetch_root_policy(client: &reqwest::blocking::Client, daemon: &str) -> Result<ObjResp> {
    let resp = client
        .get(format!("{}/v1/object", daemon.trim_end_matches('/')))
        .query(&[("path", ROOT_PATH), ("id", ROOT_ID)])
        .send()
        .context("fetching current root policy")?;
    if resp.status().as_u16() == 404 {
        bail!("root policy {ROOT_PATH}{ROOT_ID} not found on {daemon}");
    }
    let resp = resp.error_for_status().context("fetching current root policy")?;
    resp.json().context("parsing root policy object")
}

/// True when the proposed admin list no longer contains `sys_key` — the
/// irreversible cutover (the sys key loses the authority to edit this policy).
fn is_cutover(proposed: &[Value], sys_key: &str) -> bool {
    !proposed.iter().any(|m| member_key(m) == Some(sys_key))
}

fn print_members(label: &str, members: &[Value]) {
    println!("  {label}");
    if members.is_empty() {
        println!("    (empty!)");
    }
    for m in members {
        println!("    {}", serde_json::to_string(m).unwrap_or_default());
    }
}

pub fn run(args: &SetRootAdminArgs) -> Result<()> {
    if args.admin.is_empty() {
        bail!("at least one --admin <id> is required");
    }
    let proposed: Vec<Value> = args
        .admin
        .iter()
        .map(|s| parse_admin_member(s))
        .collect::<Result<_>>()?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let obj = fetch_root_policy(&client, &args.daemon)?;
    let policy = obj.value;
    if !policy.is_object() {
        bail!("root policy `value` is not a JSON object; refusing to edit");
    }

    let current_admin: Vec<Value> = policy
        .get("roles")
        .and_then(|r| r.get("admin"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let updated = mutate_admin(&policy, &proposed)?;

    // Preservation proof: fingerprint of everything-but-roles.admin, before/after.
    let before = fingerprint(&policy);
    let after = fingerprint(&updated);
    let preserved = before.rest_hash == after.rest_hash
        && before.grants == after.grants
        && before.restrictions == after.restrictions
        && before.other_roles == after.other_roles;

    // Determine the sys key we would sign with, for the cutover check. Best-effort
    // in a dry-run (so the warning is accurate when the key file is present);
    // required in --execute.
    let sys_owner: Option<String> = match load_sys_owner(&args.sys_key_file) {
        Ok(o) => Some(o),
        Err(e) => {
            if args.execute {
                return Err(e).context("--execute needs the sys key to sign the update");
            }
            None
        }
    };
    // For the cutover decision, the "sys key" is the loaded key if available,
    // else the key that currently holds admin on-chain (which IS the sys key).
    let sys_key_for_check: Option<String> = sys_owner.clone().or_else(|| {
        current_admin
            .iter()
            .find_map(|m| member_key(m).map(str::to_string))
    });
    let cutover = match &sys_key_for_check {
        Some(k) => is_cutover(&proposed, k),
        None => true, // can't identify a sys key → treat as the dangerous case
    };

    // ---- report -----------------------------------------------------------
    println!("set-root-admin on {} ({ROOT_PATH}{ROOT_ID})", args.daemon);
    println!(
        "  current object_hash {}  (confirmed: {})",
        obj.object_hash, obj.confirmed
    );
    println!(
        "  owner_ref (preserved) {}",
        obj.owner_ref.as_deref().unwrap_or("(none)")
    );
    println!();
    print_members("current roles.admin:", &current_admin);
    print_members("proposed roles.admin:", &proposed);
    println!();
    println!("  ALL OTHER POLICY CONTENT IS PRESERVED — proof (before == after):");
    println!(
        "    grants:       {} == {}",
        before.grants, after.grants
    );
    println!(
        "    restrictions: {} == {}",
        before.restrictions, after.restrictions
    );
    println!(
        "    other roles:  {:?} == {:?}",
        before.other_roles, after.other_roles
    );
    println!(
        "    rest hash (policy minus roles.admin):\n      before {}\n      after  {}",
        before.rest_hash, after.rest_hash
    );
    if !preserved {
        bail!("ABORT — preservation check FAILED: something other than roles.admin changed. Refusing to submit.");
    }
    println!("    => preserved: OK");
    println!();

    if cutover {
        println!("  ⚠ CUTOVER WARNING: the proposed roles.admin does NOT include the sys key");
        match &sys_key_for_check {
            Some(k) => println!("    sys key {k} is about to LOSE admin — this is IRREVERSIBLE."),
            None => println!("    (could not identify the sys key; treating as a cutover)"),
        }
        println!("    After this, only the listed identities can edit the root policy.");
        println!();
    }

    if !args.execute {
        println!("Dry run — nothing submitted. Re-run with --execute to apply.");
        if cutover {
            println!("(A cutover also requires --i-understand-cutover.)");
        }
        return Ok(());
    }

    // ---- execute ----------------------------------------------------------
    if cutover && !args.i_understand_cutover {
        bail!(
            "ABORT — this --execute drops the sys key from admin (irreversible cutover). \
             Re-run with --i-understand-cutover to proceed."
        );
    }

    let sys_key = load_signing_key_file(&expand_tilde(&args.sys_key_file))
        .context("loading sys signing key")?;
    let sys_owner = sys_owner.expect("sys owner computed when execute");

    let payload = serde_json::to_vec(&updated)?;
    let new_hash = ContentHash::sha256(&payload).to_string();
    // KEY-ROOTED update: Owner = sys pubkey (preserved from the current object),
    // signed by the sys key, no cert. Root policy grants admin-by-key `govern`
    // on /**, so this UPDATES /sys/policies/root in place. `prev` is left unset:
    // the daemon applies key-rooted policy amendments without it (verified live by
    // the livetest S9-S13 policy-amendment scenarios, which also submit prev-less).
    let owner = obj.owner_ref.as_deref().unwrap_or(&sys_owner);
    let wire_bytes = assemble_write(
        &sys_key,
        None,
        None,
        ROOT_PATH,
        ROOT_ID,
        "policy.v2",
        "application/json",
        payload,
        Some(owner),
        None,
    )?;

    let resp = client
        .post(format!("{}/v1/submit", args.daemon.trim_end_matches('/')))
        .header("Content-Type", "application/octet-stream")
        .body(wire_bytes)
        .send()
        .context("submitting root-policy update")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("ABORT — submit failed: HTTP {status}: {body}");
    }
    println!("✓ submitted root-policy update (new payload hash {new_hash}, signed by sys {sys_owner})");
    println!("  Verify: curl '{}/v1/object?path={ROOT_PATH}&id={ROOT_ID}'", args.daemon.trim_end_matches('/'));
    Ok(())
}

/// `~`-expand and load the sys key, returning its `ed25519:<hex>` owner string.
fn load_sys_owner(path: &str) -> Result<String> {
    let key = load_signing_key_file(&expand_tilde(path))?;
    Ok(format!("ed25519:{}", hex::encode(key.public_key().bytes)))
}

/// Expand a leading `~` to `$HOME` (mirrors livetest's key-file handling).
fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) => format!("{home}{rest}"),
            Err(_) => path.to_string(),
        },
        None => path.to_string(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The real live root policy shape (from da.sandmill.org), sys key as admin.
    fn sample_policy() -> Value {
        serde_json::json!({
            "grants": [
                { "can": ["create"], "on": "/sys/names/*", "to": "*" },
                { "can": ["update", "delete"], "on": "/sys/names/*", "to": "owner" },
                { "can": ["*"], "on": "/u/$owner/**", "to": "owner" },
                { "can": ["create", "update"], "on": "/sys/dnssec/**", "to": "*" },
                { "can": ["create"], "on": "/sys/checkpoints/**", "to": { "key": "ed25519:937fc1e8073a1d3939bb59fa744e4fd2d7ff365c2cd573ca8a931b47e7949c00" } },
                { "can": ["post", "transfer", "delete", "govern"], "on": "/**", "to": { "role": "admin" } }
            ],
            "restrictions": [
                { "on": "/communities/*/spaces/**", "require": { "not_attested": { "type": "ban" } } },
                { "on": "/sys/dnssec/**", "require": { "content_type": "application/octet-stream", "dnssec_proof": true, "schema": "dnssec.v1" } }
            ],
            "roles": { "admin": [{ "key": "ed25519:564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd" }] }
        })
    }

    const SYS_KEY: &str = "ed25519:564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd";

    #[test]
    fn key_specs_normalize_to_ed25519_key_members() {
        let hex = "564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd";
        assert_eq!(
            parse_admin_member(&format!("ed25519:{hex}")).unwrap(),
            serde_json::json!({ "key": format!("ed25519:{hex}") })
        );
        assert_eq!(
            parse_admin_member(&format!("key:{hex}")).unwrap(),
            serde_json::json!({ "key": format!("ed25519:{hex}") })
        );
    }

    #[test]
    fn email_and_bare_name_specs_become_bare_string_members() {
        // Identity::Name is an untagged bare string, not {"name": …}.
        assert_eq!(
            parse_admin_member("danmills@sandmill.org").unwrap(),
            serde_json::json!("danmills@sandmill.org")
        );
        assert_eq!(
            parse_admin_member("sys").unwrap(),
            serde_json::json!("sys")
        );
    }

    #[test]
    fn bad_key_hex_is_rejected() {
        assert!(parse_admin_member("ed25519:nothex").is_err());
        assert!(parse_admin_member("ed25519:dead").is_err()); // too short
        assert!(parse_admin_member("").is_err());
    }

    #[test]
    fn mutate_changes_only_admin_and_preserves_everything_else() {
        let policy = sample_policy();
        let before = fingerprint(&policy);
        let proposed = vec![
            parse_admin_member(SYS_KEY).unwrap(),
            parse_admin_member("danmills@sandmill.org").unwrap(),
        ];
        let updated = mutate_admin(&policy, &proposed).unwrap();
        let after = fingerprint(&updated);

        // roles.admin changed as requested.
        assert_eq!(
            updated["roles"]["admin"],
            serde_json::json!([
                parse_admin_member(SYS_KEY).unwrap(),
                "danmills@sandmill.org"
            ])
        );
        // Everything else is byte-identical.
        assert_eq!(before.rest_hash, after.rest_hash);
        assert_eq!(before.grants, after.grants);
        assert_eq!(before.restrictions, after.restrictions);
        assert_eq!(before.other_roles, after.other_roles);
        // Grants/restrictions vectors themselves are untouched.
        assert_eq!(updated["grants"], policy["grants"]);
        assert_eq!(updated["restrictions"], policy["restrictions"]);
    }

    #[test]
    fn cutover_detection() {
        // Dual-admin transition keeps the sys key → NOT a cutover.
        let transition = vec![
            parse_admin_member(SYS_KEY).unwrap(),
            parse_admin_member("danmills@sandmill.org").unwrap(),
        ];
        assert!(!is_cutover(&transition, SYS_KEY));

        // Email-only final cutover drops the sys key → IS a cutover.
        let final_admin = vec![parse_admin_member("danmills@sandmill.org").unwrap()];
        assert!(is_cutover(&final_admin, SYS_KEY));
    }
}
