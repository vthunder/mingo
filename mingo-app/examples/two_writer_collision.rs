//! Production test harness for the community-space policy fix (sbo-qv95).
//!
//! Under global (path, id) uniqueness with the now-split space policy
//! (`member:create` + `owner:update` on `/communities/<id>/spaces/**`), a
//! member must be able to CREATE their own post but must NOT be able to
//! OVERWRITE another member's post (they lack `update`, and they are not the
//! object owner). This example proves that end-to-end against PRODUCTION.
//!
//! Run:
//!   MINGO_ADMIN_TOKEN=… cargo run -q -p mingo-app --example two_writer_collision
//!
//! It provisions two throwaway test members, joins them to `cooks`, then:
//!   3. Member A creates a post at a fixed collision (path, id)  → EXPECT accept
//!   4. Member B writes the SAME (path, id), higher HLC          → EXPECT REJECT
//!   5. Member B creates a DIFFERENT id (control)                → EXPECT accept
//!   6. Read-back confirms the occupant is still A's content
//!
//! Leaves 2 test handles + a couple of test objects on the chain (best-effort
//! id printout for later cleanup). Commits nothing.

use std::process::exit;
use std::time::Duration;

use browserid_core::KeyPair;
use sbo_core::crypto::SigningKey;

use mingo_app::seed::{assemble_write, hlc_at, physical_ms};

const DAEMON: &str = "https://da.sandmill.org";
const IDP: &str = "https://mingo.place";
const DOMAIN: &str = "mingo.place";
const COMMUNITY: &str = "cooks";

struct Member {
    handle: String,
    email: String,
    key: SigningKey,
    cert: String,
}

/// One PASS/FAIL expectation line; tracks overall exit status.
struct Report {
    ok: bool,
}
impl Report {
    fn new() -> Self {
        Report { ok: true }
    }
    fn check(&mut self, label: &str, pass: bool, detail: &str) {
        if pass {
            println!("  PASS  {label}");
        } else {
            println!("  FAIL  {label}");
            self.ok = false;
        }
        if !detail.is_empty() {
            println!("        {detail}");
        }
    }
}

fn provision(
    client: &reqwest::blocking::Client,
    admin_token: &str,
    handle: &str,
) -> anyhow::Result<Member> {
    let kp = KeyPair::generate();
    let key = SigningKey::from_bytes(kp.secret_bytes());
    let pubkey_b64 = kp.public_key().to_base64();
    let resp = client
        .post(format!("{IDP}/admin/provision"))
        .header("X-Admin-Token", admin_token)
        .json(&serde_json::json!({
            "external_email": format!("{handle}.seed@sandmill.org"),
            "handle": handle,
            "pubkey": { "algorithm": "Ed25519", "publicKey": pubkey_b64 },
        }))
        .send()?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("provision {handle} failed: HTTP {status}: {body}");
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    let cert = parsed
        .get("cert")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("provision {handle}: no cert in {body}"))?
        .to_string();
    Ok(Member {
        handle: handle.to_string(),
        email: format!("{handle}@{DOMAIN}"),
        key,
        cert,
    })
}

/// Submit wire bytes; returns Ok(()) on 2xx, Err(daemon body) otherwise.
fn submit(
    client: &reqwest::blocking::Client,
    wire_bytes: &[u8],
) -> Result<String, String> {
    let resp = client
        .post(format!("{DAEMON}/v1/submit"))
        .header("Content-Type", "application/octet-stream")
        .body(wire_bytes.to_vec())
        .send()
        .map_err(|e| format!("transport error: {e}"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

/// Join `COMMUNITY` as a self-issued membership attestation in the member's own
/// namespace — mirrors the SPA joinHub shape (see seed.rs
/// `membership_payload_matches_spa_join_shape`).
fn join_community(
    client: &reqwest::blocking::Client,
    m: &Member,
    now_s: i64,
) -> Result<(), String> {
    let addr = &m.email;
    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": addr,
        "type": format!("membership:{COMMUNITY}"),
        "value": { "community": COMMUNITY, "via": "collision-test" },
        "issued_at": now_s - 1800,
        "expires": serde_json::Value::Null,
        "issuer": addr,
    }))
    .map_err(|e| e.to_string())?;
    let wire = assemble_write(
        &m.key,
        Some(&m.cert),
        None,
        &format!("/u/{addr}/attestations/{addr}/"),
        &format!("membership-{COMMUNITY}"),
        "attestation.v1",
        "application/json",
        payload,
        Some(addr),
        None,
    )
    .map_err(|e| e.to_string())?;
    submit(client, &wire).map(|_| ())
}

/// Assemble a `post.v1` write (mirrors the seeder's inline post payload).
fn post_wire(
    m: &Member,
    path: &str,
    id: &str,
    body: &str,
    hlc: &str,
    created_at: i64,
) -> anyhow::Result<Vec<u8>> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "body": body,
        "parent": serde_json::Value::Null,
        "created_at": created_at,
    }))?;
    assemble_write(
        &m.key,
        Some(&m.cert),
        None,
        path,
        id,
        "post.v1",
        "application/json",
        payload,
        Some(&m.email),
        Some(hlc),
    )
}

fn main() {
    let admin_token = match std::env::var("MINGO_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("ERROR: MINGO_ADMIN_TOKEN env var is required");
            exit(2);
        }
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client");

    let mut rep = Report::new();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let now_s = now_ms / 1000;
    // Short run suffix so re-runs don't clash on the fixed collision id.
    let suffix = format!("{:x}", (now_ms as u64) & 0xffffff);
    let collision_path = format!("/communities/{COMMUNITY}/spaces/general/");
    let collision_id = format!("collision-test-{suffix}");
    let control_id = format!("control-{suffix}");

    println!("=== two-writer collision harness (sbo-qv95) ===");
    println!("daemon={DAEMON} idp={IDP} community={COMMUNITY}");
    println!("collision (path,id) = {collision_path} {collision_id}");
    println!("control id          = {control_id}");
    println!();

    // --- Step 1: provision two members ---------------------------------------
    println!("[1] provisioning two test members…");
    let member_a = match provision(&client, &admin_token, "collisiontesta") {
        Ok(m) => m,
        Err(e) => {
            eprintln!("FATAL provisioning A: {e}");
            exit(1);
        }
    };
    let member_b = match provision(&client, &admin_token, "collisiontestb") {
        Ok(m) => m,
        Err(e) => {
            eprintln!("FATAL provisioning B: {e}");
            exit(1);
        }
    };
    println!("    A = {} ({})", member_a.handle, member_a.email);
    println!("    B = {} ({})", member_b.handle, member_b.email);

    // --- Step 2: both join cooks ---------------------------------------------
    println!("[2] joining {COMMUNITY}…");
    if let Err(e) = join_community(&client, &member_a, now_s) {
        eprintln!("FATAL A join: {e}");
        exit(1);
    }
    if let Err(e) = join_community(&client, &member_b, now_s) {
        eprintln!("FATAL B join: {e}");
        exit(1);
    }
    println!("    both memberships submitted; waiting for overlay visibility…");
    std::thread::sleep(Duration::from_secs(3));
    println!();

    // --- Step 3: Member A creates the post (EXPECT accept) -------------------
    println!("[3] Member A creates post at collision (path,id)…");
    let a_hlc = hlc_at(now_ms, 0.0);
    let a_created = physical_ms(now_ms, 0.0);
    let a_wire = post_wire(
        &member_a,
        &collision_path,
        &collision_id,
        "A's original post — the rightful occupant.",
        &a_hlc,
        a_created,
    )
    .expect("assemble A post");
    match submit(&client, &a_wire) {
        Ok(_) => rep.check("A can CREATE its own post", true, ""),
        Err(e) => rep.check("A can CREATE its own post", false, &format!("daemon: {e}")),
    }
    std::thread::sleep(Duration::from_secs(2));

    // --- Step 4: Member B overwrites SAME (path,id), higher HLC (EXPECT REJECT)
    println!("[4] Member B attempts to OVERWRITE A's post (same path,id, higher HLC)…");
    let b_hlc = format!("{}.0", a_created + 5000); // strictly greater physical
    let b_wire = post_wire(
        &member_b,
        &collision_path,
        &collision_id,
        "B's overwrite attempt — MUST be rejected.",
        &b_hlc,
        a_created + 5000,
    )
    .expect("assemble B overwrite");
    let mut b_overwrite_error = String::new();
    match submit(&client, &b_wire) {
        Ok(body) => rep.check(
            "B CANNOT overwrite A's post",
            false,
            &format!("UNEXPECTEDLY ACCEPTED: {body}"),
        ),
        Err(e) => {
            b_overwrite_error = e.clone();
            rep.check("B CANNOT overwrite A's post", true, &format!("daemon rejected: {e}"));
        }
    }
    std::thread::sleep(Duration::from_secs(2));

    // --- Step 5: Control — B creates a DIFFERENT id (EXPECT accept) ----------
    println!("[5] Control: Member B creates its OWN post at a different id…");
    let ctl_hlc = hlc_at(now_ms, 0.0);
    let ctl_wire = post_wire(
        &member_b,
        &collision_path,
        &control_id,
        "B's own control post — proves B is an authorized member.",
        &ctl_hlc,
        a_created,
    )
    .expect("assemble control");
    let mut control_ok = false;
    match submit(&client, &ctl_wire) {
        Ok(_) => {
            control_ok = true;
            rep.check("B CAN create its own (different) post", true, "");
        }
        Err(e) => rep.check(
            "B CAN create its own (different) post",
            false,
            &format!("daemon: {e}"),
        ),
    }
    std::thread::sleep(Duration::from_secs(2));

    // --- Step 6: read-back confirms occupant is still A's --------------------
    println!("[6] reading back the collision object…");
    let readback = client
        .get(format!("{DAEMON}/v1/object"))
        .query(&[("path", collision_path.as_str()), ("id", collision_id.as_str())])
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<serde_json::Value>());
    let mut occupant = String::from("<unreadable>");
    match readback {
        Ok(obj) => {
            let creator = obj
                .get("owner_ref")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("creator").and_then(|v| v.as_str()))
                .unwrap_or("<none>")
                .to_string();
            occupant = creator.clone();
            let occupant_body = obj
                .get("value")
                .and_then(|v| v.get("body"))
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("payload_text").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let is_a = creator == member_a.email;
            rep.check(
                "collision occupant is A (not overwritten by B)",
                is_a,
                &format!("creator/owner_ref = {creator}; body = {occupant_body:?}"),
            );
        }
        Err(e) => rep.check(
            "collision occupant is A (not overwritten by B)",
            false,
            &format!("read-back failed: {e}"),
        ),
    }

    // --- Summary -------------------------------------------------------------
    println!();
    println!("=== SUMMARY ===");
    println!("Step 4 overwrite rejection (the fix): {}",
        if b_overwrite_error.is_empty() { "NOT REJECTED (BAD)".to_string() }
        else { format!("REJECTED — {b_overwrite_error}") });
    println!("Step 5 control accepted: {control_ok}");
    println!("Read-back occupant: {occupant}");
    println!();
    println!("Test objects LEFT ON CHAIN (remove later if desired):");
    println!("  post   {collision_path}{collision_id}   (owner {})", member_a.email);
    if control_ok {
        println!("  post   {collision_path}{control_id}   (owner {})", member_b.email);
    }
    println!("  memberships /u/<addr>/attestations/<addr>/membership-{COMMUNITY} for both handles");
    println!("Test handles: {} , {}", member_a.handle, member_b.handle);
    println!();

    if rep.ok {
        println!("RESULT: ALL EXPECTATIONS PASSED");
        exit(0);
    } else {
        println!("RESULT: ONE OR MORE EXPECTATIONS FAILED");
        exit(1);
    }
}
