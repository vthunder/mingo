//! `mingo appoint-moderator` — appoint a board-scoped moderator on the live
//! chain by issuing a `role:moderator:<commId>` attestation attributed to the
//! community issuer `<commId>@mingo.place`.
//!
//! The live regenesis-v5 community policy grants `role:moderator` (delete on
//! `spaces/**`) bound to `{attested:{type:"role:moderator:<commId>",
//! by:"<commId>@mingo.place"}}`, and matches on the attestation's authenticated
//! on-chain issuer (`owner_ref`). So the attestation MUST be owned by — and
//! signed with a cert for — `<commId>@mingo.place`.
//!
//! This reuses the `seed` module's write path exactly: an ephemeral Ed25519
//! keypair is provisioned as `<commId>@mingo.place` via the IdP's
//! `/admin/provision` (mirroring `seed::provision_persona`), then a single
//! `attestation.v1` object is `seed::assemble_write`-assembled (identity-cert
//! auth, no warrant/evidence — the daemon resolves `/sys/dnssec/mingo.place`
//! on-chain) and POSTed to `<daemon>/v1/submit`.
//!
//! DRY-RUN by default: without `--execute` it provisions nothing and submits
//! nothing, only printing the full write plan. This is a live-chain write.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use browserid_core::KeyPair;
use sbo_core::crypto::SigningKey;

use crate::seed::assemble_write;

pub struct AppointArgs {
    /// Community id (e.g. `cooks`). Its issuer `<commId>@mingo.place` owns the
    /// attestation and is minted for the write.
    pub comm_id: String,
    /// The moderator's mingo identity (the attestation subject), e.g.
    /// `asha@mingo.place`.
    pub subject: String,
    /// IdP origin (its host is the identity domain, e.g. mingo.place).
    pub idp: String,
    /// SBO daemon origin to submit to.
    pub daemon: String,
    /// Env var holding the IdP admin token (X-Admin-Token).
    pub admin_token_env: String,
    /// Attestation `value` (cosmetic — the policy matches on type + issuer, not
    /// value). Defaults to `"moderator"`.
    pub value: Option<String>,
    /// Expiry as ISO-8601, or `none`/absent for no expiry.
    pub expires: Option<String>,
    /// Actually provision + submit (default is a dry-run print).
    pub execute: bool,
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

/// Parse `--expires` into a Unix-seconds epoch (matching `issued_at`), or `None`
/// for no expiry (`none`, empty, or absent).
pub fn parse_expires(expires: Option<&str>) -> Result<Option<i64>> {
    match expires.map(str::trim) {
        None | Some("") | Some("none") => Ok(None),
        Some(s) => {
            let dt = chrono::DateTime::parse_from_rfc3339(s)
                .with_context(|| format!("parsing --expires '{s}' as ISO-8601/RFC-3339"))?;
            Ok(Some(dt.timestamp()))
        }
    }
}

/// The `attestation.v1` payload for a `role:moderator:<commId>` grant — the
/// exact shape `seed`/app.js write (subject/type/value/issued_at/expires/issuer),
/// with the community issuer as both `issuer` and `owner_ref`.
pub fn attestation_payload(
    comm_id: &str,
    subject: &str,
    issuer: &str,
    value: &str,
    issued_at: i64,
    expires: Option<i64>,
) -> serde_json::Value {
    serde_json::json!({
        "subject": subject,
        "type": format!("role:moderator:{comm_id}"),
        "value": value,
        "issued_at": issued_at,
        "expires": expires,
        "issuer": issuer,
    })
}

/// The fully-determined write this command emits (no keys/network yet).
pub struct AppointPlan {
    pub issuer: String,
    pub external_email: String,
    pub subject: String,
    pub path: String,
    pub id: String,
    pub owner: String,
    pub schema: &'static str,
    pub content_type: &'static str,
    pub payload: serde_json::Value,
}

pub fn build_plan(args: &AppointArgs, domain: &str, now_s: i64) -> Result<AppointPlan> {
    let comm_id = args.comm_id.as_str();
    if comm_id.is_empty() {
        bail!("community id must not be empty");
    }
    if args.subject.is_empty() {
        bail!("subject must not be empty");
    }
    let issuer = format!("{comm_id}@{domain}");
    // The ephemeral persona's external identity must be an @sandmill.org /
    // @example.com address — never impersonate a real external service — and
    // the IdP rejects an external_email in its own domain (reject_own_domain).
    let external_email = format!("{comm_id}.issuer@sandmill.org");
    let value = args.value.clone().unwrap_or_else(|| "moderator".to_string());
    let expires = parse_expires(args.expires.as_deref())?;
    let payload = attestation_payload(comm_id, &args.subject, &issuer, &value, now_s, expires);
    Ok(AppointPlan {
        issuer: issuer.clone(),
        external_email,
        subject: args.subject.clone(),
        path: format!("/u/{issuer}/attestations/{}/", args.subject),
        id: format!("role:moderator:{comm_id}"),
        owner: issuer,
        schema: "attestation.v1",
        content_type: "application/json",
        payload,
    })
}

fn now_unix_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
}

pub fn run(args: &AppointArgs) -> Result<()> {
    let domain = domain_of(&args.idp);
    let plan = build_plan(args, &domain, now_unix_s())?;

    println!("Appoint-moderator plan (idp {}, daemon {})", args.idp, args.daemon);
    println!("  community        {}", args.comm_id);
    println!("  issuer identity  {} (minted from external_email {})", plan.issuer, plan.external_email);
    println!("  subject          {}", plan.subject);
    println!("  write path       {}", plan.path);
    println!("  object id        {}", plan.id);
    println!("  owner (owner_ref) {}", plan.owner);
    println!("  schema           {}", plan.schema);
    println!("  payload          {}", serde_json::to_string(&plan.payload)?);
    println!();

    if !args.execute {
        println!("Dry run — nothing provisioned or submitted. Re-run with --execute to appoint.");
        return Ok(());
    }

    execute(args, &plan, &domain)
}

// ---- live execution --------------------------------------------------------

#[derive(Deserialize)]
struct ProvisionResp {
    #[serde(default)]
    success: bool,
    cert: String,
}

#[derive(Deserialize)]
struct DnssecResp {
    #[serde(default)]
    needs_refresh: bool,
    #[serde(default)]
    proof_b64: Option<String>,
}

fn execute(args: &AppointArgs, plan: &AppointPlan, domain: &str) -> Result<()> {
    let admin_token = std::env::var(&args.admin_token_env).with_context(|| {
        format!("--execute needs the IdP admin token in ${}", args.admin_token_env)
    })?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    // Attribution of the write depends on a fresh on-chain /sys/dnssec/<domain>
    // proof (the daemon resolves it to authenticate the issuer cert).
    ensure_dnssec_fresh(&client, &args.daemon, domain, now_unix_s())?;

    // Mint the <commId>@mingo.place identity cert bound to a fresh ephemeral key.
    let key = KeyPair::generate();
    let signing_key = SigningKey::from_bytes(key.secret_bytes());
    let cert = provision_issuer(
        &client,
        &args.idp,
        &admin_token,
        &args.comm_id,
        &plan.external_email,
        &key,
    )?;
    println!("✓ provisioned issuer identity {}", plan.issuer);

    let wire_bytes = assemble_write(
        &signing_key,
        Some(&cert),
        None,
        &plan.path,
        &plan.id,
        plan.schema,
        plan.content_type,
        serde_json::to_vec(&plan.payload)?,
        Some(&plan.owner),
        None,
    )?;

    submit(&client, &args.daemon, &wire_bytes, "appoint-moderator attestation")?;
    println!("✓ appointed {} as moderator of {} ({}{})", plan.subject, args.comm_id, plan.path, plan.id);
    Ok(())
}

/// Provision (or re-provision) the `<commId>@mingo.place` identity at the IdP:
/// binds `<commId>.issuer@sandmill.org` ↔ handle `<commId>` and mints a 24h cert
/// for the supplied ephemeral key. Mirrors `seed::provision_persona`.
fn provision_issuer(
    client: &reqwest::blocking::Client,
    idp: &str,
    admin_token: &str,
    comm_id: &str,
    external_email: &str,
    key: &KeyPair,
) -> Result<String> {
    let resp = client
        .post(format!("{}/admin/provision", idp.trim_end_matches('/')))
        .header("X-Admin-Token", admin_token)
        .json(&serde_json::json!({
            "external_email": external_email,
            "handle": comm_id,
            "pubkey": { "algorithm": "Ed25519", "publicKey": key.public_key().to_base64() },
        }))
        .send()
        .with_context(|| format!("provisioning {comm_id}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("ABORT — provisioning issuer '{comm_id}' failed: HTTP {status}: {body}");
    }
    let parsed: ProvisionResp = resp
        .json()
        .with_context(|| format!("parsing provision response for {comm_id}"))?;
    if !parsed.success {
        bail!("ABORT — provisioning issuer '{comm_id}' returned success=false");
    }
    Ok(parsed.cert)
}

/// Mirror `seed::ensure_dnssec_fresh`: ask the daemon whether the on-chain proof
/// covers now+margin; if not, submit the returned proof as a key-rooted write.
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
    use base64::Engine as _;
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&proof_b64)
        .context("decoding dnssec proof")?;
    let throwaway = SigningKey::generate();
    let wire_bytes = assemble_write(
        &throwaway,
        None,
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

/// POST wire bytes to `<daemon>/v1/submit`; surface a non-success body and stop.
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
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().unwrap_or_default();
    Err(anyhow!("ABORT — submit failed for [{label}]: HTTP {status}: {body}"))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sbo_core::wire;

    fn args(comm: &str, subject: &str) -> AppointArgs {
        AppointArgs {
            comm_id: comm.to_string(),
            subject: subject.to_string(),
            idp: "https://mingo.place".to_string(),
            daemon: "https://da.sandmill.org".to_string(),
            admin_token_env: "MINGO_ADMIN_TOKEN".to_string(),
            value: None,
            expires: None,
            execute: false,
        }
    }

    #[test]
    fn plan_targets_issuer_namespace_and_role_type() {
        let plan = build_plan(&args("cooks", "asha@mingo.place"), "mingo.place", 1_800_000_000).unwrap();
        assert_eq!(plan.issuer, "cooks@mingo.place");
        assert_eq!(plan.owner, "cooks@mingo.place");
        assert_eq!(plan.external_email, "cooks.issuer@sandmill.org");
        assert_eq!(plan.id, "role:moderator:cooks");
        assert_eq!(plan.path, "/u/cooks@mingo.place/attestations/asha@mingo.place/");
        assert_eq!(plan.payload["type"], serde_json::json!("role:moderator:cooks"));
        assert_eq!(plan.payload["subject"], serde_json::json!("asha@mingo.place"));
        assert_eq!(plan.payload["issuer"], serde_json::json!("cooks@mingo.place"));
        assert_eq!(plan.payload["value"], serde_json::json!("moderator"));
        assert_eq!(plan.payload["expires"], serde_json::Value::Null);
        assert_eq!(plan.payload["issued_at"], serde_json::json!(1_800_000_000_i64));
    }

    #[test]
    fn custom_value_and_expiry_flow_through() {
        let mut a = args("woodworking", "kai@mingo.place");
        a.value = Some("lead-mod".to_string());
        a.expires = Some("2027-01-01T00:00:00Z".to_string());
        let plan = build_plan(&a, "mingo.place", 100).unwrap();
        assert_eq!(plan.payload["value"], serde_json::json!("lead-mod"));
        // 2027-01-01T00:00:00Z == 1798761600 epoch seconds.
        assert_eq!(plan.payload["expires"], serde_json::json!(1_798_761_600_i64));
    }

    #[test]
    fn expires_none_variants_are_null() {
        assert_eq!(parse_expires(None).unwrap(), None);
        assert_eq!(parse_expires(Some("none")).unwrap(), None);
        assert_eq!(parse_expires(Some("")).unwrap(), None);
        assert!(parse_expires(Some("not-a-date")).is_err());
    }

    #[test]
    fn assembled_attestation_verifies_and_owns_issuer() {
        let plan = build_plan(&args("cooks", "asha@mingo.place"), "mingo.place", 1_800_000_000).unwrap();
        let key = SigningKey::generate();
        let wire_bytes = assemble_write(
            &key,
            Some("fake.cert.jws"),
            None,
            &plan.path,
            &plan.id,
            plan.schema,
            plan.content_type,
            serde_json::to_vec(&plan.payload).unwrap(),
            Some(&plan.owner),
            None,
        )
        .unwrap();
        let msg = wire::parse(&wire_bytes).expect("wire round-trips");
        sbo_core::message::verify_message(&msg).expect("signature verifies");
        assert_eq!(msg.id.as_str(), "role:moderator:cooks");
        assert_eq!(msg.owner.as_ref().unwrap().as_str(), "cooks@mingo.place");
        assert_eq!(msg.path.to_string(), "/u/cooks@mingo.place/attestations/asha@mingo.place/");
    }
}
