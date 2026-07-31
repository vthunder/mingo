//! Refresh on-chain `/sys/dnssec/<domain>` evidence objects.
//!
//! Attribution of every email-rooted write dies when an issuer's on-chain
//! RRSIG window lapses (GENESIS.md's "proofs expire" warning — this is the
//! refresher it asked for). The daemon captures the proof; anyone may post
//! it (self-authenticating, throwaway-signed), so this needs no keys.
//!
//! Usage: dnssec-refresh [--daemon URL] <domain>...
//! Cron-friendly: exits non-zero if any domain fails to end up fresh.

use anyhow::Result;

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let daemon = if args.first().map(|a| a == "--daemon").unwrap_or(false) {
        args.remove(0);
        if args.is_empty() {
            anyhow::bail!("--daemon needs a URL");
        }
        args.remove(0)
    } else {
        "https://da.sandmill.org".to_string()
    };
    if args.is_empty() {
        anyhow::bail!("usage: dnssec-refresh [--daemon URL] <domain>...");
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let mut failed = false;
    for domain in &args {
        if let Err(e) = mingo_app::seed::ensure_dnssec_fresh(&client, &daemon, domain, now_s) {
            eprintln!("✗ {domain}: {e:#}");
            failed = true;
        }
    }
    if failed {
        anyhow::bail!("some domains failed to refresh");
    }
    Ok(())
}
