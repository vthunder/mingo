//! `mingo` — Mingo application CLI. Emits signed SBO wire bytes for Mingo's
//! application-specific writes (aggregated genesis, community policy re-issue).
//! It only *builds and signs*; submission is a separate step (POST the wire to a
//! daemon's `/v1/submit`), keeping this tool decoupled from any live daemon.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use sbo_core::keyring::Keyring;
use mingo_app::genesis::{community_policy_open, mingo_genesis, MingoCommunity};

#[derive(Parser)]
#[command(name = "mingo", about = "Mingo application CLI (emits signed SBO wire)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the Mingo aggregated genesis (domain-certified sys + pinned broker +
    /// the cooks/woodworking/homelab starter communities + hub root policy) and
    /// write the signed wire batch to --out.
    Genesis {
        /// Domain name for the domain-certified sys identity (e.g. mingo.place).
        #[arg(long)]
        domain: String,
        /// Pinned broker (defaults to id.<domain>).
        #[arg(long)]
        broker: Option<String>,
        /// Key alias for the sys identity (default: keyring default).
        #[arg(long)]
        key: Option<String>,
        /// Key alias for the domain identity (default: same as --key).
        #[arg(long)]
        domain_key: Option<String>,
        /// Key alias for the checkpoint authority (default: freshly generated).
        /// This dedicated key is granted `create` on /sys/checkpoints/**; the
        /// daemon signs `checkpoint.v1` roots with it. Its secret is written to
        /// --checkpoint-key-out for deployment (never the sys key).
        #[arg(long)]
        checkpoint_key: Option<String>,
        /// File to write the checkpoint authority key (JSON {secret_key}) for the
        /// daemon's [checkpoint] key_file.
        #[arg(long, default_value = "checkpoint-key.json")]
        checkpoint_key_out: String,
        /// File to write the signed wire batch to.
        #[arg(long, default_value = "genesis.wire")]
        out: String,
    },

    /// Re-issue a community's policy as OPEN + community-scoped (anyone can join
    /// by self-issuing a `membership:<id>` attestation). Writes the signed wire
    /// to --out.
    OpenCommunity {
        /// Community id (e.g. cooks).
        community_id: String,
        /// Community issuer (e.g. cooks@mingo.place) — still governs bans.
        issuer: String,
        /// Key alias to sign with (must have authority over /communities/<id>/).
        #[arg(long)]
        key: Option<String>,
        /// File to write the signed wire bytes to.
        #[arg(long, default_value = "policy.wire")]
        out: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let keyring = Keyring::open().context("opening keyring")?;

    match cli.command {
        Commands::Genesis { domain, broker, key, domain_key, checkpoint_key, checkpoint_key_out, out } => {
            let sys_alias = keyring.resolve_alias(key.as_deref())?;
            let sys_key = keyring.get_signing_key(&sys_alias)?;
            let domain_alias = match domain_key.as_deref() {
                Some(dk) => keyring.resolve_alias(Some(dk))?,
                None => sys_alias.clone(),
            };
            let domain_signing_key = keyring.get_signing_key(&domain_alias)?;
            // Dedicated checkpoint authority key — from a keyring alias, or freshly
            // generated for a brand-new chain. Its secret is written for the daemon.
            let (checkpoint_signing_key, checkpoint_source) = match checkpoint_key.as_deref() {
                Some(alias) => {
                    let a = keyring.resolve_alias(Some(alias))?;
                    let k = keyring.get_signing_key(&a)?;
                    (k, format!("keyring alias `{a}`"))
                }
                None => (sbo_core::crypto::SigningKey::generate(), "freshly generated".to_string()),
            };
            let broker = broker.unwrap_or_else(|| format!("id.{}", domain));

            // Starter communities (issuer = <id>@<domain>).
            let issuers: Vec<(String, String, String, String)> = [
                ("cooks", "Cooks", "Home cooks swapping recipes and technique."),
                ("woodworking", "Woodworking", "Makers, joinery, and finishing."),
                ("homelab", "Homelab", "Self-hosters and home infrastructure."),
            ]
            .iter()
            .map(|(id, name, desc)| {
                ((*id).to_string(), (*name).to_string(), (*desc).to_string(), format!("{}@{}", id, domain))
            })
            .collect();
            let communities: Vec<MingoCommunity> = issuers
                .iter()
                .map(|(id, name, desc, issuer)| MingoCommunity { id, name, description: desc, issuer })
                .collect();

            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .ok();

            let wire = mingo_genesis(
                &domain_signing_key,
                &sys_key,
                &checkpoint_signing_key,
                &domain,
                &broker,
                &communities,
                created_at,
            );
            std::fs::write(&out, &wire).with_context(|| format!("writing {out}"))?;

            // Write the checkpoint authority key for the daemon (KEEP SECRET). The
            // genesis grants its `checkpointer` identity `create` on /sys/checkpoints/**.
            let key_file = serde_json::json!({
                "secret_key": hex::encode(checkpoint_signing_key.to_bytes()),
            });
            std::fs::write(&checkpoint_key_out, serde_json::to_vec_pretty(&key_file)?)
                .with_context(|| format!("writing {checkpoint_key_out}"))?;

            println!(
                "✓ wrote Mingo genesis (domain {}, broker {}, communities: {}) to {} ({} bytes, sys {}, domain {})",
                domain,
                broker,
                communities.iter().map(|c| c.id).collect::<Vec<_>>().join(", "),
                out,
                wire.len(),
                sys_alias,
                domain_alias,
            );
            println!(
                "✓ wrote checkpoint authority key ({}) to {} — deploy it to the daemon's [checkpoint] key_file and set publish=true (KEEP SECRET; pubkey {})",
                checkpoint_source,
                checkpoint_key_out,
                hex::encode(checkpoint_signing_key.public_key().bytes),
            );
            println!(
                "\nSubmit: curl --data-binary @{} -H 'Content-Type: application/octet-stream' <daemon>/v1/submit",
                out
            );
        }
        Commands::OpenCommunity { community_id, issuer, key, out } => {
            let alias = keyring.resolve_alias(key.as_deref())?;
            let signing_key = keyring.get_signing_key(&alias)?;
            let wire = community_policy_open(&signing_key, &community_id, &issuer);
            std::fs::write(&out, &wire).with_context(|| format!("writing {out}"))?;
            println!(
                "✓ wrote OPEN policy for /communities/{}/ (issuer {}) to {} ({} bytes, signed by {})",
                community_id, issuer, out, wire.len(), alias
            );
            println!(
                "\nSubmit: curl --data-binary @{} -H 'Content-Type: application/octet-stream' <daemon>/v1/submit",
                out
            );
        }
    }

    Ok(())
}
