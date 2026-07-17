//! `mingo` — Mingo application CLI. Emits signed SBO wire bytes for Mingo's
//! application-specific writes (aggregated genesis, community policy re-issue).
//! It only *builds and signs*; submission is a separate step (POST the wire to a
//! daemon's `/v1/submit`), keeping this tool decoupled from any live daemon.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use mingo_app::genesis::{community_policy_open, mingo_genesis, MingoCommunity};
use sbo_core::keyring::Keyring;

#[derive(Parser)]
#[command(
    name = "mingo",
    about = "Mingo application CLI (emits signed SBO wire)"
)]
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
        /// Transient domain key from a file (`{"secret_key":"<hex 32-byte seed>"}`,
        /// same shape as checkpoint-key.json) instead of a keyring alias — e.g. the
        /// `_browserid` provider key for self-certifying Mode B. Read once, never
        /// persisted to the keyring. Takes precedence over --domain-key.
        #[arg(long)]
        domain_key_file: Option<String>,
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
        /// Self-certifying Mode B: path to the domain's `_browserid.<domain>` DNSSEC
        /// chain (RFC 4034 wire). Seeded at /sys/dnssec/<domain> and referenced by
        /// domain.v1 (`Auth-Evidence: ref:`). Use with --domain-key-file set to the
        /// `_browserid` provider key. Omit for plain Mode B.
        #[arg(long)]
        dnssec_evidence: Option<String>,
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

    /// Seed a lived-in demo corpus (personas, memberships, posts/comments/
    /// upvotes with staggered ages, cross-persona vouches/badges) into a live
    /// daemon. Dry-run by default — prints the full write plan; pass --execute
    /// to provision personas at the IdP and submit.
    Seed {
        /// IdP origin (its host is the identity domain, e.g. mingo.place).
        #[arg(long, default_value = "https://mingo.place")]
        idp: String,
        /// SBO daemon origin to submit to.
        #[arg(long, default_value = "https://da.sandmill.org")]
        daemon: String,
        /// Corpus JSON file (defaults to the embedded corpus).
        #[arg(long)]
        corpus: Option<String>,
        /// Sys key file (`ed25519:<hex>` keyring export, e.g.
        /// ~/secure-backup/mingo-sys.key, or JSON {"secret_key": <hex>}).
        /// When given, each community's spaces/general `_config` is temporarily
        /// widened to a 45-day authoring lag so true corpus ages (~30d) land,
        /// then restored to the genesis 24h. Without it, ages are compressed
        /// to fit under 20h.
        #[arg(long)]
        sys_key: Option<String>,
        /// Actually provision + submit (default is a dry-run print).
        #[arg(long)]
        execute: bool,
        /// Broker (fallback IdP) origin — mints certs for external-identity
        /// personas via its admin endpoint.
        #[arg(long, default_value = "https://browserid.me")]
        broker: String,
        /// Env var holding the broker admin token (X-Admin-Token) for
        /// external-identity cert mints.
        #[arg(long, default_value = "BROKER_ADMIN_TOKEN")]
        broker_admin_token_env: String,
        /// Warrant audience for digest-bot agent writes — must identify the
        /// production SBO database (mingo-idp MINGO_SBO_DB_AUDIENCE).
        #[arg(long, default_value = "sbo+raw://avail:turing:506/")]
        audience: String,
        /// Env var holding the IdP admin token (X-Admin-Token).
        #[arg(long, default_value = "MINGO_ADMIN_TOKEN")]
        admin_token_env: String,
    },

    /// Appoint a board-scoped moderator on the live chain: issue a
    /// `role:moderator:<commId>` `attestation.v1` attributed to the community
    /// issuer `<commId>@mingo.place` (which the regenesis-v5 policy binds the
    /// `role:moderator` capability to). DRY-RUN by default — prints the write
    /// plan; pass --execute to mint the issuer cert and submit.
    AppointModerator {
        /// Community id (e.g. cooks). Its issuer <commId>@mingo.place owns the
        /// attestation and is minted for the write.
        comm_id: String,
        /// The moderator's mingo identity — the attestation subject (e.g.
        /// asha@mingo.place).
        subject: String,
        /// IdP origin (its host is the identity domain, e.g. mingo.place).
        #[arg(long, default_value = "https://mingo.place")]
        idp: String,
        /// SBO daemon origin to submit to.
        #[arg(long, default_value = "https://da.sandmill.org")]
        daemon: String,
        /// Env var holding the IdP admin token (X-Admin-Token).
        #[arg(long, default_value = "MINGO_ADMIN_TOKEN")]
        admin_token_env: String,
        /// Attestation `value` (cosmetic; policy matches on type + issuer).
        /// Defaults to "moderator".
        #[arg(long)]
        value: Option<String>,
        /// Expiry as ISO-8601 (RFC-3339), or `none`/absent for no expiry.
        #[arg(long)]
        expires: Option<String>,
        /// Actually mint the issuer cert + submit (default is a dry-run print).
        #[arg(long)]
        execute: bool,
        /// Explicitly request a dry-run print (the default; accepted for clarity
        /// and ignored — only --execute submits).
        #[arg(long)]
        dry_run: bool,
    },

    /// Run live-chain authorization scenarios against the SBO chain: provision
    /// disposable `livetest-*@mingo.place` identities, perform attributed
    /// writes, and assert head state (PRESENT/ABSENT) — validating the
    /// policy-delegation model (capture fix, memberships, owner/moderator
    /// semantics). DRY-RUN by default (prints the scenario plan); pass
    /// --execute to write to the live chain.
    LiveTest {
        /// IdP origin (its host is the identity domain, e.g. mingo.place).
        #[arg(long, default_value = "https://mingo.place")]
        idp: String,
        /// SBO daemon origin (reads + submit).
        #[arg(long, default_value = "https://da.sandmill.org")]
        daemon: String,
        /// Env var holding the IdP admin token (X-Admin-Token).
        #[arg(long, default_value = "MINGO_ADMIN_TOKEN")]
        admin_token_env: String,
        /// Restrict to specific scenarios, comma-separated (e.g. --only S1,S2).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Keep test objects on-chain at the end (skip the cleanup report).
        #[arg(long)]
        keep: bool,
        /// Actually provision + write to the LIVE chain (default: print plan).
        #[arg(long)]
        execute: bool,
    },
}

/// Load a transient domain signing key from `{"secret_key":"<hex 32-byte seed>"}`
/// (the checkpoint-key.json shape). Used to sign genesis with the `_browserid`
/// provider key without importing it into the keyring.
fn load_domain_key_file(path: &str) -> Result<sbo_core::crypto::SigningKey> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&contents).context("parsing domain key file")?;
    let secret = v
        .get("secret_key")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("domain key file missing string field `secret_key`"))?;
    let raw = hex::decode(secret.trim()).context("decoding hex secret_key")?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret_key must be a 32-byte seed"))?;
    Ok(sbo_core::crypto::SigningKey::from_bytes(&arr))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let keyring = Keyring::open().context("opening keyring")?;

    match cli.command {
        Commands::Genesis {
            domain,
            broker,
            key,
            domain_key,
            domain_key_file,
            checkpoint_key,
            checkpoint_key_out,
            dnssec_evidence,
            out,
        } => {
            let sys_alias = keyring.resolve_alias(key.as_deref())?;
            let sys_key = keyring.get_signing_key(&sys_alias)?;
            // Domain key: a transient file (browserid StoredKeypair seed — e.g. the
            // _browserid provider key) takes precedence, else a keyring alias.
            let (domain_signing_key, domain_key_desc) = match domain_key_file.as_deref() {
                Some(path) => (load_domain_key_file(path)?, format!("file `{path}`")),
                None => {
                    let alias = match domain_key.as_deref() {
                        Some(dk) => keyring.resolve_alias(Some(dk))?,
                        None => sys_alias.clone(),
                    };
                    (
                        keyring.get_signing_key(&alias)?,
                        format!("keyring `{alias}`"),
                    )
                }
            };
            // Dedicated checkpoint authority key — from a keyring alias, or freshly
            // generated for a brand-new chain. Its secret is written for the daemon.
            let (checkpoint_signing_key, checkpoint_source) = match checkpoint_key.as_deref() {
                Some(alias) => {
                    let a = keyring.resolve_alias(Some(alias))?;
                    let k = keyring.get_signing_key(&a)?;
                    (k, format!("keyring alias `{a}`"))
                }
                None => (
                    sbo_core::crypto::SigningKey::generate(),
                    "freshly generated".to_string(),
                ),
            };
            let broker = broker.unwrap_or_else(|| format!("id.{}", domain));

            // Starter communities (issuer = <id>@<domain>).
            let issuers: Vec<(String, String, String, String)> = [
                (
                    "cooks",
                    "Cooks",
                    "Home cooks swapping recipes and technique.",
                ),
                (
                    "woodworking",
                    "Woodworking",
                    "Makers, joinery, and finishing.",
                ),
                (
                    "homelab",
                    "Homelab",
                    "Self-hosters and home infrastructure.",
                ),
            ]
            .iter()
            .map(|(id, name, desc)| {
                (
                    (*id).to_string(),
                    (*name).to_string(),
                    (*desc).to_string(),
                    format!("{}@{}", id, domain),
                )
            })
            .collect();
            let communities: Vec<MingoCommunity> = issuers
                .iter()
                .map(|(id, name, desc, issuer)| MingoCommunity {
                    id,
                    name,
                    description: desc,
                    issuer,
                })
                .collect();

            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .ok();

            let dnssec_bytes = match dnssec_evidence.as_deref() {
                Some(p) => {
                    Some(std::fs::read(p).with_context(|| format!("reading dnssec evidence {p}"))?)
                }
                None => None,
            };

            let wire = mingo_genesis(
                &domain_signing_key,
                &sys_key,
                &checkpoint_signing_key,
                &domain,
                &broker,
                &communities,
                created_at,
                dnssec_bytes.as_deref(),
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
                domain_key_desc,
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
        Commands::OpenCommunity {
            community_id,
            issuer,
            key,
            out,
        } => {
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
        Commands::Seed {
            idp,
            daemon,
            corpus,
            sys_key,
            execute,
            admin_token_env,
            broker,
            broker_admin_token_env,
            audience,
        } => {
            mingo_app::seed::run(&mingo_app::seed::SeedArgs {
                idp,
                daemon,
                broker,
                audience,
                corpus,
                sys_key,
                execute,
                admin_token_env,
                broker_admin_token_env,
            })?;
        }
        Commands::AppointModerator {
            comm_id,
            subject,
            idp,
            daemon,
            admin_token_env,
            value,
            expires,
            execute,
            dry_run: _,
        } => {
            mingo_app::appoint::run(&mingo_app::appoint::AppointArgs {
                comm_id,
                subject,
                idp,
                daemon,
                admin_token_env,
                value,
                expires,
                execute,
            })?;
        }
        Commands::LiveTest {
            idp,
            daemon,
            admin_token_env,
            only,
            keep,
            execute,
        } => {
            mingo_app::livetest::run(&mingo_app::livetest::LiveTestArgs {
                idp,
                daemon,
                admin_token_env,
                only,
                keep,
                execute,
            })?;
        }
    }

    Ok(())
}
