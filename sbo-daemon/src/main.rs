//! SBO Daemon Binary
//!
//! Manages local SBO repository replicas with data availability verification.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcServer, Request, Response};
use sbo_daemon::lc::LcManager;
use sbo_daemon::prover::Prover;
use sbo_daemon::repo::{RepoManager, SboUri};
use sbo_daemon::rpc::RpcClient;
use sbo_daemon::sync::SyncEngine;
use sbo_daemon::turbo::TurboDaClient;

#[derive(Parser)]
#[command(name = "sbo-daemon")]
#[command(about = "SBO daemon for repository sync and data availability verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,

        /// Verbose output for specific components (can be repeated)
        /// Options: rpc, raw-incoming, blocks
        #[arg(long = "verbose", short = 'v', value_name = "COMPONENT")]
        verbose: Vec<String>,

        /// Enable prover mode (generate ZK proofs for processed blocks)
        #[arg(long)]
        prover: bool,

        /// Enable light mode (verify proofs instead of executing state transitions)
        #[arg(long)]
        light: bool,
    },
    /// Show daemon status
    Status,
    /// Initialize configuration
    Init,
}

/// Verbose logging flags
#[derive(Clone, Default)]
pub struct VerboseFlags {
    /// Log RPC connection details
    pub rpc: bool,
    /// Log raw incoming data for repos
    pub raw_incoming: bool,
    /// Log every block processed (even empty ones)
    pub blocks: bool,
}

impl VerboseFlags {
    fn from_args(args: &[String]) -> Self {
        Self {
            rpc: args.iter().any(|s| s == "rpc"),
            raw_incoming: args.iter().any(|s| s == "raw-incoming"),
            blocks: args.iter().any(|s| s == "blocks"),
        }
    }
}

/// Shared daemon state
struct DaemonState {
    config: Config,
    repos: RepoManager,
    lc: LcManager,
    rpc: RpcClient,
    turbo: TurboDaClient,
}

impl DaemonState {
    async fn new(config: Config) -> anyhow::Result<Self> {
        // Create directories
        std::fs::create_dir_all(&config.daemon.repos_dir)?;

        // Initialize components
        let repos = RepoManager::load(config.daemon.repos_index.clone())?;

        let lc = LcManager::new(config.light_client.clone());
        let rpc = RpcClient::new(config.rpc.clone(), false);
        let turbo = TurboDaClient::new(config.turbo_da.clone());

        Ok(Self {
            config,
            repos,
            lc,
            rpc,
            turbo,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load or create config
    let config_path = cli.config.unwrap_or_else(Config::config_path);
    let config = Config::load(&config_path).unwrap_or_default();

    match cli.command {
        Commands::Init => {
            init_config(&config_path, &config)?;
        }
        Commands::Start { foreground, verbose, prover, light } => {
            if !foreground {
                tracing::warn!("Daemonizing not yet implemented, running in foreground");
            }
            if prover && light {
                anyhow::bail!("Cannot enable both --prover and --light modes simultaneously");
            }
            let verbose_flags = VerboseFlags::from_args(&verbose);

            // Override config with CLI flags
            let mut config = config;
            if prover {
                if config.light.enabled {
                    anyhow::bail!("Cannot enable --prover when light mode is enabled in config");
                }
                config.prover.enabled = true;
                tracing::info!("Prover mode enabled via CLI flag");
            }
            if light {
                config.light.enabled = true;
                config.prover.enabled = false; // Mutually exclusive with light mode
                tracing::info!("Light mode enabled via CLI flag");
            }

            run_daemon(config, verbose_flags).await?;
        }
        Commands::Status => {
            show_status(&config).await?;
        }
    }

    Ok(())
}

fn init_config(path: &PathBuf, config: &Config) -> anyhow::Result<()> {
    if path.exists() {
        println!("Config already exists at {}", path.display());
        return Ok(());
    }

    config.save(path)?;
    println!("Created config at {}", path.display());
    println!("\nEdit the config to set your TurboDA API key and other settings.");

    // Create directories
    std::fs::create_dir_all(Config::sbo_dir())?;
    println!("Created {}", Config::sbo_dir().display());

    Ok(())
}

async fn run_daemon(config: Config, verbose: VerboseFlags) -> anyhow::Result<()> {
    tracing::info!("Starting SBO daemon");

    // Check for existing daemon
    if config.daemon.socket_path.exists() {
        anyhow::bail!(
            "Socket already exists at {}. Is another daemon running?",
            config.daemon.socket_path.display()
        );
    }

    // Initialize state
    let state = Arc::new(RwLock::new(DaemonState::new(config.clone()).await?));

    // Start light client manager
    {
        let mut state = state.write().await;
        if let Err(e) = state.lc.start().await {
            tracing::warn!("Light client not available: {}. Sync will be limited.", e);
        }
    }

    // Start IPC server
    let ipc_server = IpcServer::new(config.daemon.socket_path.clone());
    let state_for_ipc = Arc::clone(&state);

    let ipc_handle = tokio::spawn(async move {
        let handler = move |req: Request| {
            let state = Arc::clone(&state_for_ipc);
            async move { handle_request(req, state).await }
        };

        if let Err(e) = ipc_server.run(handler).await {
            tracing::error!("IPC server error: {}", e);
        }
    });

    // Start sync engine
    let state_for_sync = Arc::clone(&state);
    let verbose_for_sync = verbose.clone();
    let prover_config = config.prover.clone();
    let turbo_config = config.turbo_da.clone();
    let light_mode = config.light.enabled;
    let sync_handle = tokio::spawn(async move {
        // Give IPC server time to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create prover if enabled
        let mut prover = if prover_config.enabled {
            tracing::info!(
                "Prover mode enabled: batch_size={}, receipt_kind={}, dev_mode={}",
                prover_config.batch_size,
                prover_config.receipt_kind,
                prover_config.dev_mode
            );
            Some(Prover::new(prover_config.clone()))
        } else {
            None
        };

        // Create TurboDA client for proof submission
        let turbo = TurboDaClient::new(turbo_config);

        loop {
            // Get config with short lock
            let (lc_config, rpc_config) = {
                let state = state_for_sync.read().await;
                (state.config.light_client.clone(), state.config.rpc.clone())
            };

            // Check LC status without holding lock
            let lc = LcManager::new(lc_config.clone());
            match lc.status().await {
                Ok(status) => {
                    tracing::debug!(
                        "LC status: latest={}, available={}-{}",
                        status.latest_block,
                        status.available_first,
                        status.available_last
                    );
                }
                Err(e) => {
                    tracing::debug!("LC unavailable: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }

            // Process one sync cycle
            let lc = LcManager::new(lc_config.clone());
            let status = match lc.status().await {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Process blocks for each repo
            let mut sync = SyncEngine::new(
                LcManager::new(lc_config),
                RpcClient::new(rpc_config, verbose_for_sync.rpc),
                verbose_for_sync.raw_incoming,
                light_mode,
            );

            // Get repo info with read lock
            let repos_info: Vec<_> = {
                let state = state_for_sync.read().await;
                state.repos.list().map(|r| (r.uri.clone(), r.head, r.path.clone())).collect()
            };

            // Find minimum head and maximum end across all repos
            let mut min_start = u64::MAX;
            let mut max_end = 0u64;
            for (_uri, head, _path) in &repos_info {
                let start = (*head + 1).max(status.available_first);
                let end = status.available_last.min(status.latest_block);
                if start <= end {
                    min_start = min_start.min(start);
                    max_end = max_end.max(end);
                }
            }

            if min_start <= max_end {
                // Process blocks in order
                for block_num in min_start..=max_end {
                    // Process block with write lock
                    let mut state = state_for_sync.write().await;
                    match sync.process_block(block_num, &mut state.repos).await {
                        Ok(result) => {
                            // Only log if there was data or verbose blocks enabled
                            if result.tx_count > 0 || verbose_for_sync.blocks {
                                tracing::info!("Processed block {} ({} transactions)", block_num, result.tx_count);
                            }

                            // Add block to prover if enabled and genesis has been processed
                            if let Some(ref mut p) = prover {
                                // Only prove if genesis has been processed (objects exist)
                                if !result.has_genesis {
                                    // Skip proving until genesis is processed
                                    if result.tx_count > 0 {
                                        tracing::debug!(
                                            "Skipping prover for block {} - genesis not yet processed",
                                            block_num
                                        );
                                    }
                                } else if block_num < max_end {
                                    // Skip proving while catching up (not at head yet)
                                    // Only prove once we're processing the latest block
                                    tracing::debug!(
                                        "Skipping prover for block {} - catching up ({} blocks behind)",
                                        block_num, max_end - block_num
                                    );
                                } else {
                                    // Use real state roots and objects from process_block result
                                    let pre_root = result.pre_state_root.unwrap_or([0u8; 32]);
                                    let post_root = result.post_state_root;

                                    p.add_block(
                                        block_num,
                                        pre_root,
                                        post_root,
                                        result.block_data,
                                        result.state_witness,
                                    );

                                    // Check if we should generate and submit a proof
                                    if p.should_prove(block_num) {
                                        if let Some(proof_result) = p.generate_proof() {
                                            let sbop_bytes = p.create_sbop_message(&proof_result);
                                            tracing::info!(
                                                "Generated {} proof for blocks {}-{} ({} bytes)",
                                                proof_result.receipt_kind.as_str(),
                                                proof_result.from_block,
                                                proof_result.to_block,
                                                sbop_bytes.len()
                                            );

                                            // Submit to Avail via TurboDA
                                            match turbo.submit_proof(sbop_bytes).await {
                                                Ok(tx_hash) => {
                                                    tracing::info!(
                                                        "Submitted proof to Avail: {}",
                                                        tx_hash
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "Failed to submit proof: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to process block {}: {}", block_num, e);
                            // Don't update head, will retry next cycle
                            break;
                        }
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });

    tracing::info!("Daemon running. Socket: {}", config.daemon.socket_path.display());

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");

    // Cleanup
    if config.daemon.socket_path.exists() {
        std::fs::remove_file(&config.daemon.socket_path)?;
    }

    ipc_handle.abort();
    sync_handle.abort();

    Ok(())
}

async fn handle_request(req: Request, state: Arc<RwLock<DaemonState>>) -> Response {
    match req {
        Request::RepoAdd { display_uri, resolved_uri, path, from_block } => {
            // Parse the resolved URI (always sbo+raw://)
            let uri = match SboUri::parse(&resolved_uri) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid URI: {}", e)),
            };

            // Check for duplicates
            {
                let state = state.read().await;
                for repo in state.repos.list() {
                    if repo.uri.to_string() == uri.to_string() {
                        return Response::error(format!(
                            "Already tracking this chain as {}",
                            repo.display_uri
                        ));
                    }
                }
            }

            // Resolve negative from_block relative to current chain head
            let resolved_from_block = match from_block {
                Some(block) if block < 0 => {
                    // Need to query light client for latest block
                    let state_read = state.read().await;
                    match state_read.lc.status().await {
                        Ok(status) => {
                            let latest = status.latest_block as i64;
                            let resolved = (latest + block).max(0) as u64;
                            tracing::info!(
                                "Resolved from_block {} relative to latest {} = {}",
                                block, latest, resolved
                            );
                            Some(resolved)
                        }
                        Err(e) => {
                            return Response::error(format!(
                                "Cannot resolve negative from_block: light client unavailable: {}",
                                e
                            ));
                        }
                    }
                }
                Some(block) => Some(block as u64),
                None => None,
            };

            let mut state = state.write().await;
            match state.repos.add(display_uri.clone(), uri, path, resolved_from_block) {
                Ok(repo) => Response::ok(serde_json::json!({
                    "id": repo.id,
                    "display_uri": repo.display_uri,
                    "resolved_uri": repo.uri.to_string(),
                    "path": repo.path,
                    "head": repo.head,
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::RepoRemove { path } => {
            let mut state = state.write().await;
            match state.repos.remove(&path) {
                Ok(repo) => Response::ok(serde_json::json!({
                    "removed": repo.uri.to_string(),
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::RepoRemoveByUri { uri } => {
            let mut state = state.write().await;
            match state.repos.remove_by_uri(&uri) {
                Ok(repo) => Response::ok(serde_json::json!({
                    "removed": repo.uri.to_string(),
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::RepoList => {
            let state = state.read().await;
            let repos: Vec<_> = state
                .repos
                .list()
                .map(|r| {
                    serde_json::json!({
                        "display_uri": r.display_uri,
                        "resolved_uri": r.uri.to_string(),
                        "path": r.path.to_string_lossy(),
                        "head": r.head,
                        "dns_checked_at": r.dns_checked_at,
                    })
                })
                .collect();
            Response::ok(serde_json::json!({ "repos": repos }))
        }

        Request::RepoRelink { path } => {
            let mut state = state.write().await;

            // Find repo by path
            let repo = match state.repos.find_by_path(&path) {
                Some(r) => r.clone(),
                None => return Response::error(format!("No repo at path: {}", path.display())),
            };

            // Check if it's a DNS-based URI
            if !sbo_core::dns::is_dns_uri(&repo.display_uri) {
                return Response::error("Repo is not using a DNS-based URI (sbo://)");
            }

            // Re-resolve DNS
            let new_resolved = match sbo_core::dns::resolve_uri(&repo.display_uri).await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("DNS resolution failed: {}", e)),
            };

            // Parse new URI
            let new_uri = match SboUri::parse(&new_resolved) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid resolved URI: {}", e)),
            };

            let old_resolved = repo.uri.to_string();

            // Update repo
            if let Err(e) = state.repos.update_uri(&repo.id, repo.display_uri.clone(), new_uri) {
                return Response::error(format!("Failed to update repo: {}", e));
            }

            Response::ok(serde_json::json!({
                "display_uri": repo.display_uri,
                "old_resolved": old_resolved,
                "new_resolved": new_resolved,
                "message": "Repo relinked. Will re-sync from new chain."
            }))
        }

        Request::Status => {
            let state = state.read().await;

            let lc_status = match state.lc.status().await {
                Ok(s) => serde_json::json!({
                    "connected": true,
                    "network": s.network,
                    "latest_block": s.latest_block,
                    "modes": s.modes,
                }),
                Err(e) => serde_json::json!({
                    "connected": false,
                    "error": e.to_string(),
                }),
            };

            let repo_count = state.repos.list().count();

            Response::ok(serde_json::json!({
                "light_client": lc_status,
                "repos": repo_count,
                "app_ids": state.repos.followed_app_ids(),
            }))
        }

        Request::Submit { repo_path, sbo_path, id, data } => {
            let state = state.read().await;

            // Find the repo
            let repo = match state.repos.get_by_path(&repo_path) {
                Some(r) => r,
                None => return Response::error(format!("No repo at path: {}", repo_path.display())),
            };

            // TODO: Build proper SBO message with signing
            // For now, just submit raw data
            match state.turbo.submit_raw(&data).await {
                Ok(result) => Response::ok(serde_json::json!({
                    "submission_id": result.submission_id,
                    "app_id": repo.uri.app_id,
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::GetObject { repo_path: _, path, id, with_proof: _ } => {
            // TODO: Implement GetObject with proof support
            Response::error(format!("GetObject not yet implemented for {}:{}", path, id))
        }

        Request::ObjectProof { repo_path, path, id } => {
            let state = state.read().await;

            // Find the repo
            let repo = match state.repos.get_by_path(&repo_path) {
                Some(r) => r,
                None => return Response::error(format!("No repo at path: {}", repo_path.display())),
            };

            // Get state db for this repo
            let state_db = match repo.state_db() {
                Ok(db) => db,
                Err(e) => return Response::error(format!("Failed to open state db: {}", e)),
            };

            // Parse path and id
            let sbo_path = match sbo_core::message::Path::parse(&path) {
                Ok(p) => p,
                Err(e) => return Response::error(format!("Invalid path: {}", e)),
            };
            let sbo_id = match sbo_core::message::Id::new(&id) {
                Ok(i) => i,
                Err(e) => return Response::error(format!("Invalid id: {}", e)),
            };

            // Generate trie proof (auto-detects creator)
            match state_db.generate_trie_proof_auto(&sbo_path, &sbo_id) {
                Ok(Some((creator, trie_proof))) => {
                    // Read the object file from disk
                    // Object path is: repo_path / sbo_path (without leading /) / id
                    let object_file_path = repo.path.join(path.trim_start_matches('/')).join(&id);
                    let object_bytes = match std::fs::read(&object_file_path) {
                        Ok(bytes) => Some(bytes),
                        Err(e) => {
                            tracing::warn!(
                                "Could not read object file at {}: {}",
                                object_file_path.display(), e
                            );
                            None
                        }
                    };

                    // Create SBOQ message with trie proof
                    let sboq = sbo_core::proof::SboqMessage {
                        version: "0.2".to_string(),
                        path: path.clone(),
                        id: id.clone(),
                        creator: creator.to_string(),
                        block: repo.head,
                        state_root: trie_proof.state_root,
                        object_hash: trie_proof.object_hash,
                        trie_proof,
                        object: object_bytes,
                    };

                    let sboq_bytes = sbo_core::proof::serialize_sboq(&sboq);
                    let sboq_text = String::from_utf8_lossy(&sboq_bytes).to_string();

                    Response::ok(serde_json::json!({
                        "sboq": sboq_text,
                        "creator": creator.to_string(),
                        "state_root": hex::encode(sboq.state_root),
                        "object_hash": sboq.object_hash.map(hex::encode),
                    }))
                }
                Ok(None) => Response::error("Object not found"),
                Err(e) => Response::error(format!("Failed to generate proof: {}", e)),
            }
        }

        Request::SubmitIdentity { uri, name, data, wait } => {
            use sbo_core::message::{Path, Id};

            // Get state for repo lookup and config
            let state_read = state.read().await;
            let light_mode = state_read.config.light.enabled;

            // Find repo matching the URI
            let repo = state_read.repos.list().find(|r| uri.starts_with(&r.uri.to_string()));

            let (repo_path, identity_uri) = match repo {
                Some(r) => (r.path.clone(), format!("{}/sys/names/{}", uri.trim_end_matches('/'), name)),
                None => return Response::error(format!("No repo configured for URI: {}. Add with: sbo repo add {} <path>", uri, uri)),
            };

            // Submit via TurboDA
            match state_read.turbo.submit_raw(&data).await {
                Ok(result) => {
                    // Drop read lock before polling
                    drop(state_read);

                    if wait && !light_mode {
                        // Poll for verification in full mode
                        let state_path = repo_path.join("state");
                        if let Ok(state_db) = sbo_core::state::StateDb::open(&state_path) {
                            // Poll for up to 30 seconds
                            let start = std::time::Instant::now();
                            let timeout = std::time::Duration::from_secs(30);

                            let path = match Path::parse("/sys/names/") {
                                Ok(p) => p,
                                Err(e) => return Response::error(format!("Invalid path: {}", e)),
                            };
                            let id = match Id::new(&name) {
                                Ok(i) => i,
                                Err(e) => return Response::error(format!("Invalid id: {}", e)),
                            };

                            loop {
                                // Check if object exists
                                if let Ok(Some(_)) = state_db.get_first_object_at_path_id(&path, &id) {
                                    return Response::ok(serde_json::json!({
                                        "status": "verified",
                                        "uri": identity_uri,
                                        "submission_id": result.submission_id,
                                    }));
                                }

                                if start.elapsed() > timeout {
                                    return Response::ok(serde_json::json!({
                                        "status": "pending",
                                        "uri": identity_uri,
                                        "submission_id": result.submission_id,
                                        "message": "Submitted but verification timed out. Check with 'sbo id show'",
                                    }));
                                }

                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                        }
                    }

                    // No wait or light mode - return immediately
                    Response::ok(serde_json::json!({
                        "status": "unverified",
                        "uri": identity_uri,
                        "submission_id": result.submission_id,
                    }))
                }
                Err(e) => Response::error(format!("Submission failed: {}", e)),
            }
        }

        Request::ListIdentities { uri } => {
            let state_read = state.read().await;
            let mut identities = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by URI if provided
                if let Some(ref filter_uri) = uri {
                    if !repo.uri.to_string().starts_with(filter_uri) {
                        continue;
                    }
                }

                // Scan /sys/names/ directory
                // Structure: /sys/names/<name> (file) or /sys/names/<name>/<object_id> (directory)
                let names_path = repo.path.join("sys").join("names");
                if names_path.exists() {
                    if let Ok(entries) = std::fs::read_dir(&names_path) {
                        for entry in entries.flatten() {
                            let name = entry.file_name().to_string_lossy().to_string();
                            let entry_path = entry.path();

                            // Try to find identity content - either direct file or file in directory
                            let content = if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                                // Direct file (e.g., /sys/names/sys)
                                std::fs::read(&entry_path).ok()
                            } else if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                // Directory - look for first file inside
                                std::fs::read_dir(&entry_path).ok().and_then(|files| {
                                    files.flatten().find(|f| f.file_type().map(|t| t.is_file()).unwrap_or(false))
                                        .and_then(|f| std::fs::read(f.path()).ok())
                                })
                            } else {
                                None
                            };

                            if let Some(content) = content {
                                if let Ok(msg) = sbo_core::wire::parse(&content) {
                                    if let Some(payload) = &msg.payload {
                                        // Parse identity payload
                                        let identity_data = if let Ok(identity) = sbo_core::schema::parse_identity(payload) {
                                            Some((identity.public_key, identity.display_name))
                                        } else {
                                            // Fallback for raw JSON
                                            serde_json::from_slice::<serde_json::Value>(payload).ok().and_then(|v| {
                                                let public_key = v.get("public_key")
                                                    .and_then(|k| k.as_str())
                                                    .map(|s| s.to_string())?;
                                                let display_name = v.get("display_name").and_then(|d| d.as_str()).map(|s| s.to_string());
                                                Some((public_key, display_name))
                                            })
                                        };

                                        if let Some((public_key, display_name)) = identity_data {
                                            identities.push(serde_json::json!({
                                                "uri": format!("{}/sys/names/{}", repo.uri.to_string().trim_end_matches('/'), name),
                                                "chain": repo.uri.to_string(),
                                                "name": name,
                                                "display_name": display_name,
                                                "public_key": public_key,
                                                "status": "verified",
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Response::ok(serde_json::json!({ "identities": identities }))
        }

        Request::GetIdentity { uri } => {
            let state_read = state.read().await;

            // Parse URI to extract chain and name
            // Supports: sbo+raw://avail:turing:506/sys/names/alice or just "alice"
            let (chain_uri, name) = if uri.starts_with("sbo+raw://") || uri.starts_with("sbo://") {
                // Full URI - extract chain and name
                if let Some(names_pos) = uri.find("/sys/names/") {
                    let chain = &uri[..names_pos + 1]; // Include trailing /
                    let name = &uri[names_pos + 11..]; // Skip "/sys/names/"
                    (Some(chain.to_string()), name.to_string())
                } else {
                    return Response::error("Invalid identity URI: must contain /sys/names/");
                }
            } else {
                // Just a name - search all repos
                (None, uri)
            };

            let mut found_identities = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by chain if provided
                if let Some(ref chain) = chain_uri {
                    if !repo.uri.to_string().starts_with(chain.trim_end_matches('/')) {
                        continue;
                    }
                }

                // Try to read the identity file
                let identity_path = repo.path.join("sys").join("names").join(&name);
                if identity_path.exists() {
                    if let Ok(content) = std::fs::read(&identity_path) {
                        if let Ok(msg) = sbo_core::wire::parse(&content) {
                            if let Some(payload) = &msg.payload {
                                // Parse identity payload
                                let identity_data = if let Ok(identity) = sbo_core::schema::parse_identity(payload) {
                                    Some((identity.public_key, identity.display_name, identity.description, identity.avatar, identity.links, identity.binding))
                                } else {
                                    // Fallback for raw JSON
                                    serde_json::from_slice::<serde_json::Value>(payload).ok().and_then(|v| {
                                        let public_key = v.get("public_key")
                                            .and_then(|k| k.as_str())
                                            .map(|s| s.to_string())?;
                                        let display_name = v.get("display_name").and_then(|d| d.as_str()).map(|s| s.to_string());
                                        Some((public_key, display_name, None, None, None, None))
                                    })
                                };

                                if let Some((public_key, display_name, description, avatar, links, binding)) = identity_data {
                                    found_identities.push(serde_json::json!({
                                        "uri": format!("{}/sys/names/{}", repo.uri.to_string().trim_end_matches('/'), name),
                                        "chain": repo.uri.to_string(),
                                        "name": name,
                                        "public_key": public_key,
                                        "display_name": display_name,
                                        "description": description,
                                        "avatar": avatar,
                                        "links": links,
                                        "binding": binding,
                                        "status": "verified",
                                    }));
                                }
                            }
                        }
                    }
                }
            }

            if found_identities.is_empty() {
                Response::error(format!("Identity '{}' not found", name))
            } else if found_identities.len() == 1 {
                Response::ok(found_identities.into_iter().next().unwrap())
            } else {
                // Multiple identities with same name across chains
                Response::ok(serde_json::json!({ "identities": found_identities }))
            }
        }

        Request::RepoCreate { uri, path, genesis_data } => {
            // Parse and validate URI
            let parsed_uri = match SboUri::parse(&uri) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid URI: {}", e)),
            };

            // URI path must be "/" for genesis (no path prefix or empty)
            if parsed_uri.path_prefix.is_some() && parsed_uri.path_prefix.as_deref() != Some("/") {
                return Response::error("URI path must be '/' for repo creation");
            }

            let state_read = state.read().await;

            // Check if repo already exists
            if state_read.repos.list().any(|r| r.uri.to_string() == parsed_uri.to_string()) {
                return Response::error(format!("Repo already exists for URI: {}", uri));
            }

            // Get current block height before submission
            let current_block = match state_read.lc.status().await {
                Ok(status) => status.latest_block,
                Err(e) => {
                    return Response::error(format!("Cannot get chain head: {}", e));
                }
            };

            // Submit genesis via TurboDA
            match state_read.turbo.submit_raw(&genesis_data).await {
                Ok(result) => {
                    tracing::info!(
                        "Genesis submitted for {}: submission_id={}",
                        uri, result.submission_id
                    );

                    // Drop read lock before taking write lock
                    drop(state_read);

                    // Add repo starting from current block
                    let mut state_write = state.write().await;
                    match state_write.repos.add(uri.clone(), parsed_uri.clone(), path.clone(), Some(current_block)) {
                        Ok(repo) => {
                            Response::ok(serde_json::json!({
                                "uri": repo.uri.to_string(),
                                "path": repo.path,
                                "from_block": current_block,
                                "submission_id": result.submission_id,
                            }))
                        }
                        Err(e) => {
                            Response::error(format!(
                                "Genesis submitted (id={}) but failed to add repo: {}",
                                result.submission_id, e
                            ))
                        }
                    }
                }
                Err(e) => Response::error(format!("Failed to submit genesis: {}", e)),
            }
        }

        Request::Shutdown => {
            tracing::info!("Shutdown requested via IPC");
            // TODO: Graceful shutdown
            Response::ok(serde_json::json!({"status": "shutting down"}))
        }
    }
}

async fn show_status(config: &Config) -> anyhow::Result<()> {
    use sbo_daemon::ipc::IpcClient;

    let client = IpcClient::new(config.daemon.socket_path.clone());

    match client.request(Request::Status).await {
        Ok(Response::Ok { data }) => {
            println!("SBO Daemon Status");
            println!("=================");
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Ok(Response::Error { message }) => {
            println!("Error: {}", message);
        }
        Err(e) => {
            println!("Daemon not running or unreachable: {}", e);
        }
    }

    Ok(())
}
