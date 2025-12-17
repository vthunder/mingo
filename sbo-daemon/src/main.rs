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
        Request::RepoAdd { uri, path, from_block } => {
            let parsed_uri = match SboUri::parse(&uri) {
                Ok(u) => u,
                Err(e) => return Response::error(e.to_string()),
            };

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
            match state.repos.add(parsed_uri, path, resolved_from_block) {
                Ok(repo) => Response::ok(serde_json::json!({
                    "id": repo.id,
                    "uri": repo.uri.to_string(),
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
                        "id": r.id,
                        "uri": r.uri.to_string(),
                        "path": r.path,
                        "head": r.head,
                    })
                })
                .collect();
            Response::ok(repos)
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
