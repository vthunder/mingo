//! SBO Daemon Binary
//!
//! Manages local SBO repository replicas with data availability verification.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use sbo_daemon::config::Config;
use sbo_daemon::http::{self, SignRequestStore};
use sbo_daemon::ipc::{IpcServer, Request, Response, SignRequestStatus, SignRequest as IpcSignRequest};
use sbo_daemon::lc::LcManager;
use sbo_daemon::prover::Prover;
use sbo_daemon::repo::{RepoManager, SboUri};
use sbo_daemon::rpc::RpcClient;
use sbo_daemon::sync::SyncEngine;
use sbo_daemon::turbo::TurboDaClient;
use sbo_core::dns;

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
        /// Options: rpc, rpc-decode, raw-incoming, blocks
        #[arg(long = "verbose", short = 'v', value_name = "COMPONENT")]
        verbose: Vec<String>,

        /// Debug options (can be repeated)
        /// Options: save-raw-block
        #[arg(long = "debug", short = 'd', value_name = "OPTION")]
        debug: Vec<String>,

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
    /// Log RPC decode details (block headers, matrix decoding)
    pub rpc_decode: bool,
    /// Log raw incoming data for repos
    pub raw_incoming: bool,
    /// Log every block processed (even empty ones)
    pub blocks: bool,
}

impl VerboseFlags {
    fn from_args(args: &[String]) -> Self {
        Self {
            rpc: args.iter().any(|s| s == "rpc"),
            rpc_decode: args.iter().any(|s| s == "rpc-decode"),
            raw_incoming: args.iter().any(|s| s == "raw-incoming"),
            blocks: args.iter().any(|s| s == "blocks"),
        }
    }
}

/// Debug flags for development/troubleshooting
#[derive(Clone, Default)]
pub struct DebugFlags {
    /// Save raw block data (header, matrix, lookup) to /tmp/sbo-debug/
    pub save_raw_block: bool,
}

impl DebugFlags {
    fn from_args(args: &[String]) -> Self {
        Self {
            save_raw_block: args.iter().any(|s| s == "save-raw-block"),
        }
    }
}

/// In-flight session binding request (while waiting for user verification)
#[derive(Clone)]
#[allow(dead_code)]
struct SessionBindingRequest {
    /// Request ID (from domain's session endpoint)
    request_id: String,
    /// Email address
    email: String,
    /// Domain for this session
    domain: String,
    /// Discovery document for this domain
    discovery: dns::DiscoveryDocument,
    /// When this request was created
    created_at: u64,
    /// When this request expires
    expires_at: u64,
}

/// In-flight identity provisioning request (while waiting for user verification)
#[derive(Clone)]
#[allow(dead_code)]
struct IdentityProvisioningRequest {
    /// Request ID (from domain's identity endpoint)
    request_id: String,
    /// Email address
    email: String,
    /// Public key being registered
    public_key: String,
    /// Domain for this identity
    domain: String,
    /// Discovery document for this domain
    discovery: dns::DiscoveryDocument,
    /// When this request was created
    created_at: u64,
    /// When this request expires
    expires_at: u64,
}

/// Shared daemon state
struct DaemonState {
    config: Config,
    repos: RepoManager,
    lc: LcManager,
    #[allow(dead_code)]
    rpc: RpcClient,
    turbo: TurboDaClient,
    /// Pending sign requests from apps (keyed by request_id)
    sign_requests: HashMap<String, IpcSignRequest>,
    /// In-flight session binding requests (keyed by request_id)
    session_binding_requests: HashMap<String, SessionBindingRequest>,
    /// In-flight identity provisioning requests (keyed by request_id)
    identity_provisioning_requests: HashMap<String, IdentityProvisioningRequest>,
}

impl DaemonState {
    async fn new(config: Config) -> anyhow::Result<Self> {
        // Create directories
        std::fs::create_dir_all(&config.daemon.repos_dir)?;

        // Initialize components
        let repos = RepoManager::load(config.daemon.repos_index.clone())?;

        let lc = LcManager::new(config.light_client.clone());
        let rpc = RpcClient::new(config.rpc.clone(), false, false, false);
        let turbo = TurboDaClient::new(config.turbo_da.clone());

        Ok(Self {
            config,
            repos,
            lc,
            rpc,
            turbo,
            sign_requests: HashMap::new(),
            session_binding_requests: HashMap::new(),
            identity_provisioning_requests: HashMap::new(),
        })
    }
}

impl SignRequestStore for DaemonState {
    fn create_sign_request(&mut self, request: IpcSignRequest) -> String {
        let id = request.request_id.clone();
        self.sign_requests.insert(id.clone(), request);
        id
    }

    fn get_sign_request(&self, request_id: &str) -> Option<&IpcSignRequest> {
        self.sign_requests.get(request_id)
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
        Commands::Start { foreground, verbose, debug, prover, light } => {
            // Auto-create sample config if it doesn't exist
            if !config_path.exists() {
                std::fs::create_dir_all(Config::sbo_dir())?;
                Config::save_sample(&config_path)?;
                tracing::info!("Created sample config at {}", config_path.display());
            }
            if !foreground {
                tracing::warn!("Daemonizing not yet implemented, running in foreground");
            }
            if prover && light {
                anyhow::bail!("Cannot enable both --prover and --light modes simultaneously");
            }
            let verbose_flags = VerboseFlags::from_args(&verbose);
            let debug_flags = DebugFlags::from_args(&debug);

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

            run_daemon(config, verbose_flags, debug_flags).await?;
        }
        Commands::Status => {
            show_status(&config).await?;
        }
    }

    Ok(())
}

fn init_config(path: &PathBuf, _config: &Config) -> anyhow::Result<()> {
    if path.exists() {
        println!("Config already exists at {}", path.display());
        println!("Delete it first if you want to regenerate: rm {}", path.display());
        return Ok(());
    }

    // Create directories first
    std::fs::create_dir_all(Config::sbo_dir())?;

    // Save a well-documented sample config
    Config::save_sample(path)?;
    println!("Created config at {}", path.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit {} to set your TurboDA API key", path.display());
    println!("  2. Start the daemon: sbo daemon start");
    println!();
    println!("Get a TurboDA API key at: https://turbo.availproject.org");

    Ok(())
}

/// Check DNS for all sbo:// repos and log warnings for mismatches
async fn check_dns_on_startup(repos: &RepoManager) {
    for repo in repos.list() {
        if !sbo_core::dns::is_dns_uri(&repo.display_uri) {
            continue;
        }

        match sbo_core::dns::resolve_uri(&repo.display_uri).await {
            Ok(current_resolved) => {
                let stored_resolved = repo.uri.to_string();
                if current_resolved == stored_resolved {
                    tracing::info!("DNS check: {} → {} ✓", repo.display_uri, stored_resolved);
                } else {
                    tracing::warn!(
                        "DNS mismatch: {} resolves to {} but repo is tracking {}. Run 'sbo repo relink {}' to update",
                        repo.display_uri,
                        current_resolved,
                        stored_resolved,
                        repo.path.display()
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "DNS check failed for {}: {} (continuing with cached resolution)",
                    repo.display_uri,
                    e
                );
            }
        }
    }
}

async fn run_daemon(config: Config, verbose: VerboseFlags, debug: DebugFlags) -> anyhow::Result<()> {
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

    // Check DNS for sbo:// repos
    {
        let state = state.read().await;
        check_dns_on_startup(&state.repos).await;
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

    // Start HTTP server for web auth
    let state_for_http = Arc::clone(&state);
    let http_handle = tokio::spawn(async move {
        if let Err(e) = http::run_server(state_for_http, 7890).await {
            tracing::error!("HTTP server error: {}", e);
        }
    });

    // Start sync engine
    let state_for_sync = Arc::clone(&state);
    let verbose_for_sync = verbose.clone();
    let debug_for_sync = debug.clone();
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
                RpcClient::new(rpc_config, verbose_for_sync.rpc, verbose_for_sync.rpc_decode, debug_for_sync.save_raw_block),
                verbose_for_sync.raw_incoming,
                verbose_for_sync.rpc_decode,
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
    http_handle.abort();
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

        Request::Submit { repo_path, sbo_path: _, id: _, data } => {
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

        Request::SubmitIdentity { uri, name, data, wait: _ } => {
            // Get state for repo lookup
            let state_read = state.read().await;

            // Find repo matching the URI (check both display_uri and resolved uri)
            // Normalize by trimming trailing slashes for comparison
            let uri_normalized = uri.trim_end_matches('/');
            let repo = state_read.repos.list().find(|r| {
                let repo_uri = r.uri.to_string();
                let repo_uri_normalized = repo_uri.trim_end_matches('/');
                let display_uri_normalized = r.display_uri.trim_end_matches('/');
                uri_normalized.starts_with(repo_uri_normalized)
                    || repo_uri_normalized.starts_with(uri_normalized)
                    || uri_normalized.starts_with(display_uri_normalized)
                    || display_uri_normalized.starts_with(uri_normalized)
            });

            let identity_uri = match repo {
                Some(r) => format!("{}/sys/names/{}", r.uri.to_string().trim_end_matches('/'), name),
                None => return Response::error(format!("No repo configured for URI: {}. Add with: sbo repo add {} <path>", uri, uri)),
            };

            // Submit via TurboDA
            match state_read.turbo.submit_raw(&data).await {
                Ok(result) => {
                    // Return submitted status - verification happens asynchronously via sync thread
                    // User can check status with 'sbo id show'
                    Response::ok(serde_json::json!({
                        "status": "submitted",
                        "uri": identity_uri,
                        "submission_id": result.submission_id,
                        "message": "Identity submitted to chain. Check verification with 'sbo id show'",
                    }))
                }
                Err(e) => Response::error(format!("Submission failed: {}", e)),
            }
        }

        Request::ListIdentities { uri } => {
            let state_read = state.read().await;
            let mut identities = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by URI if provided (check both display_uri and resolved uri)
                if let Some(ref filter_uri) = uri {
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(filter_uri) && !repo.display_uri.starts_with(filter_uri) {
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
                                        // Parse identity payload - try multiple formats
                                        let identity_data = if let Ok(identity) = sbo_core::schema::parse_identity(payload) {
                                            // JSON identity schema
                                            Some((identity.public_key, identity.display_name))
                                        } else if let Ok(token_str) = std::str::from_utf8(payload) {
                                            // Try JWT format (Content-Type: application/jwt)
                                            sbo_core::jwt::decode_identity_claims(token_str).ok().map(|claims| {
                                                (claims.public_key, None)
                                            })
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
                                                "uri": format!("{}/sys/names/{}", repo.display_uri.trim_end_matches('/'), name),
                                                "chain": &repo.display_uri,
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
                // Filter by chain if provided (check both display_uri and resolved uri)
                if let Some(ref chain) = chain_uri {
                    let chain_trimmed = chain.trim_end_matches('/');
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(chain_trimmed) && !repo.display_uri.starts_with(chain_trimmed) {
                        continue;
                    }
                }

                // Try to read the identity file
                let identity_path = repo.path.join("sys").join("names").join(&name);
                if identity_path.exists() {
                    if let Ok(content) = std::fs::read(&identity_path) {
                        if let Ok(msg) = sbo_core::wire::parse(&content) {
                            if let Some(payload) = &msg.payload {
                                // Parse identity payload - try multiple formats
                                let identity_data = if let Ok(identity) = sbo_core::schema::parse_identity(payload) {
                                    // JSON identity schema
                                    Some((identity.public_key, identity.display_name, identity.description, identity.avatar, identity.links, identity.binding))
                                } else if let Ok(token_str) = std::str::from_utf8(payload) {
                                    // Try JWT format (Content-Type: application/jwt)
                                    sbo_core::jwt::decode_identity_claims(token_str).ok().map(|claims| {
                                        (claims.public_key, None, None, None, None, None)
                                    })
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
                                        "uri": format!("{}/sys/names/{}", repo.display_uri.trim_end_matches('/'), name),
                                        "chain": &repo.display_uri,
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

        Request::SubmitDomain { uri, domain_name, data } => {
            // Get state for repo lookup
            let state_read = state.read().await;

            // Find repo matching the URI
            let repo = state_read.repos.list().find(|r| {
                uri.starts_with(&r.uri.to_string()) || uri.starts_with(&r.display_uri)
            });

            let domain_uri = match repo {
                Some(r) => format!("{}/sys/domains/{}", r.uri.to_string().trim_end_matches('/'), domain_name),
                None => return Response::error(format!("No repo configured for URI: {}. Add with: sbo repo add {} <path>", uri, uri)),
            };

            // Submit via TurboDA
            match state_read.turbo.submit_raw(&data).await {
                Ok(result) => {
                    Response::ok(serde_json::json!({
                        "status": "submitted",
                        "uri": domain_uri,
                        "submission_id": result.submission_id,
                    }))
                }
                Err(e) => Response::error(format!("Submission failed: {}", e)),
            }
        }

        Request::ListDomains { uri } => {
            let state_read = state.read().await;
            let mut domains = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by URI if provided
                if let Some(ref filter_uri) = uri {
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(filter_uri) && !repo.display_uri.starts_with(filter_uri) {
                        continue;
                    }
                }

                // Scan /sys/domains/ directory
                let domains_path = repo.path.join("sys").join("domains");
                if domains_path.exists() {
                    if let Ok(entries) = std::fs::read_dir(&domains_path) {
                        for entry in entries.flatten() {
                            let domain_name = entry.file_name().to_string_lossy().to_string();
                            let entry_path = entry.path();

                            // Try to read domain content
                            let content = if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                                std::fs::read(&entry_path).ok()
                            } else if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
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
                                        // Parse domain JWT to get public key
                                        if let Ok(token_str) = std::str::from_utf8(payload) {
                                            if let Ok(claims) = sbo_core::jwt::decode_identity_claims(token_str) {
                                                domains.push(serde_json::json!({
                                                    "uri": format!("{}/sys/domains/{}", repo.display_uri.trim_end_matches('/'), domain_name),
                                                    "chain": &repo.display_uri,
                                                    "domain": domain_name,
                                                    "public_key": claims.public_key,
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
            }

            Response::ok(serde_json::json!({ "domains": domains }))
        }

        Request::GetDomain { domain } => {
            let state_read = state.read().await;

            // Parse domain reference - either full URI or just domain name
            let (chain_uri, domain_name) = if domain.starts_with("sbo+raw://") || domain.starts_with("sbo://") {
                // Full URI - extract chain and domain
                if let Some(domains_pos) = domain.find("/sys/domains/") {
                    let chain = &domain[..domains_pos + 1];
                    let name = &domain[domains_pos + 13..]; // Skip "/sys/domains/"
                    (Some(chain.to_string()), name.to_string())
                } else {
                    return Response::error("Invalid domain URI: must contain /sys/domains/");
                }
            } else {
                // Just a domain name - search all repos
                (None, domain)
            };

            let mut found_domains = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by chain if provided
                if let Some(ref chain) = chain_uri {
                    let chain_trimmed = chain.trim_end_matches('/');
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(chain_trimmed) && !repo.display_uri.starts_with(chain_trimmed) {
                        continue;
                    }
                }

                // Try to read the domain file
                let domain_path = repo.path.join("sys").join("domains").join(&domain_name);
                if domain_path.exists() {
                    if let Ok(content) = std::fs::read(&domain_path) {
                        if let Ok(msg) = sbo_core::wire::parse(&content) {
                            if let Some(payload) = &msg.payload {
                                // Parse domain JWT
                                if let Ok(token_str) = std::str::from_utf8(payload) {
                                    if let Ok(claims) = sbo_core::jwt::decode_identity_claims(token_str) {
                                        found_domains.push(serde_json::json!({
                                            "uri": format!("{}/sys/domains/{}", repo.display_uri.trim_end_matches('/'), domain_name),
                                            "chain": &repo.display_uri,
                                            "domain": domain_name,
                                            "public_key": claims.public_key,
                                            "status": "verified",
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if found_domains.is_empty() {
                Response::error(format!("Domain '{}' not found", domain_name))
            } else if found_domains.len() == 1 {
                Response::ok(found_domains.into_iter().next().unwrap())
            } else {
                Response::ok(serde_json::json!({ "domains": found_domains }))
            }
        }

        Request::RepoCreate { display_uri, resolved_uri, path, genesis_data } => {
            // Parse and validate the resolved URI (always sbo+raw://)
            let parsed_uri = match SboUri::parse(&resolved_uri) {
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
                return Response::error(format!("Repo already exists for URI: {}", resolved_uri));
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
                        display_uri, result.submission_id
                    );

                    // Drop read lock before taking write lock
                    drop(state_read);

                    // Add repo starting from current block
                    let mut state_write = state.write().await;
                    match state_write.repos.add(display_uri.clone(), parsed_uri.clone(), path.clone(), Some(current_block)) {
                        Ok(repo) => {
                            Response::ok(serde_json::json!({
                                "display_uri": repo.display_uri,
                                "resolved_uri": repo.uri.to_string(),
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

        // ====================================================================
        // Auth / Sign Request Flow
        // ====================================================================

        Request::SubmitSignRequest {
            request_id,
            app_name,
            app_origin,
            email,
            challenge,
            purpose,
        } => {
            let mut state_write = state.write().await;

            // Check for duplicate request_id
            if state_write.sign_requests.contains_key(&request_id) {
                return Response::error(format!("Request ID '{}' already exists", request_id));
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let request = IpcSignRequest {
                request_id: request_id.clone(),
                app_name,
                app_origin,
                email,
                challenge,
                purpose,
                status: SignRequestStatus::Pending,
                created_at: now,
                assertion_jwt: None,
                session_binding_jwt: None,
                rejection_reason: None,
            };

            state_write.sign_requests.insert(request_id.clone(), request);

            tracing::info!("New sign request queued: {}", request_id);

            Response::ok(serde_json::json!({
                "status": "pending",
                "request_id": request_id,
            }))
        }

        Request::ListSignRequests => {
            let state_read = state.read().await;

            let requests: Vec<_> = state_read
                .sign_requests
                .values()
                .filter(|r| r.status == SignRequestStatus::Pending)
                .map(|r| serde_json::json!({
                    "request_id": r.request_id,
                    "app_name": r.app_name,
                    "app_origin": r.app_origin,
                    "email": r.email,
                    "challenge": r.challenge,
                    "purpose": r.purpose,
                    "created_at": r.created_at,
                }))
                .collect();

            Response::ok(serde_json::json!({ "requests": requests }))
        }

        Request::GetSignRequest { request_id } => {
            let state_read = state.read().await;

            match state_read.sign_requests.get(&request_id) {
                Some(request) => Response::ok(serde_json::json!({
                    "request_id": request.request_id,
                    "app_name": request.app_name,
                    "app_origin": request.app_origin,
                    "email": request.email,
                    "challenge": request.challenge,
                    "purpose": request.purpose,
                    "status": format!("{:?}", request.status),
                    "created_at": request.created_at,
                })),
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        Request::ApproveSignRequest {
            request_id,
            assertion_jwt,
            session_binding_jwt,
        } => {
            let mut state_write = state.write().await;

            match state_write.sign_requests.get_mut(&request_id) {
                Some(request) => {
                    if request.status != SignRequestStatus::Pending {
                        return Response::error(format!(
                            "Request '{}' is not pending (status: {:?})",
                            request_id, request.status
                        ));
                    }

                    request.status = SignRequestStatus::Approved;
                    request.assertion_jwt = Some(assertion_jwt);
                    request.session_binding_jwt = Some(session_binding_jwt);

                    tracing::info!("Sign request approved: {}", request_id);

                    Response::ok(serde_json::json!({
                        "status": "approved",
                        "request_id": request_id,
                    }))
                }
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        Request::RejectSignRequest { request_id, reason } => {
            let mut state_write = state.write().await;

            match state_write.sign_requests.get_mut(&request_id) {
                Some(request) => {
                    if request.status != SignRequestStatus::Pending {
                        return Response::error(format!(
                            "Request '{}' is not pending (status: {:?})",
                            request_id, request.status
                        ));
                    }

                    request.status = SignRequestStatus::Rejected;
                    request.rejection_reason = reason;

                    tracing::info!("Sign request rejected: {}", request_id);

                    Response::ok(serde_json::json!({
                        "status": "rejected",
                        "request_id": request_id,
                    }))
                }
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        Request::GetSignRequestResult { request_id } => {
            let state_read = state.read().await;

            match state_read.sign_requests.get(&request_id) {
                Some(request) => {
                    let status = format!("{:?}", request.status).to_lowercase();

                    // Return SignRequestResult format
                    let result = serde_json::json!({
                        "status": status,
                        "assertion_jwt": request.assertion_jwt,
                        "session_binding_jwt": request.session_binding_jwt,
                        "rejection_reason": request.rejection_reason,
                    });

                    Response::ok(result)
                }
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        // Session binding requests
        Request::RequestSessionBinding {
            email,
            ephemeral_public_key,
            user_delegation_jwt,
        } => {
            // Extract domain from email
            let domain = match dns::parse_email(&email) {
                Some((_, d)) => d.to_string(),
                None => return Response::error(format!("Invalid email address: {}", email)),
            };

            // Resolve discovery host from DNS
            let dns_record = match dns::resolve(&domain).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed to resolve DNS for {}: {}", domain, e);
                    // Fall back to domain itself as discovery host
                    dns::SboRecord {
                        repository_uri: String::new(),
                        discovery_host: None,
                    }
                }
            };

            let discovery_host = dns::get_discovery_host(&dns_record, &domain);

            // Fetch discovery document
            let discovery = match dns::fetch_discovery(&discovery_host, &domain).await {
                Ok(d) => d,
                Err(e) => return Response::error(format!("Failed to fetch discovery document: {}", e)),
            };

            // Get session endpoint
            let session_endpoint = match &discovery.session {
                Some(p) => p,
                None => return Response::error("Domain does not support session binding"),
            };

            // POST to session endpoint
            let session_url = format!("https://{}{}?domain={}", discovery_host, session_endpoint, domain);

            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "email": email,
                "ephemeral_public_key": ephemeral_public_key,
                "user_delegation": user_delegation_jwt,
            });

            let response = match client.post(&session_url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Failed to contact session endpoint: {}", e)),
            };

            if !response.status().is_success() {
                return Response::error(format!(
                    "Session endpoint returned {}: {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                ));
            }

            #[derive(serde::Deserialize)]
            struct SessionResponse {
                request_id: String,
                verification_uri: String,
                expires_in: u64,
            }

            let session_response: SessionResponse = match response.json().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Invalid session response: {}", e)),
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Store the request for polling
            let session_request = SessionBindingRequest {
                request_id: session_response.request_id.clone(),
                email,
                domain,
                discovery,
                created_at: now,
                expires_at: now + session_response.expires_in,
            };

            {
                let mut state_write = state.write().await;
                state_write.session_binding_requests.insert(
                    session_response.request_id.clone(),
                    session_request,
                );
            }

            tracing::info!(
                "Session binding request initiated: {}",
                session_response.request_id
            );

            Response::ok(serde_json::json!({
                "request_id": session_response.request_id,
                "verification_uri": session_response.verification_uri,
                "expires_in": session_response.expires_in,
            }))
        }

        Request::PollSessionBinding { request_id } => {
            // Find the stored request
            let session_request = {
                let state_read = state.read().await;
                match state_read.session_binding_requests.get(&request_id) {
                    Some(r) => r.clone(),
                    None => return Response::error(format!(
                        "Session binding request '{}' not found",
                        request_id
                    )),
                }
            };

            // Check if expired
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now > session_request.expires_at {
                // Clean up expired request
                let mut state_write = state.write().await;
                state_write.session_binding_requests.remove(&request_id);

                return Response::ok(serde_json::json!({
                    "status": "expired",
                    "session_binding": null,
                }));
            }

            // Get poll endpoint from discovery (or fall back to session + /poll)
            let poll_path = match &session_request.discovery.session_poll {
                Some(p) => p.clone(),
                None => {
                    // Fallback: append /poll to session endpoint
                    match &session_request.discovery.session {
                        Some(p) => format!("{}/poll", p),
                        None => return Response::error("Session has no poll endpoint"),
                    }
                }
            };

            // Determine discovery host
            let dns_record = dns::SboRecord {
                repository_uri: String::new(),
                discovery_host: session_request.discovery.authority.clone(),
            };
            let discovery_host = dns::get_discovery_host(&dns_record, &session_request.domain);

            // POST to poll endpoint
            let poll_url = format!(
                "https://{}{}?domain={}",
                discovery_host, poll_path, session_request.domain
            );

            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "request_id": request_id,
            });

            let response = match client.post(&poll_url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Failed to poll session endpoint: {}", e)),
            };

            if !response.status().is_success() {
                return Response::error(format!(
                    "Poll endpoint returned {}: {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                ));
            }

            #[derive(serde::Deserialize)]
            struct PollResponse {
                status: String,
                session_binding: Option<String>,
            }

            let poll_response: PollResponse = match response.json().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Invalid poll response: {}", e)),
            };

            // If complete, clean up the stored request
            if poll_response.status == "complete" {
                let mut state_write = state.write().await;
                state_write.session_binding_requests.remove(&request_id);
                tracing::info!("Session binding completed: {}", request_id);
            }

            Response::ok(serde_json::json!({
                "status": poll_response.status,
                "session_binding": poll_response.session_binding,
            }))
        }

        // Identity provisioning requests
        Request::RequestIdentityProvisioning { email, public_key } => {
            // Extract domain from email
            let domain = match dns::parse_email(&email) {
                Some((_, d)) => d.to_string(),
                None => return Response::error(format!("Invalid email address: {}", email)),
            };

            // Resolve discovery host from DNS
            let dns_record = match dns::resolve(&domain).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed to resolve DNS for {}: {}", domain, e);
                    // Fall back to domain itself as discovery host
                    dns::SboRecord {
                        repository_uri: String::new(),
                        discovery_host: None,
                    }
                }
            };

            let discovery_host = dns::get_discovery_host(&dns_record, &domain);

            // Fetch discovery document
            let discovery = match dns::fetch_discovery(&discovery_host, &domain).await {
                Ok(d) => d,
                Err(e) => return Response::error(format!("Failed to fetch discovery document: {}", e)),
            };

            // Get identity endpoint
            let identity_endpoint = match &discovery.identity {
                Some(p) => p,
                None => return Response::error("Domain does not support identity provisioning"),
            };

            // POST to identity endpoint
            let identity_url = format!("https://{}{}?domain={}", discovery_host, identity_endpoint, domain);

            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "email": email,
                "public_key": public_key,
            });

            let response = match client.post(&identity_url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Failed to contact identity endpoint: {}", e)),
            };

            if !response.status().is_success() {
                return Response::error(format!(
                    "Identity endpoint returned {}: {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                ));
            }

            #[derive(serde::Deserialize)]
            struct IdentityResponse {
                status: String,
                #[serde(default)]
                request_id: Option<String>,
                #[serde(default)]
                verification_uri: Option<String>,
                #[serde(default)]
                expires_in: Option<u64>,
                #[serde(default)]
                identity_jwt: Option<String>,
            }

            let identity_response: IdentityResponse = match response.json().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Invalid identity response: {}", e)),
            };

            // If complete immediately (user already authenticated), return the JWT
            if identity_response.status == "complete" {
                tracing::info!("Identity provisioning completed immediately for {}", email);
                return Response::ok(serde_json::json!({
                    "status": "complete",
                    "request_id": null,
                    "verification_uri": null,
                    "expires_in": null,
                    "identity_jwt": identity_response.identity_jwt,
                }));
            }

            // Otherwise, store request for polling
            let request_id = match &identity_response.request_id {
                Some(id) => id.clone(),
                None => return Response::error("Identity endpoint returned pending but no request_id"),
            };

            let expires_in = identity_response.expires_in.unwrap_or(300);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let identity_request = IdentityProvisioningRequest {
                request_id: request_id.clone(),
                email,
                public_key,
                domain,
                discovery,
                created_at: now,
                expires_at: now + expires_in,
            };

            {
                let mut state_write = state.write().await;
                state_write.identity_provisioning_requests.insert(
                    request_id.clone(),
                    identity_request,
                );
            }

            tracing::info!(
                "Identity provisioning request initiated: {}",
                request_id
            );

            Response::ok(serde_json::json!({
                "status": "pending",
                "request_id": request_id,
                "verification_uri": identity_response.verification_uri,
                "expires_in": expires_in,
                "identity_jwt": null,
            }))
        }

        Request::PollIdentityProvisioning { request_id } => {
            // Find the stored request
            let identity_request = {
                let state_read = state.read().await;
                match state_read.identity_provisioning_requests.get(&request_id) {
                    Some(r) => r.clone(),
                    None => return Response::error(format!(
                        "Identity provisioning request '{}' not found",
                        request_id
                    )),
                }
            };

            // Check if expired
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now > identity_request.expires_at {
                // Clean up expired request
                let mut state_write = state.write().await;
                state_write.identity_provisioning_requests.remove(&request_id);

                return Response::ok(serde_json::json!({
                    "status": "expired",
                    "identity_jwt": null,
                }));
            }

            // Get poll endpoint from discovery (or fall back to identity + /poll)
            let poll_path = match &identity_request.discovery.identity_poll {
                Some(p) => p.clone(),
                None => {
                    // Fallback: append /poll to identity endpoint
                    match &identity_request.discovery.identity {
                        Some(p) => format!("{}/poll", p),
                        None => return Response::error("Identity has no poll endpoint"),
                    }
                }
            };

            // Determine discovery host
            let dns_record = dns::SboRecord {
                repository_uri: String::new(),
                discovery_host: identity_request.discovery.authority.clone(),
            };
            let discovery_host = dns::get_discovery_host(&dns_record, &identity_request.domain);

            // POST to poll endpoint
            let poll_url = format!(
                "https://{}{}?domain={}",
                discovery_host, poll_path, identity_request.domain
            );

            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "request_id": request_id,
            });

            let response = match client.post(&poll_url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Failed to poll identity endpoint: {}", e)),
            };

            if !response.status().is_success() {
                return Response::error(format!(
                    "Poll endpoint returned {}: {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                ));
            }

            #[derive(serde::Deserialize)]
            struct PollResponse {
                status: String,
                identity_jwt: Option<String>,
            }

            let poll_response: PollResponse = match response.json().await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("Invalid poll response: {}", e)),
            };

            // If complete, clean up the stored request
            if poll_response.status == "complete" {
                let mut state_write = state.write().await;
                state_write.identity_provisioning_requests.remove(&request_id);
                tracing::info!("Identity provisioning completed: {}", request_id);
            }

            Response::ok(serde_json::json!({
                "status": poll_response.status,
                "identity_jwt": poll_response.identity_jwt,
            }))
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
