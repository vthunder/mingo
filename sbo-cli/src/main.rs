//! SBO Command Line Interface

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};

mod commands;

#[derive(Parser)]
#[command(name = "sbo", about = "SBO client", version)]
struct Cli {
    /// Data directory
    #[arg(long, default_value = "~/.sbo")]
    data_dir: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Post an object
    Post {
        /// Path (e.g., /alice/nfts/)
        #[arg(long)]
        path: String,
        /// Object ID
        #[arg(long)]
        id: String,
        /// File containing payload
        #[arg(long)]
        file: PathBuf,
        /// Content type
        #[arg(long)]
        content_type: Option<String>,
    },

    /// Transfer an object
    Transfer {
        /// Current path
        path: String,
        /// Current ID
        id: String,
        /// New owner
        #[arg(long)]
        new_owner: Option<String>,
        /// New path
        #[arg(long)]
        new_path: Option<String>,
        /// New ID
        #[arg(long)]
        new_id: Option<String>,
    },

    /// Query an object
    Get {
        /// Path
        path: String,
        /// Object ID
        id: String,
    },

    /// List objects at a path
    List {
        /// Path to list
        path: String,
    },

    /// DA layer test commands
    #[command(subcommand)]
    Da(DaCommands),

    /// Repository management
    #[command(subcommand)]
    Repo(RepoCommands),

    /// Daemon management
    #[command(subcommand)]
    Daemon(DaemonCommands),

    /// Proof operations
    #[command(subcommand)]
    Proof(ProofCommands),

    /// Identity operations
    #[command(subcommand)]
    Identity(IdentityCommands),
}

#[derive(Subcommand)]
enum ProofCommands {
    /// Generate a trie proof for an object (SBOQ format)
    ///
    /// Examples:
    ///   sbo proof generate ./my-repo/sys/names/alice
    ///   sbo proof generate /home/user/repos/nft-collection/tokens/123
    Generate {
        /// Full path to object: <repo-mount>/<sbo-path>/<object-id>
        /// e.g., ./my-repo/sys/names/alice
        object_path: String,
    },
    /// Verify a trie proof (SBOQ message)
    Verify {
        /// Path to SBOQ file, or - for stdin
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create an identity object (identity.v1 schema)
    ///
    /// Creates a JSON payload with signing_key and optional profile fields,
    /// then posts it with Content-Schema: identity.v1
    Create {
        /// Name to claim (will post to /sys/names/<claim>/)
        #[arg(long)]
        claim: Option<String>,

        /// Display name (e.g., "Alice Smith")
        #[arg(long)]
        name: Option<String>,

        /// Description / bio
        #[arg(long)]
        description: Option<String>,

        /// Avatar path (SBO path like /alice/avatar.png or URL)
        #[arg(long)]
        avatar: Option<String>,

        /// Website link
        #[arg(long)]
        website: Option<String>,

        /// Cross-chain identity binding (SBO URI)
        #[arg(long)]
        binding: Option<String>,

        /// Output the SBO message to stdout instead of submitting
        #[arg(long)]
        dry_run: bool,
    },
    /// Show identity information for a name
    Show {
        /// Name to look up (e.g., "alice")
        name: String,
    },
}

#[derive(Subcommand)]
enum RepoCommands {
    /// Add a repository to follow
    Add {
        /// SBO URI (e.g., sbo://avail:turing:13/)
        uri: String,
        /// Local path to sync to
        path: PathBuf,
        /// Start syncing from this block number. Use negative for relative to chain head (e.g., -100)
        #[arg(long, allow_hyphen_values = true)]
        from_block: Option<i64>,
    },
    /// Remove a repository
    Remove {
        /// Local path or SBO URI of the repo to remove
        target: String,
    },
    /// List followed repositories
    List,
}

#[derive(Subcommand)]
enum DaemonCommands {
    /// Start the daemon
    Start {
        /// Run in foreground
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
}

#[derive(Subcommand)]
enum DaCommands {
    /// Stream raw blocks from the DA layer
    Stream {
        /// Starting block height
        #[arg(long, default_value = "0")]
        from: u64,
        /// Stop after N blocks
        #[arg(long)]
        limit: Option<u64>,
        /// Print raw bytes (hex) instead of attempting SBO parse
        #[arg(long)]
        raw: bool,
    },

    /// Submit test payloads to DA
    Submit {
        /// Use a preset payload
        #[arg(long)]
        preset: Option<TestPreset>,
        /// Custom payload from file
        #[arg(long)]
        file: Option<PathBuf>,
        /// Submit multiple times
        #[arg(long)]
        count: Option<u32>,
        /// Use TurboDA for submission (requires API key in config)
        #[arg(long)]
        turbo: bool,
        /// Verbose output (comma-separated: raw-submissions,parsed)
        #[arg(long, value_delimiter = ',')]
        verbose: Vec<String>,
    },

    /// Check DA connection status
    Ping,

    /// Scan a specific block for data submissions
    Scan {
        /// Block number to scan
        block: u64,
        /// Show raw transaction data
        #[arg(long)]
        raw: bool,
        /// App ID to query (default: 506)
        #[arg(long, default_value = "506")]
        app_id: u32,
    },

    /// Check TurboDA submission status
    Status {
        /// Submission ID from TurboDA
        submission_id: String,
    },
}

#[derive(Clone, ValueEnum)]
enum TestPreset {
    /// Simple "hello world" bytes (not SBO)
    Hello,
    /// Valid genesis (sys identity + root policy)
    Genesis,
    /// Valid SBO post message
    Post,
    /// Valid SBO transfer message
    Transfer,
    /// Valid SBO collection creation
    Collection,
    /// Intentionally malformed SBO
    Invalid,
    /// Claim a name (should succeed after genesis)
    ClaimName,
    /// Post to own namespace (should succeed after claiming name)
    PostOwn,
    /// Post to another's namespace (should be DENIED by policy)
    PostUnauthorized,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    match cli.command {
        Commands::Post { path, id, file, content_type } => {
            println!("Posting object: {}:{}", path, id);
            todo!("Implement post")
        }
        Commands::Transfer { path, id, new_owner, new_path, new_id } => {
            println!("Transferring object: {}:{}", path, id);
            todo!("Implement transfer")
        }
        Commands::Get { path, id } => {
            println!("Getting object: {}:{}", path, id);
            todo!("Implement get")
        }
        Commands::List { path } => {
            println!("Listing objects at: {}", path);
            todo!("Implement list")
        }
        Commands::Da(da_cmd) => {
            match da_cmd {
                DaCommands::Stream { from, limit, raw } => {
                    commands::da::stream(from, limit, raw).await?;
                }
                DaCommands::Submit { preset, file, count, turbo, verbose } => {
                    commands::da::submit(preset, file, count, turbo, &verbose).await?;
                }
                DaCommands::Ping => {
                    commands::da::ping().await?;
                }
                DaCommands::Scan { block, raw, app_id } => {
                    commands::da::scan(block, raw, app_id).await?;
                }
                DaCommands::Status { submission_id } => {
                    commands::da::turbo_status(&submission_id).await?;
                }
            }
        }
        Commands::Repo(repo_cmd) => {
            let config = Config::load(&Config::config_path()).unwrap_or_default();
            let client = IpcClient::new(config.daemon.socket_path);

            match repo_cmd {
                RepoCommands::Add { uri, path, from_block } => {
                    let path = canonicalize_path(&path)?;
                    match client.request(Request::RepoAdd { uri, path: path.clone(), from_block }).await {
                        Ok(Response::Ok { data }) => {
                            println!("Added repository:");
                            println!("  URI:  {}", data["uri"].as_str().unwrap_or("?"));
                            println!("  Path: {}", path.display());
                            println!("  Head: {}", data["head"].as_u64().unwrap_or(0));
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                            eprintln!("Is the daemon running? Try: sbo daemon start");
                        }
                    }
                }
                RepoCommands::Remove { target } => {
                    // Detect if target is a URI or a path
                    let request = if target.starts_with("sbo://") {
                        Request::RepoRemoveByUri { uri: target }
                    } else {
                        let path = canonicalize_path(&PathBuf::from(&target))?;
                        Request::RepoRemove { path }
                    };

                    match client.request(request).await {
                        Ok(Response::Ok { data }) => {
                            println!("Removed: {}", data["removed"].as_str().unwrap_or("?"));
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                        }
                    }
                }
                RepoCommands::List => {
                    match client.request(Request::RepoList).await {
                        Ok(Response::Ok { data }) => {
                            if let Some(repos) = data.as_array() {
                                if repos.is_empty() {
                                    println!("No repositories. Add one with: sbo repo add <uri> <path>");
                                } else {
                                    println!("{:<40} {:<10} {}", "URI", "HEAD", "PATH");
                                    println!("{}", "-".repeat(70));
                                    for repo in repos {
                                        println!(
                                            "{:<40} {:<10} {}",
                                            repo["uri"].as_str().unwrap_or("?"),
                                            repo["head"].as_u64().unwrap_or(0),
                                            repo["path"].as_str().unwrap_or("?")
                                        );
                                    }
                                }
                            }
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                        }
                    }
                }
            }
        }
        Commands::Daemon(daemon_cmd) => {
            match daemon_cmd {
                DaemonCommands::Start { foreground } => {
                    // Delegate to sbo-daemon binary
                    let mut cmd = std::process::Command::new("sbo-daemon");
                    cmd.arg("start");
                    if foreground {
                        cmd.arg("--foreground");
                    }
                    let status = cmd.status()?;
                    if !status.success() {
                        std::process::exit(status.code().unwrap_or(1));
                    }
                }
                DaemonCommands::Stop => {
                    let config = Config::load(&Config::config_path()).unwrap_or_default();
                    let client = IpcClient::new(config.daemon.socket_path);
                    match client.request(Request::Shutdown).await {
                        Ok(_) => println!("Shutdown requested"),
                        Err(e) => eprintln!("Failed to connect to daemon: {}", e),
                    }
                }
                DaemonCommands::Status => {
                    let config = Config::load(&Config::config_path()).unwrap_or_default();
                    let client = IpcClient::new(config.daemon.socket_path);
                    match client.request(Request::Status).await {
                        Ok(Response::Ok { data }) => {
                            println!("SBO Daemon Status");
                            println!("=================");
                            if let Some(lc) = data.get("light_client") {
                                let connected = lc["connected"].as_bool().unwrap_or(false);
                                if connected {
                                    println!("Light Client: connected");
                                    println!("  Network: {}", lc["network"].as_str().unwrap_or("?"));
                                    println!("  Latest:  {}", lc["latest_block"].as_u64().unwrap_or(0));
                                } else {
                                    println!("Light Client: disconnected");
                                    if let Some(err) = lc["error"].as_str() {
                                        println!("  Error: {}", err);
                                    }
                                }
                            }
                            println!("Repos: {}", data["repos"].as_u64().unwrap_or(0));
                            if let Some(app_ids) = data["app_ids"].as_array() {
                                let ids: Vec<_> = app_ids.iter()
                                    .filter_map(|v| v.as_u64())
                                    .collect();
                                if !ids.is_empty() {
                                    println!("App IDs: {:?}", ids);
                                }
                            }
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Daemon not running: {}", e);
                        }
                    }
                }
            }
        }
        Commands::Proof(proof_cmd) => {
            let config = Config::load(&Config::config_path()).unwrap_or_default();
            let client = IpcClient::new(config.daemon.socket_path);

            match proof_cmd {
                ProofCommands::Generate { object_path } => {
                    // Parse the unified path like ./my-repo/sys/names/alice
                    // Find which repo contains this path and extract the SBO path + id
                    let (repo_path, sbo_path, id) = match parse_object_path(&object_path, &client).await {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            return Ok(());
                        }
                    };

                    match client.request(Request::ObjectProof {
                        repo_path,
                        path: sbo_path,
                        id,
                    }).await {
                        Ok(Response::Ok { data }) => {
                            // Print the SBOQ message
                            if let Some(sboq) = data["sboq"].as_str() {
                                println!("{}", sboq);
                            } else {
                                println!("{}", serde_json::to_string_pretty(&data)?);
                            }
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                        }
                    }
                }
                ProofCommands::Verify { file } => {
                    // Read the SBOQ file
                    let contents = if file.to_string_lossy() == "-" {
                        use std::io::Read;
                        let mut buf = Vec::new();
                        std::io::stdin().read_to_end(&mut buf)?;
                        buf
                    } else {
                        std::fs::read(&file)?
                    };

                    // Parse and verify the proof
                    match sbo_core::proof::parse_sboq(&contents) {
                        Ok(sboq) => {
                            // Verify the trie proof
                            let trie_valid = match sbo_crypto::verify_trie_proof(&sboq.trie_proof) {
                                Ok(true) => true,
                                Ok(false) | Err(_) => false,
                            };

                            // If embedded object is present, verify it matches the object_hash
                            let object_valid = if let Some(ref obj_bytes) = sboq.object {
                                // Compute object_hash = sha256(raw_sbo_bytes)
                                let computed_hash = sbo_crypto::hash::sha256(obj_bytes);

                                if let Some(expected_hash) = sboq.object_hash {
                                    if computed_hash == expected_hash {
                                        Some(true)
                                    } else {
                                        eprintln!("Object verification FAILED: hash mismatch");
                                        eprintln!("  Expected: {}", hex::encode(expected_hash));
                                        eprintln!("  Computed: {}", hex::encode(computed_hash));
                                        Some(false)
                                    }
                                } else {
                                    // Non-existence proof shouldn't have an object
                                    eprintln!("Object verification FAILED: object present but proof claims non-existence");
                                    Some(false)
                                }
                            } else {
                                None // No embedded object - trie proof only
                            };

                            // Try to verify block → state_root mapping against historical records
                            let block_verified = {
                                let data_dir = std::env::var("HOME").ok()
                                    .map(|h| std::path::PathBuf::from(h).join(".sbo").join("repos"));

                                if let Some(repos_dir) = data_dir {
                                    if repos_dir.exists() {
                                        let mut found_match = false;
                                        let mut checked_any = false;
                                        let mut block_in_future = false;

                                        if let Ok(entries) = std::fs::read_dir(&repos_dir) {
                                            for entry in entries.flatten() {
                                                let state_path = entry.path().join("state");
                                                if state_path.exists() {
                                                    if let Ok(state_db) = sbo_core::state::StateDb::open(&state_path) {
                                                        checked_any = true;

                                                        // First check: is the claimed block in the future?
                                                        if let Ok(Some(last_block)) = state_db.get_last_block() {
                                                            if sboq.block > last_block {
                                                                block_in_future = true;
                                                                continue; // Try other repos
                                                            }
                                                        }

                                                        // Get the state root at or before the claimed block
                                                        if let Ok(Some((_recorded_block, stored_root))) = state_db.get_state_root_at_or_before(sboq.block) {
                                                            if stored_root == sboq.state_root {
                                                                found_match = true;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if found_match {
                                            Some(true)
                                        } else if block_in_future && !found_match {
                                            Some(false)
                                        } else if checked_any {
                                            Some(false)
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            };

                            let is_existence_proof = sboq.object_hash.is_some();

                            if trie_valid && object_valid != Some(false) && block_verified != Some(false) {
                                println!("Proof VALID");
                                println!("  Type:       {}", if is_existence_proof { "inclusion" } else { "non-existence" });
                                println!("  Path:       {}", sboq.path);
                                println!("  ID:         {}", sboq.id);
                                println!("  Creator:    {}", sboq.creator);
                                println!("  Block:      {}", sboq.block);
                                println!("  State Root: {}", hex::encode(sboq.state_root));
                                if let Some(obj_hash) = sboq.object_hash {
                                    println!("  Object Hash: {}", hex::encode(obj_hash));
                                } else {
                                    println!("  Object Hash: null (non-existence)");
                                }
                                if sboq.object.is_some() {
                                    if object_valid == Some(true) {
                                        println!("  Object:     verified (hash matches)");
                                    } else {
                                        println!("  Object:     present (could not verify)");
                                    }
                                } else {
                                    println!("  Object:     not included");
                                }
                                match block_verified {
                                    Some(true) => println!("  Block:      verified (state root matches history)"),
                                    Some(false) => {} // Won't reach here due to condition above
                                    None => println!("  Block:      unverified (no local state history)"),
                                }
                            } else if !trie_valid {
                                eprintln!("Proof INVALID: trie verification failed");
                                std::process::exit(1);
                            } else if block_verified == Some(false) {
                                eprintln!("Proof INVALID: state root does not match history for block {}", sboq.block);
                                eprintln!("  Declared: {}", hex::encode(sboq.state_root));
                                std::process::exit(1);
                            } else {
                                eprintln!("Proof INVALID: object verification failed");
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse SBOQ: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Commands::Identity(identity_cmd) => {
            match identity_cmd {
                IdentityCommands::Create { claim, name, description, avatar, website, binding, dry_run } => {
                    commands::identity::create(claim, name, description, avatar, website, binding, dry_run).await?;
                }
                IdentityCommands::Show { name } => {
                    commands::identity::show(&name).await?;
                }
            }
        }
    }

    Ok(())
}

fn canonicalize_path(path: &PathBuf) -> anyhow::Result<PathBuf> {
    // If path exists, canonicalize it; otherwise, make it absolute
    if path.exists() {
        Ok(path.canonicalize()?)
    } else {
        let abs = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()?.join(path)
        };
        Ok(abs)
    }
}

/// Normalize a path by resolving . and .. without requiring the path to exist
fn normalize_path(path: &PathBuf) -> PathBuf {
    use std::path::Component;

    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {
                // Skip current directory markers
            }
            _ => {
                result.push(component);
            }
        }
    }
    result
}

/// Parse a unified object path like ./my-repo/sys/names/alice
/// Returns (repo_path, sbo_path, object_id)
async fn parse_object_path(
    object_path: &str,
    client: &IpcClient,
) -> anyhow::Result<(PathBuf, String, String)> {
    // Make the path absolute and clean (resolve . and ..)
    let full_path = if object_path.starts_with('/') {
        PathBuf::from(object_path)
    } else {
        std::env::current_dir()?.join(object_path)
    };

    // Normalize the path (resolve . and .. without requiring it to exist)
    let full_path = normalize_path(&full_path);

    // Query daemon for list of repos
    let repos = match client.request(Request::RepoList).await {
        Ok(Response::Ok { data }) => {
            data.as_array()
                .map(|arr| arr.iter()
                    .filter_map(|r| {
                        let path = r["path"].as_str()?.to_string();
                        Some(PathBuf::from(path))
                    })
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        }
        Ok(Response::Error { message }) => {
            return Err(anyhow::anyhow!("Failed to list repos: {}", message));
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to connect to daemon: {}", e));
        }
    };

    if repos.is_empty() {
        return Err(anyhow::anyhow!("No repos found. Add a repo first with: sbo repo add <uri> <path>"));
    }

    // Find which repo contains this path (longest prefix match)
    let full_path_str = full_path.to_string_lossy();
    let mut best_match: Option<(PathBuf, usize)> = None;

    for repo_path in &repos {
        let repo_str = repo_path.to_string_lossy();
        if full_path_str.starts_with(repo_str.as_ref()) {
            let len = repo_str.len();
            if best_match.is_none() || len > best_match.as_ref().unwrap().1 {
                best_match = Some((repo_path.clone(), len));
            }
        }
    }

    let repo_path = match best_match {
        Some((path, _)) => path,
        None => {
            return Err(anyhow::anyhow!(
                "Path '{}' is not inside any known repo. Known repos:\n{}",
                object_path,
                repos.iter().map(|p| format!("  {}", p.display())).collect::<Vec<_>>().join("\n")
            ));
        }
    };

    // Extract the SBO path portion (everything after repo_path)
    let repo_str = repo_path.to_string_lossy();
    let remainder = &full_path_str[repo_str.len()..];

    // Parse the remainder as /sbo/path/object_id
    // e.g., /sys/names/alice -> path=/sys/names/, id=alice
    let remainder = remainder.trim_start_matches('/');
    if remainder.is_empty() {
        return Err(anyhow::anyhow!("Missing SBO path and object ID after repo path"));
    }

    // Split into path components
    let parts: Vec<&str> = remainder.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(anyhow::anyhow!("Missing SBO path and object ID"));
    }
    if parts.len() < 2 {
        return Err(anyhow::anyhow!(
            "Need at least a path and object ID. Got: /{}",
            parts.join("/")
        ));
    }

    // Last component is the object ID
    let id = parts[parts.len() - 1].to_string();
    // Everything before is the path (with trailing slash)
    let sbo_path = format!("/{}/", parts[..parts.len() - 1].join("/"));

    Ok((repo_path, sbo_path, id))
}
