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
    /// Object operations using SBO URIs
    ///
    /// Work with objects using fully-qualified SBO URIs like:
    ///   sbo+raw://avail:turing:506/alice/nfts/token1
    #[command(subcommand)]
    Uri(UriCommands),

    /// Repository management
    #[command(subcommand)]
    Repo(RepoCommands),

    /// Daemon management
    #[command(subcommand)]
    Daemon(DaemonCommands),

    /// Proof operations
    #[command(subcommand)]
    Proof(ProofCommands),

    /// Local keyring management (signing keys)
    #[command(subcommand)]
    Key(KeyCommands),

    /// On-chain identity management (identity.v1 objects)
    #[command(subcommand)]
    Id(IdCommands),

    /// Debugging and low-level tools
    #[command(subcommand)]
    Debug(DebugCommands),
}

#[derive(Subcommand)]
enum UriCommands {
    /// Get an object by SBO URI
    ///
    /// Examples:
    ///   sbo uri get sbo+raw://avail:turing:506/alice/nfts/token1
    ///   sbo uri get sbo+raw://avail:turing:506/sys/names/alice
    Get {
        /// SBO URI (e.g., sbo+raw://avail:turing:506/path/to/object)
        uri: String,
    },

    /// Post an object to an SBO URI
    ///
    /// Examples:
    ///   sbo uri post sbo+raw://avail:turing:506/alice/nfts/token1 ./data.json
    ///   sbo uri post sbo+raw://avail:turing:506/alice/images/photo image.png --content-type image/png
    Post {
        /// SBO URI (e.g., sbo+raw://avail:turing:506/path/to/object)
        uri: String,
        /// File containing payload
        file: PathBuf,
        /// Content type (auto-detected if not specified)
        #[arg(long)]
        content_type: Option<String>,
    },

    /// List objects at an SBO URI path
    ///
    /// Examples:
    ///   sbo uri list sbo+raw://avail:turing:506/alice/nfts/
    ///   sbo uri list sbo+raw://avail:turing:506/sys/names/
    List {
        /// SBO URI path (e.g., sbo+raw://avail:turing:506/path/)
        uri: String,
    },

    /// Transfer an object to a new location or owner
    ///
    /// Examples:
    ///   sbo uri transfer sbo+raw://avail:turing:506/alice/nfts/token1 --new-path /bob/nfts/
    ///   sbo uri transfer sbo+raw://avail:turing:506/alice/nfts/token1 --new-owner <pubkey>
    Transfer {
        /// SBO URI of the object to transfer
        uri: String,
        /// New owner public key
        #[arg(long)]
        new_owner: Option<String>,
        /// New path (within same chain/app)
        #[arg(long)]
        new_path: Option<String>,
        /// New object ID
        #[arg(long)]
        new_id: Option<String>,
    },
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
enum KeyCommands {
    /// Generate a new signing key and add to keyring
    ///
    /// Keys are stored in ~/.sbo/keys/
    Generate {
        /// Alias for the key (default: "default")
        #[arg(long)]
        name: Option<String>,
    },

    /// List keys in the local keyring
    ///
    /// Shows key aliases, public keys, and associated identities
    List,

    /// Import a key from file or hex string
    Import {
        /// Path to key file, or hex string of 32-byte secret key
        source: String,
        /// Alias for the imported key
        #[arg(long)]
        name: Option<String>,
    },

    /// Export a key (for backup)
    Export {
        /// Key alias to export (default: "default")
        name: Option<String>,
        /// Output file (default: stdout as hex)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Delete a key from the keyring
    Delete {
        /// Key alias to delete
        name: String,
    },

    /// Get or set the default signing key
    Default {
        /// Key alias to set as default (omit to show current default)
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum IdCommands {
    /// Create an identity on chain (identity.v1 schema)
    ///
    /// Creates a JSON payload with signing_key and optional profile fields,
    /// then posts it to /sys/names/<name>/ with Content-Schema: identity.v1
    ///
    /// Examples:
    ///   sbo id create sbo+raw://avail:turing:506/ alice
    ///   sbo id create sbo+raw://avail:turing:506/ alice --display-name "Alice Smith"
    Create {
        /// SBO URI of the chain/app (e.g., sbo+raw://avail:turing:506/)
        uri: String,

        /// Name to claim (will post to /sys/names/<name>/)
        name: String,

        /// Key alias to use for signing (default: "default")
        #[arg(long)]
        key: Option<String>,

        /// Display name (e.g., "Alice Smith")
        #[arg(long)]
        display_name: Option<String>,

        /// Description / bio
        #[arg(long)]
        description: Option<String>,

        /// Avatar path (SBO path or URL)
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

        /// Don't wait for on-chain verification (return immediately after submission)
        #[arg(long)]
        no_wait: bool,
    },

    /// List identities on chain
    ///
    /// Shows identities and which local keys they're associated with
    List {
        /// SBO URI to search (e.g., sbo+raw://avail:turing:506/)
        uri: Option<String>,
    },

    /// Show detailed identity information
    Show {
        /// SBO URI of identity (e.g., sbo+raw://avail:turing:506/sys/names/alice)
        /// or just the name if URI context is set
        name: String,
    },

    /// Update an existing identity
    Update {
        /// SBO URI of identity (e.g., sbo+raw://avail:turing:506/sys/names/alice)
        uri: String,

        /// Key alias to use for signing (must match identity's key)
        #[arg(long)]
        key: Option<String>,

        /// New display name
        #[arg(long)]
        display_name: Option<String>,

        /// New description / bio
        #[arg(long)]
        description: Option<String>,

        /// New avatar path
        #[arg(long)]
        avatar: Option<String>,

        /// New website link
        #[arg(long)]
        website: Option<String>,
    },

    /// Import an identity from a synced repo into your keyring
    ///
    /// Associates an on-chain identity with your local key.
    /// You must have the matching private key already in your keyring.
    ///
    /// Examples:
    ///   sbo id import sbo+raw://avail:turing:506/ alice
    ///   sbo id import ./my-repo alice --proof proof.sboq
    Import {
        /// SBO URI or local repo path (e.g., sbo+raw://avail:turing:506/ or ./my-repo)
        repo: String,

        /// Identity name to import
        name: String,

        /// SBOQ proof file (required in light mode, optional in full mode)
        #[arg(long)]
        proof: Option<PathBuf>,
    },

    /// Remove an identity from local keyring (does not affect on-chain state)
    ///
    /// This only forgets the association between a local key and an on-chain identity.
    /// The on-chain identity remains unchanged.
    ///
    /// Examples:
    ///   sbo id remove sbo+raw://avail:turing:506/ alice
    Remove {
        /// SBO chain URI (e.g., sbo+raw://avail:turing:506/)
        chain: String,

        /// Identity name to remove
        name: String,
    },
}

#[derive(Subcommand)]
enum RepoCommands {
    /// Create a new repository with genesis (sys identity + root policy)
    ///
    /// This submits a genesis payload to initialize a new SBO namespace on the chain.
    /// The URI path must be "/" (root).
    ///
    /// Examples:
    ///   sbo repo create sbo+raw://avail:turing:506/ ./my-repo
    ///   sbo repo create sbo+raw://avail:turing:506/ ./my-repo --key default
    Create {
        /// SBO URI with root path (e.g., sbo+raw://avail:turing:506/)
        uri: String,
        /// Local path to sync to
        path: PathBuf,
        /// Key alias to use for signing genesis (default: "default")
        #[arg(long)]
        key: Option<String>,
    },
    /// Add a repository to follow
    Add {
        /// SBO URI (e.g., sbo+raw://avail:turing:506/)
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
enum DebugCommands {
    /// DA layer commands (stream blocks, submit test data, scan)
    #[command(subcommand)]
    Da(DaCommands),
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
        Commands::Uri(uri_cmd) => {
            match uri_cmd {
                UriCommands::Get { uri } => {
                    println!("Getting object: {}", uri);
                    todo!("Implement uri get")
                }
                UriCommands::Post { uri, file, content_type } => {
                    println!("Posting to {}: {:?}", uri, file);
                    let _ = content_type; // TODO: use content_type
                    todo!("Implement uri post")
                }
                UriCommands::List { uri } => {
                    println!("Listing: {}", uri);
                    todo!("Implement uri list")
                }
                UriCommands::Transfer { uri, new_owner, new_path, new_id } => {
                    println!("Transferring: {}", uri);
                    let _ = (new_owner, new_path, new_id); // TODO: use these
                    todo!("Implement uri transfer")
                }
            }
        }
        Commands::Debug(debug_cmd) => {
            match debug_cmd {
                DebugCommands::Da(da_cmd) => {
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
            }
        }
        Commands::Repo(repo_cmd) => {
            let config = Config::load(&Config::config_path()).unwrap_or_default();
            let client = IpcClient::new(config.daemon.socket_path);

            match repo_cmd {
                RepoCommands::Create { uri, path, key } => {
                    use sbo_core::keyring::Keyring;

                    // Open keyring and get signing key
                    let keyring = match Keyring::open() {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("Failed to open keyring: {}", e);
                            eprintln!("Generate a key first with: sbo key generate");
                            std::process::exit(1);
                        }
                    };

                    let alias = match keyring.resolve_alias(key.as_deref()) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    };

                    let signing_key = match keyring.get_signing_key(&alias) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("Failed to get signing key: {}", e);
                            std::process::exit(1);
                        }
                    };

                    // Generate genesis payload
                    let genesis_data = sbo_core::presets::genesis(&signing_key);

                    let path = canonicalize_path(&path)?;

                    println!("Creating new repository at {}", uri);
                    println!("  Key: {} ({})", alias, signing_key.public_key().to_string());
                    println!("  Path: {}", path.display());

                    match client.request(Request::RepoCreate {
                        uri: uri.clone(),
                        path: path.clone(),
                        genesis_data,
                    }).await {
                        Ok(Response::Ok { data }) => {
                            let chain_uri = data["uri"].as_str().unwrap_or(&uri);
                            let sys_identity_uri = format!("{}/sys/names/sys", chain_uri.trim_end_matches('/'));

                            // Add sys identity to keyring
                            let mut keyring = Keyring::open().expect("keyring was just opened");
                            if let Err(e) = keyring.add_identity(&alias, &sys_identity_uri) {
                                eprintln!("Warning: failed to add sys identity to keyring: {}", e);
                            }

                            println!("\n✓ Repository created");
                            println!("  URI:           {}", chain_uri);
                            println!("  Path:          {}", path.display());
                            println!("  From Block:    {}", data["from_block"].as_u64().unwrap_or(0));
                            println!("  Submission ID: {}", data["submission_id"].as_str().unwrap_or("?"));
                            println!("  Sys Identity:  {} → {}", sys_identity_uri, alias);
                            println!("\nThe daemon will sync this repo automatically.");
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                            eprintln!("Is the daemon running? Try: sbo daemon start");
                            std::process::exit(1);
                        }
                    }
                }
                RepoCommands::Add { uri, path, from_block } => {
                    let path = canonicalize_path(&path)?;

                    // Resolve sbo:// URIs via DNS
                    let (display_uri, resolved_uri) = if sbo_core::dns::is_dns_uri(&uri) {
                        print!("Resolving {}...", uri);
                        std::io::Write::flush(&mut std::io::stdout())?;

                        match sbo_core::dns::resolve_uri(&uri).await {
                            Ok(resolved) => {
                                println!(" -> {}", resolved);
                                (uri.clone(), resolved)
                            }
                            Err(e) => {
                                println!();
                                eprintln!("Error: Failed to resolve DNS for {}: {}", uri, e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        (uri.clone(), uri.clone())
                    };

                    match client.request(Request::RepoAdd {
                        display_uri: display_uri.clone(),
                        resolved_uri,
                        path: path.clone(),
                        from_block,
                    }).await {
                        Ok(Response::Ok { data }) => {
                            println!("Added repository:");
                            println!("  URI:  {}", data["display_uri"].as_str().unwrap_or("?"));
                            if data["display_uri"] != data["resolved_uri"] {
                                println!("  Chain: {}", data["resolved_uri"].as_str().unwrap_or("?"));
                            }
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
                    let request = if target.starts_with("sbo+raw://") || target.starts_with("sbo://") {
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
        Commands::Key(key_cmd) => {
            use sbo_core::keyring::Keyring;

            let mut keyring = match Keyring::open() {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Failed to open keyring: {}", e);
                    std::process::exit(1);
                }
            };

            match key_cmd {
                KeyCommands::Generate { name } => {
                    let alias = name.as_deref().unwrap_or("default");
                    match keyring.generate(alias) {
                        Ok(pubkey) => {
                            println!("Generated key '{}'", alias);
                            println!("  Public key: {}", pubkey.to_string());
                            if keyring.default_key() == Some(alias) {
                                println!("  (set as default)");
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to generate key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                KeyCommands::List => {
                    let keys = keyring.list();
                    if keys.is_empty() {
                        println!("No keys in keyring. Generate one with: sbo key generate");
                    } else {
                        let default = keyring.default_key();
                        for (alias, entry) in keys {
                            let marker = if Some(alias.as_str()) == default { "*" } else { " " };
                            println!("{} {} ({})", marker, alias, entry.algorithm);
                            println!("    {}", entry.public_key);
                            println!("    Created: {}", entry.created_at);
                            if !entry.identities.is_empty() {
                                println!("    Identities: {}", entry.identities.join(", "));
                            }
                        }
                        println!();
                        println!("* = default key");
                    }
                }
                KeyCommands::Import { source, name } => {
                    let alias = name.as_deref().unwrap_or("default");

                    // Determine if source is a file path or hex string
                    let result = if std::path::Path::new(&source).exists() {
                        keyring.import_file(alias, std::path::Path::new(&source))
                    } else {
                        keyring.import_hex(alias, &source)
                    };

                    match result {
                        Ok(pubkey) => {
                            println!("Imported key '{}'", alias);
                            println!("  Public key: {}", pubkey.to_string());
                        }
                        Err(e) => {
                            eprintln!("Failed to import key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                KeyCommands::Export { name, output } => {
                    let alias = keyring.resolve_alias(name.as_deref());
                    let alias = match alias {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    };

                    match keyring.export(&alias) {
                        Ok(key_hex) => {
                            if let Some(output_path) = output {
                                match std::fs::write(&output_path, &key_hex) {
                                    Ok(_) => {
                                        // Set restrictive permissions on the output file
                                        #[cfg(unix)]
                                        {
                                            use std::os::unix::fs::PermissionsExt;
                                            let _ = std::fs::set_permissions(
                                                &output_path,
                                                std::fs::Permissions::from_mode(0o600),
                                            );
                                        }
                                        println!("Exported key '{}' to {}", alias, output_path.display());
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to write file: {}", e);
                                        std::process::exit(1);
                                    }
                                }
                            } else {
                                // Print to stdout
                                println!("{}", key_hex);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to export key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                KeyCommands::Delete { name } => {
                    match keyring.delete(&name) {
                        Ok(_) => {
                            println!("Deleted key '{}'", name);
                        }
                        Err(e) => {
                            eprintln!("Failed to delete key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                KeyCommands::Default { name } => {
                    match name {
                        Some(alias) => {
                            match keyring.set_default(&alias) {
                                Ok(_) => println!("Set '{}' as the default key", alias),
                                Err(e) => {
                                    eprintln!("Error: {}", e);
                                    std::process::exit(1);
                                }
                            }
                        }
                        None => {
                            match keyring.default_key() {
                                Some(alias) => println!("Default key: {}", alias),
                                None => println!("No default key set"),
                            }
                        }
                    }
                }
            }
        }
        Commands::Id(id_cmd) => {
            match id_cmd {
                IdCommands::Create { uri, name, key, display_name, description, avatar, website, binding, dry_run, no_wait } => {
                    commands::identity::create(
                        &uri,
                        &name,
                        key.as_deref(),
                        display_name.as_deref(),
                        description.as_deref(),
                        avatar.as_deref(),
                        website.as_deref(),
                        binding.as_deref(),
                        dry_run,
                        no_wait,
                    ).await?;
                }
                IdCommands::List { uri } => {
                    commands::identity::list(uri.as_deref()).await?;
                }
                IdCommands::Show { name } => {
                    commands::identity::show(&name).await?;
                }
                IdCommands::Update { uri, key, display_name, description, avatar, website } => {
                    commands::identity::update(
                        &uri,
                        key.as_deref(),
                        display_name.as_deref(),
                        description.as_deref(),
                        avatar.as_deref(),
                        website.as_deref(),
                        false, // no_wait not supported in update command yet
                    ).await?;
                }
                IdCommands::Import { repo, name, proof } => {
                    commands::identity::import(
                        &repo,
                        &name,
                        proof.as_deref(),
                    ).await?;
                }
                IdCommands::Remove { chain, name } => {
                    commands::identity::remove(&chain, &name)?;
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
