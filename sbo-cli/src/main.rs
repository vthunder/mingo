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
    /// Initialize a new SBO database
    Init {
        /// Avail app ID
        #[arg(long)]
        app_id: u32,
    },

    /// Sync blocks from the DA layer
    Sync {
        /// Keep following new blocks
        #[arg(long)]
        follow: bool,
    },

    /// Claim an identity name
    Claim {
        /// Name to claim
        name: String,
    },

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

    /// Show database status
    Status,

    /// DA layer test commands
    #[command(subcommand)]
    Da(DaCommands),

    /// Repository management
    #[command(subcommand)]
    Repo(RepoCommands),

    /// Daemon management
    #[command(subcommand)]
    Daemon(DaemonCommands),
}

#[derive(Subcommand)]
enum RepoCommands {
    /// Add a repository to follow
    Add {
        /// SBO URI (e.g., sbo://Avail:13/)
        uri: String,
        /// Local path to sync to
        path: PathBuf,
        /// Start syncing from this block number. Use negative for relative to chain head (e.g., -100)
        #[arg(long, allow_hyphen_values = true)]
        from_block: Option<i64>,
    },
    /// Remove a repository
    Remove {
        /// Local path of the repo
        path: PathBuf,
    },
    /// List followed repositories
    List,
    /// Force sync a repository
    Sync {
        /// Local path (or all if not specified)
        path: Option<PathBuf>,
    },
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
        Commands::Init { app_id } => {
            println!("Initializing SBO database with app_id: {}", app_id);
            todo!("Implement init")
        }
        Commands::Sync { follow } => {
            println!("Syncing blocks (follow: {})", follow);
            todo!("Implement sync")
        }
        Commands::Claim { name } => {
            println!("Claiming identity: {}", name);
            todo!("Implement claim")
        }
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
        Commands::Status => {
            println!("Database status");
            todo!("Implement status")
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
                RepoCommands::Remove { path } => {
                    let path = canonicalize_path(&path)?;
                    match client.request(Request::RepoRemove { path }).await {
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
                RepoCommands::Sync { path } => {
                    let path = path.map(|p| canonicalize_path(&p)).transpose()?;
                    match client.request(Request::RepoSync { path }).await {
                        Ok(Response::Ok { data }) => {
                            println!("Sync requested: {:?}", data);
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
