//! SBO Command Line Interface

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
    },

    /// Check DA connection status
    Ping,
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
                DaCommands::Submit { preset, file, count } => {
                    commands::da::submit(preset, file, count).await?;
                }
                DaCommands::Ping => {
                    commands::da::ping().await?;
                }
            }
        }
    }

    Ok(())
}
