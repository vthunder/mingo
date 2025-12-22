//! SBO Daemon
//!
//! Manages local replicas of SBO repositories, verifying data availability
//! via a light client and syncing object data from Avail RPC nodes.

pub mod config;
pub mod repo;
pub mod lc;
pub mod rpc;
pub mod turbo;
pub mod sync;
pub mod ipc;
pub mod http;
pub mod validate;
pub mod prover;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Repository error: {0}")]
    Repo(String),

    #[error("Light client error: {0}")]
    LightClient(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("TurboDA error: {0}")]
    TurboDa(String),

    #[error("Sync error: {0}")]
    Sync(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("State error: {0}")]
    State(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DaemonError>;

/// Sanitize a URI into a filesystem-safe directory name
/// e.g., "sbo+raw://avail:turing:506/nft/" -> "avail_turing_506_nft"
pub fn sanitize_uri_for_path(uri: &str) -> String {
    // Remove sbo+raw:// or sbo:// prefix
    let s = uri.strip_prefix("sbo+raw://")
        .or_else(|| uri.strip_prefix("sbo://"))
        .unwrap_or(uri);

    // Replace non-alphanumeric chars with underscores, collapse multiple underscores
    let sanitized: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();

    // Collapse multiple underscores and trim trailing ones
    let mut result = String::new();
    let mut prev_underscore = false;
    for c in sanitized.chars() {
        if c == '_' {
            if !prev_underscore && !result.is_empty() {
                result.push(c);
            }
            prev_underscore = true;
        } else {
            result.push(c);
            prev_underscore = false;
        }
    }

    // Trim trailing underscore
    result.trim_end_matches('_').to_string()
}

/// Compute the repo metadata directory path based on its URI
/// Results in human-readable paths like ~/.sbo/repos/avail_turing_506/
pub fn repo_dir_for_uri(uri: &str) -> std::path::PathBuf {
    let sbo_dir = config::Config::sbo_dir();
    sbo_dir.join("repos").join(sanitize_uri_for_path(uri))
}

/// Compute the state DB path for a repo based on its URI
/// Results in paths like ~/.sbo/repos/avail_turing_506/state/
pub fn state_db_path_for_uri(uri: &str) -> std::path::PathBuf {
    repo_dir_for_uri(uri).join("state")
}
