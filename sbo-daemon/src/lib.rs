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
pub mod validate;

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
