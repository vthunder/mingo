//! Daemon configuration

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Global daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub light_client: LightClientConfig,
    pub rpc: RpcConfig,
    pub turbo_da: TurboDaConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub prover: ProverConfig,
    #[serde(default)]
    pub light: LightModeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub pid_file: PathBuf,
    pub repos_dir: PathBuf,
    pub repos_index: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientConfig {
    pub network: String,
    pub identity_file: Option<PathBuf>,
    pub http_port: u16,
    pub binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub endpoints: Vec<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurboDaConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    /// App ID associated with this API key (informational - determined by TurboDA)
    #[serde(default)]
    pub app_id: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertsConfig {
    pub webhook_url: Option<String>,
}

/// Prover configuration for ZK proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// Enable prover mode (also via --prover flag)
    #[serde(default)]
    pub enabled: bool,

    /// Blocks per proof batch (1 = every block)
    #[serde(default = "default_batch_size")]
    pub batch_size: u64,

    /// Receipt kind: composite, succinct, groth16
    #[serde(default = "default_receipt_kind")]
    pub receipt_kind: String,

    /// Use RISC0_DEV_MODE for testing (fake proofs)
    #[serde(default)]
    pub dev_mode: bool,
}

fn default_batch_size() -> u64 { 1 }
fn default_receipt_kind() -> String { "composite".to_string() }

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_size: default_batch_size(),
            receipt_kind: default_receipt_kind(),
            dev_mode: false,
        }
    }
}

/// Light client mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightModeConfig {
    /// Enable light client mode (also via --light flag)
    #[serde(default)]
    pub enabled: bool,

    /// Verify object proofs when requested
    #[serde(default = "default_true")]
    pub verify_objects: bool,
}

fn default_true() -> bool { true }

impl Default for LightModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_objects: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let sbo_dir = dirs::home_dir()
            .map(|h| h.join(".sbo"))
            .unwrap_or_else(|| PathBuf::from(".sbo"));

        Self {
            daemon: DaemonConfig {
                socket_path: sbo_dir.join("daemon.sock"),
                pid_file: sbo_dir.join("daemon.pid"),
                repos_dir: sbo_dir.join("repos"),
                repos_index: sbo_dir.join("repos.json"),
            },
            light_client: LightClientConfig {
                network: "turing".to_string(),
                identity_file: None,
                http_port: 7007,
                binary_path: None,
            },
            rpc: RpcConfig {
                // avail-rust uses HTTP JSON-RPC, not WebSocket
                endpoints: vec!["https://turing-rpc.avail.so/rpc".to_string()],
                timeout_secs: 30,
            },
            turbo_da: TurboDaConfig {
                endpoint: "https://staging.turbo-api.availproject.org".to_string(),
                api_key: None,
                app_id: None,
            },
            alerts: AlertsConfig::default(),
            prover: ProverConfig::default(),
            light: LightModeConfig::default(),
        }
    }
}

impl Config {
    /// Load config from file, or create default
    pub fn load(path: &Path) -> crate::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content)
                .map_err(|e| crate::DaemonError::Config(format!("Failed to parse config: {}", e)))
        } else {
            Ok(Self::default())
        }
    }

    /// Save config to file
    pub fn save(&self, path: &Path) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::DaemonError::Config(format!("Failed to serialize config: {}", e)))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Save a well-documented sample config to file
    pub fn save_sample(path: &Path) -> crate::Result<()> {
        let sbo_dir = Self::sbo_dir();
        let content = format!(r#"# SBO Daemon Configuration
# ========================
#
# This file configures the SBO daemon. Edit as needed.
# Documentation: https://docs.sbo.dev/daemon/config

# ------------------------------------------------------------------------------
# Daemon Settings
# ------------------------------------------------------------------------------
[daemon]
# Unix socket for CLI-daemon communication
socket_path = "{sbo_dir}/daemon.sock"

# PID file for daemon process tracking
pid_file = "{sbo_dir}/daemon.pid"

# Directory where repository data is stored
repos_dir = "{sbo_dir}/repos"

# JSON file tracking configured repositories
repos_index = "{sbo_dir}/repos.json"

# ------------------------------------------------------------------------------
# Light Client Settings (Avail Light Client)
# ------------------------------------------------------------------------------
[light_client]
# Network to connect to: "mainnet" or "turing" (testnet)
network = "turing"

# Optional: Path to light client identity file for persistent peer ID
# identity_file = "{sbo_dir}/identity.toml"

# HTTP port for light client API (used internally)
http_port = 7007

# Optional: Path to avail-light binary (auto-detected if not set)
# binary_path = "/usr/local/bin/avail-light"

# ------------------------------------------------------------------------------
# RPC Settings (Avail Full Node)
# ------------------------------------------------------------------------------
[rpc]
# RPC endpoints to query block data from
# Multiple endpoints provide fallback redundancy
endpoints = [
    "https://turing-rpc.avail.so/rpc",
    # "https://avail-turing.public.blastapi.io",
]

# Request timeout in seconds
timeout_secs = 30

# ------------------------------------------------------------------------------
# TurboDA Settings (Data Submission)
# ------------------------------------------------------------------------------
[turbo_da]
# TurboDA API endpoint
# Staging (testnet): https://staging.turbo-api.availproject.org
# Production:        https://turbo-api.availproject.org
endpoint = "https://staging.turbo-api.availproject.org"

# Your TurboDA API key (REQUIRED for submitting data)
# Get one at: https://turbo.availproject.org
# api_key = "your-api-key-here"

# App ID associated with your API key (informational only)
# app_id = 506

# ------------------------------------------------------------------------------
# Alerts Settings (Optional)
# ------------------------------------------------------------------------------
[alerts]
# Webhook URL for error notifications (Discord, Slack, etc.)
# webhook_url = "https://discord.com/api/webhooks/..."

# ------------------------------------------------------------------------------
# Prover Settings (ZK Proof Generation)
# ------------------------------------------------------------------------------
[prover]
# Enable prover mode to generate ZK proofs for state transitions
# Can also be enabled with: sbo-daemon start --prover
enabled = false

# Number of blocks to batch into a single proof
# 1 = proof per block, higher = more efficient but delayed
batch_size = 1

# Proof type to generate:
# - "composite": Fast, large proofs (~1MB) - good for testing
# - "succinct":  Slower, smaller proofs (~200KB)
# - "groth16":   Slowest, tiny proofs (~256 bytes) - for on-chain verification
receipt_kind = "composite"

# Development mode: generate fake proofs instantly (for testing only!)
dev_mode = false

# ------------------------------------------------------------------------------
# Light Mode Settings (Proof Verification Only)
# ------------------------------------------------------------------------------
[light]
# Enable light mode: verify proofs instead of executing state transitions
# Mutually exclusive with prover mode
# Can also be enabled with: sbo-daemon start --light
enabled = false

# Verify object proofs when they are requested
verify_objects = true
"#, sbo_dir = sbo_dir.display());

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get the base SBO directory
    pub fn sbo_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".sbo"))
            .unwrap_or_else(|| PathBuf::from(".sbo"))
    }

    /// Get the config file path
    pub fn config_path() -> PathBuf {
        Self::sbo_dir().join("config.toml")
    }
}
