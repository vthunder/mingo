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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertsConfig {
    pub webhook_url: Option<String>,
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
            },
            alerts: AlertsConfig::default(),
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
