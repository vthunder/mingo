//! Light Client Manager
//!
//! Manages the standalone Avail light client process.

use crate::config::LightClientConfig;
use std::process::{Child, Command};
use tokio::sync::watch;

/// Light client status from /v2/status
#[derive(Debug, Clone)]
pub struct LcStatus {
    pub modes: Vec<String>,
    pub app_id: Option<u32>,
    pub network: String,
    pub latest_block: u64,
    pub available_first: u64,
    pub available_last: u64,
}

/// Manages the light client process
pub struct LcManager {
    config: LightClientConfig,
    process: Option<Child>,
    http_client: reqwest::Client,
}

impl LcManager {
    pub fn new(config: LightClientConfig) -> Self {
        Self {
            config,
            process: None,
            http_client: reqwest::Client::new(),
        }
    }

    /// Start the light client process
    pub async fn start(&mut self) -> crate::Result<()> {
        // For now, assume LC is already running externally
        // TODO: Actually spawn and manage the process

        tracing::info!(
            "Light client manager initialized, expecting LC at port {}",
            self.config.http_port
        );

        // Verify connection
        self.status().await?;

        Ok(())
    }

    /// Stop the light client process
    pub async fn stop(&mut self) -> crate::Result<()> {
        if let Some(mut child) = self.process.take() {
            tracing::info!("Stopping light client process");
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }

    /// Get light client status
    pub async fn status(&self) -> crate::Result<LcStatus> {
        let url = format!("http://127.0.0.1:{}/v2/status", self.config.http_port);

        let resp: serde_json::Value = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::DaemonError::LightClient(format!("Failed to connect: {}", e)))?
            .json()
            .await
            .map_err(|e| crate::DaemonError::LightClient(format!("Failed to parse status: {}", e)))?;

        Ok(LcStatus {
            modes: resp["modes"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            app_id: resp["app_id"].as_u64().map(|n| n as u32),
            network: resp["network"].as_str().unwrap_or("unknown").to_string(),
            latest_block: resp["blocks"]["latest"].as_u64().unwrap_or(0),
            available_first: resp["blocks"]["available"]["first"].as_u64().unwrap_or(0),
            available_last: resp["blocks"]["available"]["last"].as_u64().unwrap_or(0),
        })
    }

    /// Check if a block is available (DAS verified)
    pub async fn is_block_available(&self, block_number: u64) -> crate::Result<bool> {
        let status = self.status().await?;
        Ok(block_number >= status.available_first && block_number <= status.available_last)
    }

    /// Wait for a block to become available
    pub async fn wait_for_block(&self, block_number: u64) -> crate::Result<()> {
        loop {
            if self.is_block_available(block_number).await? {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Subscribe to new finalized blocks
    pub fn subscribe_blocks(&self) -> watch::Receiver<u64> {
        let (tx, rx) = watch::channel(0u64);

        let http_client = self.http_client.clone();
        let port = self.config.http_port;

        tokio::spawn(async move {
            let mut last_block = 0u64;
            loop {
                let url = format!("http://127.0.0.1:{}/v2/status", port);
                if let Ok(resp) = http_client.get(&url).send().await {
                    if let Ok(status) = resp.json::<serde_json::Value>().await {
                        if let Some(latest) = status["blocks"]["latest"].as_u64() {
                            if latest > last_block {
                                last_block = latest;
                                let _ = tx.send(latest);
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        rx
    }
}
