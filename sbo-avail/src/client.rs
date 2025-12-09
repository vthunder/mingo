//! Avail light client wrapper

use super::{Block, DaError, DataAvailability, SubmitResult};

/// Configuration for Avail client
#[derive(Debug, Clone)]
pub struct AvailConfig {
    /// Network (mainnet, testnet, etc.)
    pub network: String,
    /// App ID for filtering transactions
    pub app_id: u32,
    /// Light client RPC endpoint (if not using embedded)
    pub rpc_endpoint: Option<String>,
}

impl Default for AvailConfig {
    fn default() -> Self {
        Self {
            network: "testnet".to_string(),
            app_id: 0,
            rpc_endpoint: None,
        }
    }
}

/// Avail light client
pub struct AvailClient {
    config: AvailConfig,
    // TODO: Add actual light client when integrating
    // light_client: avail_light_client::Client,
}

impl AvailClient {
    /// Connect to Avail network
    pub async fn connect(config: AvailConfig) -> Result<Self, DaError> {
        tracing::info!("Connecting to Avail network: {}", config.network);
        tracing::info!("App ID: {}", config.app_id);

        // TODO: Initialize actual light client
        // let light_client = avail_light_client::Client::new(&config.network, config.app_id).await?;

        Ok(Self { config })
    }

    /// Get the configured app ID
    pub fn app_id(&self) -> u32 {
        self.config.app_id
    }
}

impl DataAvailability for AvailClient {
    fn stream_blocks(&self, from: u64) -> impl futures::Stream<Item = Block> + Send {
        tracing::info!("Starting block stream from height {}", from);

        // TODO: Implement actual block streaming
        futures::stream::empty()
    }

    async fn submit(&self, data: &[u8]) -> Result<SubmitResult, DaError> {
        tracing::info!("Submitting {} bytes to Avail", data.len());

        // TODO: Implement actual submission
        Err(DaError::Submission("Not implemented".to_string()))
    }

    async fn get_block(&self, number: u64) -> Result<Option<Block>, DaError> {
        tracing::info!("Fetching block {}", number);

        // TODO: Implement actual block fetch
        Ok(None)
    }
}
