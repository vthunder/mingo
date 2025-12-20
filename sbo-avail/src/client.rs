//! Avail light client HTTP API wrapper

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::{Block, DaError, DataAvailability, SubmitResult, Transaction};

/// Configuration for Avail client
#[derive(Debug, Clone)]
pub struct AvailConfig {
    /// Light client API endpoint
    pub endpoint: String,
    /// App ID for filtering transactions
    pub app_id: u32,
}

impl Default for AvailConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:7007".to_string(),
            app_id: 0,
        }
    }
}

impl AvailConfig {
    /// Create config for a specific endpoint
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }

    /// Set the app ID
    pub fn with_app_id(mut self, app_id: u32) -> Self {
        self.app_id = app_id;
        self
    }
}

/// Response from /v2/status
#[derive(Debug, Deserialize)]
pub struct StatusResponse {
    pub modes: Vec<String>,
    pub app_id: Option<u32>,
    #[serde(default)]
    pub genesis_hash: String,
    #[serde(default)]
    pub network: String,
    pub blocks: BlocksStatus,
}

#[derive(Debug, Deserialize)]
pub struct BlocksStatus {
    pub latest: u64,
    #[serde(default)]
    pub available: BlockRange,
    #[serde(default)]
    pub app_data: BlockRange,
}

#[derive(Debug, Default, Deserialize)]
pub struct BlockRange {
    pub first: u64,
    pub last: u64,
}

/// Request for /v2/submit
#[derive(Debug, Serialize)]
struct SubmitRequest {
    data: String, // base64 encoded
}

/// Response from /v2/submit
#[derive(Debug, Deserialize)]
struct SubmitResponse {
    block_number: u64,
    block_hash: String,
    hash: String, // tx hash
    index: u32,
}

/// Response from /v2/blocks/{n}/data
#[derive(Debug, Deserialize)]
struct BlockDataResponse {
    #[allow(dead_code)]
    block_number: u64,
    data_transactions: Vec<DataTransaction>,
}

#[derive(Debug, Deserialize)]
struct DataTransaction {
    data: String, // base64 encoded
    #[allow(dead_code)]
    extrinsic: Option<String>,
}

/// Avail light client
pub struct AvailClient {
    config: AvailConfig,
    http: reqwest::Client,
}

impl AvailClient {
    /// Connect to Avail light client
    pub async fn connect(config: AvailConfig) -> Result<Self, DaError> {
        tracing::info!("Connecting to Avail light client at {}", config.endpoint);

        let http = reqwest::Client::new();
        let client = Self { config, http };

        // Verify connection by fetching status
        let status = client.status().await?;
        tracing::info!(
            "Connected! Network: {}, Latest block: {}, Modes: {:?}",
            status.network,
            status.blocks.latest,
            status.modes
        );

        Ok(client)
    }

    /// Get the configured app ID
    pub fn app_id(&self) -> u32 {
        self.config.app_id
    }

    /// Get light client status
    pub async fn status(&self) -> Result<StatusResponse, DaError> {
        let url = format!("{}/v2/status", self.config.endpoint);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| DaError::Connection(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(DaError::Connection(format!(
                "Status check failed: {}",
                resp.status()
            )));
        }

        resp.json()
            .await
            .map_err(|e| DaError::Connection(format!("Failed to parse status: {}", e)))
    }
}

impl DataAvailability for AvailClient {
    fn stream_blocks(&self, from: u64) -> impl futures::Stream<Item = Block> + Send {
        tracing::info!("Starting block stream from height {}", from);

        // Clone what we need for the stream
        let endpoint = self.config.endpoint.clone();
        let http = self.http.clone();

        // Polling-based stream using unfold
        futures::stream::unfold(
            (from, endpoint, http),
            |(current_height, endpoint, http)| async move {
                loop {
                    let url = format!("{}/v2/blocks/{}/data?fields=data", endpoint, current_height);

                    tracing::debug!("Polling block {}", current_height);

                    let resp = match http.get(&url).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("Failed to fetch block {}: {}", current_height, e);
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    };

                    if resp.status().as_u16() == 404 {
                        // Block not available yet, wait and retry
                        tracing::debug!("Block {} not available yet, waiting...", current_height);
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();

                        // "Block data is not available" means LC doesn't have this block's app data
                        // Skip to next block instead of retrying forever
                        if status.as_u16() == 400 && body.contains("not available") {
                            tracing::warn!("Block {} app data not available, skipping", current_height);
                            return Some((
                                Block {
                                    number: current_height,
                                    hash: [0u8; 32],
                                    transactions: vec![], // Empty - data unavailable
                                },
                                (current_height + 1, endpoint, http),
                            ));
                        }

                        tracing::warn!("Error fetching block {}: {} - {}", current_height, status, body);
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }

                    let data: BlockDataResponse = match resp.json().await {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!("Failed to parse block {}: {}", current_height, e);
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    // Decode transactions
                    let transactions: Vec<Transaction> = data
                        .data_transactions
                        .into_iter()
                        .enumerate()
                        .filter_map(|(index, tx)| {
                            base64::engine::general_purpose::STANDARD
                                .decode(&tx.data)
                                .ok()
                                .map(|decoded| Transaction {
                                    index: index as u32,
                                    data: decoded,
                                })
                        })
                        .collect();

                    let block = Block {
                        number: current_height,
                        hash: [0u8; 32], // TODO: fetch actual hash
                        transactions,
                    };

                    tracing::info!("Received block {} with {} txs", current_height, block.transactions.len());

                    return Some((block, (current_height + 1, endpoint, http)));
                }
            },
        )
    }

    async fn submit(&self, data: &[u8]) -> Result<SubmitResult, DaError> {
        let url = format!("{}/v2/submit", self.config.endpoint);

        // Base64 encode the data
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let request = SubmitRequest { data: encoded };

        tracing::info!("Submitting {} bytes to Avail", data.len());

        let resp = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| DaError::Submission(format!("Request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DaError::Submission(format!(
                "Submit failed ({}): {}",
                status, body
            )));
        }

        let result: SubmitResponse = resp
            .json()
            .await
            .map_err(|e| DaError::Submission(format!("Failed to parse response: {}", e)))?;

        tracing::info!(
            "Submitted! Block: {}, Tx: {}, Index: {}",
            result.block_number,
            result.hash,
            result.index
        );

        // Parse tx hash
        let tx_hash = hex::decode(&result.hash)
            .map_err(|e| DaError::Submission(format!("Invalid tx hash: {}", e)))?;
        let mut tx_hash_arr = [0u8; 32];
        if tx_hash.len() >= 32 {
            tx_hash_arr.copy_from_slice(&tx_hash[..32]);
        }

        // Parse block hash
        let block_hash = hex::decode(&result.block_hash).ok();
        let block_hash_arr = block_hash.and_then(|h| {
            if h.len() >= 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h[..32]);
                Some(arr)
            } else {
                None
            }
        });

        Ok(SubmitResult {
            tx_hash: tx_hash_arr,
            block_number: Some(result.block_number),
            block_hash: block_hash_arr,
        })
    }

    async fn get_block(&self, number: u64) -> Result<Option<Block>, DaError> {
        let url = format!(
            "{}/v2/blocks/{}/data?fields=data",
            self.config.endpoint, number
        );

        tracing::debug!("Fetching block {}", number);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| DaError::Connection(format!("Request failed: {}", e)))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DaError::Connection(format!(
                "Get block failed ({}): {}",
                status, body
            )));
        }

        let data: BlockDataResponse = resp
            .json()
            .await
            .map_err(|e| DaError::Connection(format!("Failed to parse block: {}", e)))?;

        // Decode transactions
        let transactions: Vec<Transaction> = data
            .data_transactions
            .into_iter()
            .enumerate()
            .filter_map(|(index, tx)| {
                base64::engine::general_purpose::STANDARD
                    .decode(&tx.data)
                    .ok()
                    .map(|decoded| Transaction {
                        index: index as u32,
                        data: decoded,
                    })
            })
            .collect();

        Ok(Some(Block {
            number,
            hash: [0u8; 32], // TODO: fetch actual hash
            transactions,
        }))
    }
}
