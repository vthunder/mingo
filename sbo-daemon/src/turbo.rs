//! TurboDA Client
//!
//! Submits data to Avail via TurboDA for fast preconfirmations (~250ms).

use crate::config::TurboDaConfig;
use serde::{Deserialize, Serialize};

/// Submission result from TurboDA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionResult {
    pub submission_id: String,
}

/// Pending submission tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSubmission {
    pub submission_id: String,
    pub app_id: u32,
    pub data_hash: String,
    pub submitted_at: u64,
}

/// TurboDA client for fast submissions
pub struct TurboDaClient {
    config: TurboDaConfig,
    http_client: reqwest::Client,
}

impl TurboDaClient {
    pub fn new(config: TurboDaConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    /// Submit raw data to TurboDA
    pub async fn submit_raw(&self, data: &[u8]) -> crate::Result<SubmissionResult> {
        let api_key = self.config.api_key.as_ref().ok_or_else(|| {
            crate::DaemonError::TurboDa("TurboDA API key not configured".to_string())
        })?;

        let url = format!("{}/v1/submit_raw_data", self.config.endpoint);

        tracing::info!("Submitting {} bytes to TurboDA", data.len());

        let resp = self
            .http_client
            .post(&url)
            .header("x-api-key", api_key)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| crate::DaemonError::TurboDa(format!("Request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::DaemonError::TurboDa(format!(
                "Submission failed ({}): {}",
                status, body
            )));
        }

        let result: SubmissionResult = resp
            .json()
            .await
            .map_err(|e| crate::DaemonError::TurboDa(format!("Failed to parse response: {}", e)))?;

        tracing::info!("Submitted! submission_id: {}", result.submission_id);

        Ok(result)
    }

    /// Check submission status
    pub async fn get_submission_status(&self, submission_id: &str) -> crate::Result<serde_json::Value> {
        let api_key = self.config.api_key.as_ref().ok_or_else(|| {
            crate::DaemonError::TurboDa("TurboDA API key not configured".to_string())
        })?;

        let url = format!("{}/v1/submission/{}", self.config.endpoint, submission_id);

        let resp = self
            .http_client
            .get(&url)
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(|e| crate::DaemonError::TurboDa(format!("Request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::DaemonError::TurboDa(format!(
                "Status check failed ({}): {}",
                status, body
            )));
        }

        resp.json()
            .await
            .map_err(|e| crate::DaemonError::TurboDa(format!("Failed to parse response: {}", e)))
    }
}
