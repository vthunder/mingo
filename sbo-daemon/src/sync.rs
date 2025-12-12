//! Block synchronization
//!
//! Coordinates LC verification with RPC data fetching and filesystem writes.

use std::collections::HashMap;
use crate::lc::LcManager;
use crate::repo::{Repo, RepoManager};
use crate::rpc::RpcClient;
use crate::validate::{validate_message, message_to_stored_object, ValidationResult};
use sbo_core::state::StateDb;

/// Synchronization engine
pub struct SyncEngine {
    lc: LcManager,
    rpc: RpcClient,
    verbose_raw: bool,
    /// StateDb instances per repo URI
    state_dbs: HashMap<String, StateDb>,
}

impl SyncEngine {
    pub fn new(lc: LcManager, rpc: RpcClient, verbose_raw: bool) -> Self {
        Self { lc, rpc, verbose_raw, state_dbs: HashMap::new() }
    }

    /// Get or open StateDb for a repo by URI
    /// State is stored in ~/.sbo/state/<sanitized_uri>/ for human-readable paths
    fn get_state_db(&mut self, uri: &str) -> crate::Result<&StateDb> {
        if !self.state_dbs.contains_key(uri) {
            let state_path = crate::state_db_path_for_uri(uri);
            std::fs::create_dir_all(&state_path)?;

            let state_db = StateDb::open(&state_path)
                .map_err(|e| crate::DaemonError::State(format!("Failed to open state DB: {}", e)))?;
            self.state_dbs.insert(uri.to_string(), state_db);
        }
        Ok(self.state_dbs.get(uri).unwrap())
    }

    /// Process a single block for all repos
    pub async fn process_block(
        &mut self,
        block_number: u64,
        repos: &mut RepoManager,
    ) -> crate::Result<()> {
        // 1. Verify block is available via LC (DAS)
        if !self.lc.is_block_available(block_number).await? {
            tracing::warn!("Block {} not available (DAS failed)", block_number);
            // TODO: Raise alarm
            return Err(crate::DaemonError::Sync(format!(
                "Block {} DAS verification failed",
                block_number
            )));
        }

        // 2. Get all app_ids we're following
        let app_ids = repos.followed_app_ids();
        if app_ids.is_empty() {
            return Ok(());
        }

        tracing::debug!("Processing block {} for app_ids {:?}", block_number, app_ids);

        // 3. Fetch block data for each app_id via RPC
        let block_data = self.rpc.fetch_block_data_multi(block_number, &app_ids).await?;

        // 4. Process each transaction
        for data in block_data {
            for tx in data.transactions {
                // Find repos that match this app_id
                let matching_repos = repos.get_by_app_id(tx.app_id);

                // Log submission discovery
                tracing::info!(
                    "[{}/{}] Received {} bytes for app {}",
                    block_number,
                    tx.index,
                    tx.data.len(),
                    tx.app_id
                );

                // Parse SBO messages (may be a batch with multiple messages)
                let messages = match sbo_core::wire::parse_batch(&tx.data) {
                    Ok(msgs) => {
                        if msgs.len() > 1 {
                            tracing::debug!(
                                "[{}/{}] Parsed batch of {} messages",
                                block_number,
                                tx.index,
                                msgs.len()
                            );
                        }
                        msgs
                    }
                    Err(e) => {
                        // Use debug level - non-SBO data on this app_id is expected
                        tracing::debug!(
                            "[{}/{}] → parse:✗ ({})",
                            block_number,
                            tx.index,
                            e
                        );
                        continue;
                    }
                };

                for repo in matching_repos {
                    for msg in &messages {
                        // Check path prefix filter
                        if let Some(ref prefix) = repo.uri.path_prefix {
                            if !msg.path.to_string().starts_with(prefix) {
                                continue;
                            }
                        }

                        // Get state DB for this repo (keyed by URI)
                        let uri = repo.uri.to_string();
                        let state_db = match self.get_state_db(&uri) {
                            Ok(db) => db,
                            Err(e) => {
                                tracing::error!("Failed to open state DB for {}: {}", uri, e);
                                continue;
                            }
                        };

                        // Validate message against state
                        match validate_message(msg, state_db, &repo.path) {
                            ValidationResult::Valid { creator } => {
                                // Condensed success log: [block/tx] Action path/id by creator → sig:✓ state:✓ applied
                                tracing::info!(
                                    "[{}/{}] {:?} {}{} by {} → sig:✓ state:✓ applied",
                                    block_number,
                                    tx.index,
                                    msg.action,
                                    msg.path,
                                    msg.id,
                                    creator
                                );
                            }
                            ValidationResult::Invalid { stage, reason } => {
                                // Condensed failure log: [block/tx] Action path/id → stage:✗ (reason)
                                tracing::warn!(
                                    "[{}/{}] {:?} {}{} → {}:✗ ({})",
                                    block_number,
                                    tx.index,
                                    msg.action,
                                    msg.path,
                                    msg.id,
                                    stage,
                                    reason
                                );
                                continue;
                            }
                        }

                        // Log raw data if verbose
                        if self.verbose_raw {
                            // Serialize message to show wire format
                            let wire_data = sbo_core::wire::serialize(msg);
                            match std::str::from_utf8(&wire_data) {
                                Ok(s) => {
                                    tracing::info!("  --- Wire format ---");
                                    for line in s.lines().take(30) {
                                        tracing::info!("  | {}", line);
                                    }
                                    let line_count = s.lines().count();
                                    if line_count > 30 {
                                        tracing::info!("  | ... ({} more lines)", line_count - 30);
                                    }
                                    tracing::info!("  -------------------");
                                }
                                Err(_) => {
                                    tracing::info!("  (binary data, {} bytes)", wire_data.len());
                                }
                            }
                        }

                        // Write to filesystem and update state
                        self.write_object(repo, msg, block_number)?;
                    }
                }
            }
        }

        // 5. Update head for all repos with these app_ids
        let paths_to_update: Vec<_> = app_ids
            .iter()
            .flat_map(|&app_id| repos.get_by_app_id(app_id))
            .map(|r| r.path.clone())
            .collect();

        for path in paths_to_update {
            repos.update_head(&path, block_number)?;
        }

        Ok(())
    }

    /// Write an SBO object to the filesystem and update state
    fn write_object(&mut self, repo: &Repo, msg: &sbo_core::message::Message, block_number: u64) -> crate::Result<()> {
        // Build path: repo_root / sbo_path / sbo_id
        let mut file_path = repo.path.clone();

        // Add path components (skip leading slash)
        let path_str = msg.path.to_string();
        for component in path_str.trim_start_matches('/').split('/').filter(|s| !s.is_empty()) {
            file_path.push(component);
        }

        // Add the ID as filename
        file_path.push(msg.id.as_str());

        // Create parent directories
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Serialize to wire format
        let wire_data = sbo_core::wire::serialize(msg);

        // Atomic write: write to temp file, then rename
        let temp_path = file_path.with_extension("tmp");
        std::fs::write(&temp_path, &wire_data)?;
        std::fs::rename(&temp_path, &file_path)?;

        tracing::debug!(
            "Wrote object {}{} to {}",
            msg.path,
            msg.id,
            file_path.display()
        );

        // Update state DB (keyed by URI)
        let uri = repo.uri.to_string();
        let state_db = self.state_dbs.get(&uri);
        if let Some(stored_obj) = message_to_stored_object(msg, block_number, state_db) {
            if let Some(db) = state_db {
                if let Err(e) = db.put_object(&stored_obj) {
                    tracing::warn!("Failed to update state DB: {}", e);
                }

                // If this is a name claim at /sys/names/, index pubkey -> name
                if path_str.starts_with("/sys/names/") {
                    let pubkey = msg.signing_key.to_string();
                    let name = msg.id.as_str();
                    if let Err(e) = db.put_name_claim(&pubkey, name) {
                        tracing::warn!("Failed to index name claim: {}", e);
                    } else {
                        tracing::info!("Indexed name claim: {} -> {}", name, pubkey);
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the sync loop
    pub async fn run(&mut self, repos: &mut RepoManager) -> crate::Result<()> {
        let mut block_rx = self.lc.subscribe_blocks();

        tracing::info!("Starting sync loop");

        loop {
            // Wait for new block notification
            if block_rx.changed().await.is_err() {
                break;
            }

            let latest_block = *block_rx.borrow();

            // Find minimum head across all repos
            let min_head = repos
                .list()
                .map(|r| r.head)
                .min()
                .unwrap_or(latest_block);

            // Process blocks from min_head to latest
            for block_num in (min_head + 1)..=latest_block {
                if let Err(e) = self.process_block(block_num, repos).await {
                    tracing::error!("Failed to process block {}: {}", block_num, e);
                    // Continue with next block
                }
            }
        }

        Ok(())
    }
}
