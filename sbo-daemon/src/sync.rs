//! Block synchronization
//!
//! Coordinates LC verification with RPC data fetching and filesystem writes.

use std::collections::HashMap;
use std::path::PathBuf;
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
    /// StateDb instances per repo path
    state_dbs: HashMap<PathBuf, StateDb>,
}

impl SyncEngine {
    pub fn new(lc: LcManager, rpc: RpcClient, verbose_raw: bool) -> Self {
        Self { lc, rpc, verbose_raw, state_dbs: HashMap::new() }
    }

    /// Get or open StateDb for a repo
    fn get_state_db(&mut self, repo_path: &std::path::Path) -> crate::Result<&StateDb> {
        if !self.state_dbs.contains_key(repo_path) {
            let state_path = repo_path.join(".sbo-state");
            let state_db = StateDb::open(&state_path)
                .map_err(|e| crate::DaemonError::State(format!("Failed to open state DB: {}", e)))?;
            self.state_dbs.insert(repo_path.to_path_buf(), state_db);
        }
        Ok(self.state_dbs.get(repo_path).unwrap())
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

                for repo in matching_repos {
                    // Parse SBO message
                    match sbo_core::wire::parse(&tx.data) {
                        Ok(msg) => {
                            // Check path prefix filter
                            if let Some(ref prefix) = repo.uri.path_prefix {
                                if !msg.path.to_string().starts_with(prefix) {
                                    continue;
                                }
                            }

                            // Get state DB for this repo
                            let state_db = match self.get_state_db(&repo.path) {
                                Ok(db) => db,
                                Err(e) => {
                                    tracing::error!("Failed to open state DB for {}: {}", repo.path.display(), e);
                                    continue;
                                }
                            };

                            // Validate message against state
                            match validate_message(&msg, state_db, &repo.path) {
                                ValidationResult::Valid => {
                                    // Log update
                                    tracing::info!(
                                        "Block {}: Updating {}",
                                        block_number,
                                        repo.uri.to_string()
                                    );
                                }
                                ValidationResult::Invalid(reason) => {
                                    tracing::warn!(
                                        "Block {} tx {}: Rejected - {}",
                                        block_number,
                                        tx.index,
                                        reason
                                    );
                                    continue;
                                }
                            }

                            // Log raw data if verbose
                            if self.verbose_raw {
                                tracing::info!(
                                    "  Path: {}{} ({} bytes)",
                                    msg.path,
                                    msg.id,
                                    tx.data.len()
                                );
                                // Show as UTF-8 (SBO data should be human-readable)
                                match std::str::from_utf8(&tx.data) {
                                    Ok(s) => {
                                        for line in s.lines().take(20) {
                                            tracing::info!("  | {}", line);
                                        }
                                        let line_count = s.lines().count();
                                        if line_count > 20 {
                                            tracing::info!("  | ... ({} more lines)", line_count - 20);
                                        }
                                    }
                                    Err(_) => {
                                        tracing::info!("  (binary data, {} bytes)", tx.data.len());
                                    }
                                }
                            }

                            // Write to filesystem and update state
                            self.write_object(repo, &msg, block_number)?;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse SBO message in block {} tx {}: {}",
                                block_number,
                                tx.index,
                                e
                            );
                        }
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

        // Update state DB
        if let Some(stored_obj) = message_to_stored_object(msg, block_number) {
            let state_db = self.state_dbs.get(&repo.path);
            if let Some(db) = state_db {
                if let Err(e) = db.put_object(&stored_obj) {
                    tracing::warn!("Failed to update state DB: {}", e);
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
