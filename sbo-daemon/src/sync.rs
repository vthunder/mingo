//! Block synchronization
//!
//! Coordinates LC verification with RPC data fetching and filesystem writes.

use std::collections::HashMap;
use crate::lc::LcManager;
use crate::repo::{Repo, RepoManager};
use crate::rpc::RpcClient;
use crate::validate::{validate_message, message_to_stored_object, ValidationResult};
use sbo_core::state::StateDb;
use sha2::{Sha256, Digest};

/// Compute transition state root: sha256(prev_root || actions_data)
///
/// This is a simple transition commitment (commits to the sequence of changes).
/// Phase 4 upgrades to merkle state root for object inclusion proofs.
fn compute_transition_root(prev_root: [u8; 32], actions_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&prev_root);
    hasher.update(actions_data);
    hasher.finalize().into()
}

/// Verify an SBOP proof against historical state roots
///
/// Returns true if the proof is valid for the given state database.
/// In dev mode, checks that:
/// 1. Block range is valid (block_to >= block_from)
/// 2. State roots exist for the claimed blocks
/// 3. Receipt has DEV: prefix (dev mode format)
///
/// In production, this would verify the ZK proof via RISC Zero.
fn verify_proof(
    sbop: &sbo_core::proof::SbopMessage,
    state_db: &StateDb,
) -> Result<bool, crate::DaemonError> {
    // Basic range validation
    if sbop.block_to < sbop.block_from {
        tracing::warn!(
            "Invalid proof block range: {} > {}",
            sbop.block_from, sbop.block_to
        );
        return Ok(false);
    }

    // Check we have state roots for the claimed blocks
    let pre_root = state_db.get_state_root_at_block(sbop.block_from)
        .map_err(|e| crate::DaemonError::State(format!("Failed to get pre-state root: {}", e)))?;
    let post_root = state_db.get_state_root_at_block(sbop.block_to)
        .map_err(|e| crate::DaemonError::State(format!("Failed to get post-state root: {}", e)))?;

    // If we don't have state for these blocks yet, we can't verify
    if pre_root.is_none() || post_root.is_none() {
        tracing::debug!(
            "Cannot verify proof: missing state roots for blocks {}-{}",
            sbop.block_from, sbop.block_to
        );
        // Store as unverified - we may be able to verify later
        return Ok(false);
    }

    // Check receipt format based on receipt_kind
    match sbop.receipt_kind.as_str() {
        "composite" | "succinct" | "groth16" => {
            // Dev mode proofs start with "DEV:"
            if sbop.receipt_bytes.starts_with(b"DEV:") {
                tracing::debug!("Verified dev mode proof for blocks {}-{}", sbop.block_from, sbop.block_to);
                return Ok(true);
            }

            // Production zkVM proof verification would go here
            // For now, only dev mode proofs are supported
            tracing::warn!(
                "Production zkVM proof verification not yet implemented (receipt_kind: {})",
                sbop.receipt_kind
            );
            Ok(false)
        }
        _ => {
            tracing::warn!("Unknown receipt kind: {}", sbop.receipt_kind);
            Ok(false)
        }
    }
}

/// Synchronization engine
pub struct SyncEngine {
    lc: LcManager,
    rpc: RpcClient,
    verbose_raw: bool,
    /// Light mode: only process SBOP proofs, skip state transitions
    light_mode: bool,
    /// StateDb instances per repo URI
    state_dbs: HashMap<String, StateDb>,
}

impl SyncEngine {
    pub fn new(lc: LcManager, rpc: RpcClient, verbose_raw: bool, light_mode: bool) -> Self {
        if light_mode {
            tracing::info!("SyncEngine running in LIGHT mode - proofs only, no state execution");
        }
        Self { lc, rpc, verbose_raw, light_mode, state_dbs: HashMap::new() }
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
    /// Returns the number of transactions processed for followed app_ids
    pub async fn process_block(
        &mut self,
        block_number: u64,
        repos: &mut RepoManager,
    ) -> crate::Result<usize> {
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
            return Ok(0);
        }

        tracing::debug!("Processing block {} for app_ids {:?}", block_number, app_ids);

        // 3. Fetch block data for each app_id via RPC
        let block_data = self.rpc.fetch_block_data_multi(block_number, &app_ids).await?;

        // Track transaction count for this block
        let mut tx_count = 0;

        // 4. Process each transaction
        for data in block_data {
            tx_count += data.transactions.len();
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

                // Check if this is an SBOP (proof) message
                if sbo_core::proof::is_sbop_message(&tx.data) {
                    match sbo_core::proof::parse_sbop(&tx.data) {
                        Ok(sbop) => {
                            tracing::info!(
                                "[{}/{}] SBOP proof blocks {}-{} ({})",
                                block_number,
                                tx.index,
                                sbop.block_from,
                                sbop.block_to,
                                sbop.receipt_kind
                            );

                            // Verify and store proof for each matching repo
                            let matching_repos = repos.get_by_app_id(tx.app_id);
                            for repo in matching_repos {
                                let uri = repo.uri.to_string();
                                if let Ok(state_db) = self.get_state_db(&uri) {
                                    // Verify the proof against historical state
                                    let verified = match verify_proof(&sbop, state_db) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to verify proof for {}: {}",
                                                uri, e
                                            );
                                            false
                                        }
                                    };

                                    let stored_proof = sbo_core::state::StoredProof {
                                        block_from: sbop.block_from,
                                        block_to: sbop.block_to,
                                        receipt_kind: sbop.receipt_kind.clone(),
                                        receipt_bytes: sbop.receipt_bytes.clone(),
                                        received_at_block: block_number,
                                        verified,
                                    };
                                    if let Err(e) = state_db.put_proof(&stored_proof) {
                                        tracing::warn!(
                                            "Failed to store proof for {}: {}",
                                            uri, e
                                        );
                                    } else {
                                        let status = if verified { "verified" } else { "unverified" };
                                        tracing::info!(
                                            "Stored {} SBOP proof for {} (blocks {}-{})",
                                            status, uri, sbop.block_from, sbop.block_to
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "[{}/{}] SBOP parse failed: {}",
                                block_number,
                                tx.index,
                                e
                            );
                        }
                    }
                    continue; // Don't try to parse as SBO message
                }

                // In light mode, only process SBOP proofs - skip SBO message execution
                if self.light_mode {
                    tracing::debug!(
                        "[{}/{}] Light mode: skipping SBO message (proofs only)",
                        block_number,
                        tx.index
                    );
                    continue;
                }

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

        // 6. Compute and record trie state root for each repo
        // Collect unique URIs for ALL repos we're syncing (not just ones with transactions)
        let uris: std::collections::HashSet<_> = app_ids
            .iter()
            .flat_map(|&app_id| repos.get_by_app_id(app_id))
            .map(|r| r.uri.to_string())
            .collect();

        for uri in &uris {
            // Ensure state_db is opened for ALL repos we're syncing
            if let Err(e) = self.get_state_db(uri) {
                tracing::warn!("Failed to open state DB for {}: {}", uri, e);
                continue;
            }
        }

        for uri in uris {
            if let Some(state_db) = self.state_dbs.get(&uri) {
                // Compute trie state root from all objects
                let new_root = match state_db.compute_trie_state_root() {
                    Ok(root) => root,
                    Err(e) => {
                        tracing::warn!("Failed to compute trie root for {}: {}", uri, e);
                        // Fall back to transition root
                        let prev_root = state_db.get_state_root_at_block(block_number.saturating_sub(1))
                            .unwrap_or(None)
                            .unwrap_or([0u8; 32]);
                        let actions_data = block_number.to_le_bytes();
                        compute_transition_root(prev_root, &actions_data)
                    }
                };

                // Only record state root if it changed (optimization)
                let should_record = match state_db.get_latest_state_root() {
                    Ok(Some((_, prev_root))) => prev_root != new_root,
                    _ => true, // No previous root, always record
                };

                if should_record {
                    if let Err(e) = state_db.record_state_root(block_number, new_root) {
                        tracing::warn!("Failed to record state root for {}: {}", uri, e);
                    } else {
                        tracing::debug!(
                            "Recorded trie state root for {} at block {}: {}",
                            uri, block_number, hex::encode(&new_root[..8])
                        );
                    }
                }

                // ALWAYS record the last processed block (needed for "future block" check)
                if let Err(e) = state_db.set_last_block(block_number) {
                    tracing::warn!("Failed to set last block for {}: {}", uri, e);
                }
            }
        }

        Ok(tx_count)
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

        // Compute object hash for trie (hash of complete raw bytes)
        let object_hash = sbo_core::sha256(&wire_data);

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
        if let Some(stored_obj) = message_to_stored_object(msg, block_number, state_db, object_hash) {
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

                // If this is a policy object (Content-Schema: policy.v2), index it
                if msg.content_schema.as_deref() == Some("policy.v2") {
                    if let Some(ref payload) = msg.payload {
                        match serde_json::from_slice::<sbo_core::policy::Policy>(payload) {
                            Ok(policy) => {
                                if let Err(e) = db.put_policy(&msg.path, &policy) {
                                    tracing::warn!("Failed to index policy at {}: {}", msg.path, e);
                                } else {
                                    tracing::info!("Indexed policy at {}", msg.path);
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse policy.v2 at {}: {}", msg.path, e);
                            }
                        }
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
