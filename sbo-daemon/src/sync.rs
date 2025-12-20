//! Block synchronization
//!
//! Coordinates LC verification with RPC data fetching and filesystem writes.

use std::collections::HashMap;
use crate::lc::LcManager;
use crate::repo::{Repo, RepoManager};
use crate::rpc::RpcClient;
use crate::validate::{validate_message, message_to_stored_object, resolve_creator, ValidationResult};
use sbo_core::state::StateDb;
use sbo_core::{StateTransitionWitness, ObjectWitness, SparseTrie};
use sha2::{Sha256, Digest};

/// Tracking touched objects during block processing for witness generation
#[derive(Debug, Default)]
pub struct TouchedObjects {
    pub creates: Vec<TouchedCreate>,
    pub updates: Vec<TouchedUpdate>,
    pub deletes: Vec<TouchedDelete>,
}

#[derive(Debug, Clone)]
pub struct TouchedCreate {
    pub path_segments: Vec<String>,
    pub new_object_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TouchedUpdate {
    pub path_segments: Vec<String>,
    pub old_object_hash: [u8; 32],
    pub new_object_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TouchedDelete {
    pub path_segments: Vec<String>,
    pub old_object_hash: [u8; 32],
}

/// Generate a state transition witness from pre-state trie and touched objects
fn generate_witness(
    pre_trie: &SparseTrie,
    touched: &TouchedObjects,
    prev_state_root: [u8; 32],
) -> StateTransitionWitness {
    let mut witnesses = Vec::new();

    // Generate witnesses for creates (non-existence proofs)
    for create in &touched.creates {
        match pre_trie.generate_nonexistence_proof(&create.path_segments) {
            Ok(nonexistence_proof) => {
                witnesses.push(ObjectWitness::Create {
                    path_segments: create.path_segments.clone(),
                    new_object_hash: create.new_object_hash,
                    nonexistence_proof,
                });
            }
            Err(e) => {
                tracing::warn!("Failed to generate nonexistence proof for {:?}: {:?}",
                    create.path_segments, e);
            }
        }
    }

    // Generate witnesses for updates (inclusion proofs)
    for update in &touched.updates {
        match pre_trie.generate_proof(&update.path_segments) {
            Ok(inclusion_proof) => {
                witnesses.push(ObjectWitness::Update {
                    path_segments: update.path_segments.clone(),
                    old_object_hash: update.old_object_hash,
                    new_object_hash: update.new_object_hash,
                    inclusion_proof,
                });
            }
            Err(e) => {
                tracing::warn!("Failed to generate inclusion proof for update {:?}: {:?}",
                    update.path_segments, e);
            }
        }
    }

    // Generate witnesses for deletes (inclusion proofs)
    for delete in &touched.deletes {
        match pre_trie.generate_proof(&delete.path_segments) {
            Ok(inclusion_proof) => {
                witnesses.push(ObjectWitness::Delete {
                    path_segments: delete.path_segments.clone(),
                    old_object_hash: delete.old_object_hash,
                    inclusion_proof,
                });
            }
            Err(e) => {
                tracing::warn!("Failed to generate inclusion proof for delete {:?}: {:?}",
                    delete.path_segments, e);
            }
        }
    }

    StateTransitionWitness {
        prev_state_root,
        witnesses,
        sibling_hints: Vec::new(), // Sibling hints computed during verification
    }
}

/// Result of processing a block - includes state transition info for prover
#[derive(Debug, Clone)]
pub struct BlockProcessResult {
    /// Number of transactions processed
    pub tx_count: usize,
    /// State root before processing this block (None if no prior state)
    pub pre_state_root: Option<[u8; 32]>,
    /// State root after processing this block
    pub post_state_root: [u8; 32],
    /// Combined block data (all transaction bytes)
    pub block_data: Vec<u8>,
    /// Whether genesis has been processed (state DB has objects)
    pub has_genesis: bool,
    /// State transition witness for zkVM (touched objects with proofs)
    pub state_witness: StateTransitionWitness,
}

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
    // Note: get_state_root_at_block(N) returns state AFTER block N was processed
    // So for prev_state_root (state BEFORE block_from), we need block_from - 1
    // For genesis (block_from == 0 or first proof), prev_state_root should be [0; 32]
    #[allow(unused_variables)] // Used in zkvm feature
    let pre_root = if sbop.block_from == 0 {
        Some([0u8; 32]) // Genesis starts with empty state
    } else {
        state_db.get_state_root_at_block(sbop.block_from - 1)
            .map_err(|e| crate::DaemonError::State(format!("Failed to get pre-state root: {}", e)))?
    };
    let post_root = state_db.get_state_root_at_block(sbop.block_to)
        .map_err(|e| crate::DaemonError::State(format!("Failed to get post-state root: {}", e)))?;

    // If we don't have post state for these blocks yet, we can't verify
    // (pre_root can be None for bootstrap proofs where we start from arbitrary block)
    if post_root.is_none() {
        tracing::debug!(
            "Cannot verify proof: missing post-state root for block {}",
            sbop.block_to
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

            // Production zkVM proof verification
            #[cfg(feature = "zkvm")]
            {
                match sbo_zkvm::verify_receipt(&sbop.receipt_bytes) {
                    Ok(output) => {
                        // Verify journal claims match our state
                        // The journal contains: prev_state_root, new_state_root, block_number, block_hash

                        // Check block number matches claimed range
                        // Note: For batched proofs, block_number is the starting block
                        if output.block_number != sbop.block_from {
                            tracing::warn!(
                                "Journal block_number {} doesn't match claimed block_from {}",
                                output.block_number, sbop.block_from
                            );
                            return Ok(false);
                        }

                        // Verify state roots match what we computed
                        // Note: For bootstrap proofs (first proof in chain), the prover uses [0; 32] as
                        // prev_state_root. We accept this if we don't have state at block_from - 1
                        // (meaning we also started syncing from this point).
                        if let Some(our_pre_root) = pre_root {
                            // Allow bootstrap proofs where prev_state_root is [0; 32]
                            let is_bootstrap_proof = output.prev_state_root == [0u8; 32];
                            if !is_bootstrap_proof && output.prev_state_root != our_pre_root {
                                tracing::warn!(
                                    "Journal prev_state_root {} doesn't match our state {}",
                                    hex::encode(&output.prev_state_root[..8]),
                                    hex::encode(&our_pre_root[..8])
                                );
                                return Ok(false);
                            }
                            if is_bootstrap_proof && our_pre_root != [0u8; 32] {
                                // Bootstrap proof but we have different pre-state
                                // This is acceptable if we're both starting from same point
                                tracing::debug!(
                                    "Bootstrap proof: accepting [0] prev_state_root (our state: {})",
                                    hex::encode(&our_pre_root[..8])
                                );
                            }
                        }

                        if let Some(our_post_root) = post_root {
                            if output.new_state_root != our_post_root {
                                tracing::warn!(
                                    "Journal new_state_root {} doesn't match our state {}",
                                    hex::encode(&output.new_state_root[..8]),
                                    hex::encode(&our_post_root[..8])
                                );
                                return Ok(false);
                            }
                        }

                        tracing::info!(
                            "✓ Verified zkVM proof for blocks {}-{} (state: {} → {})",
                            sbop.block_from, sbop.block_to,
                            hex::encode(&output.prev_state_root[..4]),
                            hex::encode(&output.new_state_root[..4])
                        );
                        return Ok(true);
                    }
                    Err(e) => {
                        tracing::warn!("zkVM proof verification failed: {}", e);
                        return Ok(false);
                    }
                }
            }

            #[cfg(not(feature = "zkvm"))]
            {
                tracing::warn!(
                    "zkVM feature not enabled - cannot verify production proofs (receipt_kind: {})",
                    sbop.receipt_kind
                );
                Ok(false)
            }
        }
        _ => {
            tracing::warn!("Unknown receipt kind: {}", sbop.receipt_kind);
            Ok(false)
        }
    }
}

/// Verified proof output from light mode verification
#[derive(Debug)]
pub struct VerifiedProofOutput {
    pub block_from: u64,
    pub block_to: u64,
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
}

/// Verify an SBOP proof in light mode (cryptographic verification only)
///
/// Unlike verify_proof, this doesn't require existing state roots.
/// It verifies the zkVM receipt cryptographically and extracts the proven state roots.
/// Returns Ok(Some(output)) if verified, Ok(None) if not verifiable, Err on error.
fn verify_proof_light_mode(
    sbop: &sbo_core::proof::SbopMessage,
) -> Result<Option<VerifiedProofOutput>, crate::DaemonError> {
    // Basic range validation
    if sbop.block_to < sbop.block_from {
        tracing::warn!(
            "Invalid proof block range: {} > {}",
            sbop.block_from, sbop.block_to
        );
        return Ok(None);
    }

    // Check receipt format
    match sbop.receipt_kind.as_str() {
        "composite" | "succinct" | "groth16" => {
            // Dev mode proofs start with "DEV:"
            if sbop.receipt_bytes.starts_with(b"DEV:") {
                // Parse dev mode proof format: "DEV:prev_root:new_root"
                // For now, we can't extract state roots from dev mode proofs
                // Just mark as verified with placeholder roots
                tracing::warn!(
                    "Light mode: dev mode proofs don't contain verifiable state roots"
                );
                return Ok(None);
            }

            // Production zkVM proof verification
            #[cfg(feature = "zkvm")]
            {
                match sbo_zkvm::verify_receipt(&sbop.receipt_bytes) {
                    Ok(output) => {
                        // Verify journal claims match SBOP metadata
                        if output.block_number != sbop.block_from {
                            tracing::warn!(
                                "Journal block_number {} doesn't match SBOP block_from {}",
                                output.block_number, sbop.block_from
                            );
                            return Ok(None);
                        }

                        tracing::info!(
                            "✓ Light mode: verified zkVM proof for blocks {}-{} (state: {} → {})",
                            sbop.block_from, sbop.block_to,
                            hex::encode(&output.prev_state_root[..4]),
                            hex::encode(&output.new_state_root[..4])
                        );

                        return Ok(Some(VerifiedProofOutput {
                            block_from: sbop.block_from,
                            block_to: sbop.block_to,
                            prev_state_root: output.prev_state_root,
                            new_state_root: output.new_state_root,
                        }));
                    }
                    Err(e) => {
                        tracing::warn!("Light mode: zkVM proof verification failed: {}", e);
                        return Ok(None);
                    }
                }
            }

            #[cfg(not(feature = "zkvm"))]
            {
                tracing::warn!(
                    "Light mode: zkVM feature not enabled - cannot verify production proofs"
                );
                Ok(None)
            }
        }
        _ => {
            tracing::warn!("Light mode: unknown receipt kind: {}", sbop.receipt_kind);
            Ok(None)
        }
    }
}

/// Synchronization engine
pub struct SyncEngine {
    lc: LcManager,
    rpc: RpcClient,
    verbose_raw: bool,
    verbose_rpc_decode: bool,
    /// Light mode: only process SBOP proofs, skip state transitions
    light_mode: bool,
    /// StateDb instances per repo URI
    state_dbs: HashMap<String, StateDb>,
}

impl SyncEngine {
    pub fn new(lc: LcManager, rpc: RpcClient, verbose_raw: bool, verbose_rpc_decode: bool, light_mode: bool) -> Self {
        Self { lc, rpc, verbose_raw, verbose_rpc_decode, light_mode, state_dbs: HashMap::new() }
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
    /// Returns BlockProcessResult with transaction count and state transition info
    pub async fn process_block(
        &mut self,
        block_number: u64,
        repos: &mut RepoManager,
    ) -> crate::Result<BlockProcessResult> {
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
            return Ok(BlockProcessResult {
                tx_count: 0,
                pre_state_root: None,
                post_state_root: [0u8; 32],
                block_data: Vec::new(),
                has_genesis: false,
                state_witness: StateTransitionWitness::default(),
            });
        }

        // 2a. Capture pre-state root before processing (for prover)
        // We use the first repo's URI as representative (all should have same state)
        let first_uri = repos.followed_app_ids()
            .iter()
            .flat_map(|&app_id| repos.get_by_app_id(app_id))
            .next()
            .map(|r| r.uri.to_string());

        // Collect all unique repo URIs upfront
        let all_uris: Vec<String> = app_ids
            .iter()
            .flat_map(|&app_id| repos.get_by_app_id(app_id))
            .map(|r| r.uri.to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Open ALL state_dbs BEFORE processing (so write_object can track touched objects)
        for uri in &all_uris {
            if let Err(e) = self.get_state_db(uri) {
                tracing::warn!("Failed to open state DB for {}: {}", uri, e);
            }
        }

        // Capture pre-state root and build trie for proof generation
        // IMPORTANT: pre_state_root MUST be computed from the trie, not from the database
        // The trie is the authoritative source - proofs are generated against it
        let pre_trie = if let Some(ref uri) = first_uri {
            // Make sure state_db is opened for first_uri (might not be in all_uris)
            if let Err(e) = self.get_state_db(uri) {
                tracing::warn!("Failed to open state DB for first_uri {}: {}", uri, e);
            }
            if let Some(db) = self.state_dbs.get(uri) {
                // Build trie from existing objects for generating proofs
                let objects = db.get_all_objects_for_trie().unwrap_or_default();
                tracing::debug!(
                    "Building pre_trie from {} objects for uri {}",
                    objects.len(), uri
                );
                let mut trie = SparseTrie::new();
                for (segments, hash) in objects {
                    trie.insert(segments, hash);
                }
                trie
            } else {
                tracing::warn!("No state_db found for first_uri: {}", uri);
                SparseTrie::new()
            }
        } else {
            tracing::warn!("No first_uri found");
            SparseTrie::new()
        };

        // Compute pre_state_root from the trie - this is the authoritative source
        // Proofs are generated against pre_trie, so witness.prev_state_root must match
        let pre_state_root = pre_trie.root_hash();
        tracing::debug!(
            "pre_trie.root_hash() = {}",
            hex::encode(&pre_state_root[..8])
        );
        let pre_state_root_opt = if pre_state_root == [0u8; 32] { None } else { Some(pre_state_root) };

        // Track touched objects for witness generation
        let mut touched_objects = TouchedObjects::default();

        tracing::debug!("Processing block {} for app_ids {:?}", block_number, app_ids);

        // 3. Fetch block data for each app_id via RPC
        let rpc_block_data = self.rpc.fetch_block_data_multi(block_number, &app_ids).await?;

        // Track transaction count and collect raw data for prover
        let mut tx_count = 0;
        let mut raw_block_data: Vec<u8> = Vec::new();

        // 4. Process each transaction
        for data in rpc_block_data {
            tx_count += data.transactions.len();
            for tx in data.transactions {
                // Collect raw transaction data for prover
                raw_block_data.extend_from_slice(&tx.data);
                // Find repos that match this app_id
                let matching_repos = repos.get_by_app_id(tx.app_id);

                // Log submission discovery (verbose only)
                if self.verbose_rpc_decode {
                    tracing::info!(
                        "[{}/{}] Received {} bytes for app {}",
                        block_number,
                        tx.index,
                        tx.data.len(),
                        tx.app_id
                    );
                }

                // Check if this is an SBOP (proof) message
                if sbo_core::proof::is_sbop_message(&tx.data) {
                    // Debug: show first and last bytes to diagnose parse failures (verbose only)
                    if self.verbose_rpc_decode {
                        let first_bytes: Vec<u8> = tx.data.iter().take(50).copied().collect();
                        let last_bytes: Vec<u8> = tx.data.iter().rev().take(50).rev().copied().collect();
                        tracing::info!(
                            "[{}/{}] SBOP data: len={}, first 50: {:?}, last 50: {:02x?}",
                            block_number, tx.index, tx.data.len(),
                            String::from_utf8_lossy(&first_bytes),
                            last_bytes
                        );
                    }
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
                            let light_mode = self.light_mode; // Copy to avoid borrow checker issues
                            for repo in matching_repos {
                                let uri = repo.uri.to_string();
                                if let Ok(state_db) = self.get_state_db(&uri) {
                                    // In light mode: use cryptographic verification and store proven state roots
                                    // In normal mode: verify against existing computed state
                                    let verified = if light_mode {
                                        match verify_proof_light_mode(&sbop) {
                                            Ok(Some(output)) => {
                                                // Store the proven state root from the verified proof
                                                if let Err(e) = state_db.record_state_root(
                                                    output.block_to,
                                                    output.new_state_root
                                                ) {
                                                    tracing::warn!(
                                                        "Failed to store proven state root for {}: {}",
                                                        uri, e
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        "Light mode: stored proven state root {} at block {} for {}",
                                                        hex::encode(&output.new_state_root[..4]),
                                                        output.block_to,
                                                        uri
                                                    );
                                                }
                                                true
                                            }
                                            Ok(None) => false,
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Light mode verification error for {}: {}",
                                                    uri, e
                                                );
                                                false
                                            }
                                        }
                                    } else {
                                        // Normal mode: verify against existing state
                                        match verify_proof(&sbop, state_db) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to verify proof for {}: {}",
                                                    uri, e
                                                );
                                                false
                                            }
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
                        self.write_object(repo, msg, block_number, &mut touched_objects)?;
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

        // Track the post-state root and genesis status for the result
        let mut post_state_root = [0u8; 32];
        let mut has_genesis = false;

        for uri in uris {
            if let Some(state_db) = self.state_dbs.get(&uri) {
                // Check if genesis has been processed (any objects exist)
                has_genesis = state_db.has_objects().unwrap_or(false);

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

                // Capture for result
                post_state_root = new_root;

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

        // Generate state transition witness from pre_trie and touched_objects
        // Use pre_state_root (computed from trie) - this matches what proofs are generated against
        let state_witness = generate_witness(&pre_trie, &touched_objects, pre_state_root);

        Ok(BlockProcessResult {
            tx_count,
            pre_state_root: pre_state_root_opt,
            post_state_root,
            block_data: raw_block_data,
            has_genesis,
            state_witness,
        })
    }

    /// Write an SBO object to the filesystem and update state
    fn write_object(
        &mut self,
        repo: &Repo,
        msg: &sbo_core::message::Message,
        block_number: u64,
        touched: &mut TouchedObjects,
    ) -> crate::Result<()> {
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

        // Check if object exists and track the touch operation
        let uri = repo.uri.to_string();
        if let Some(state_db) = self.state_dbs.get(&uri) {
            // Get the creator ID using the same resolution as message_to_stored_object
            // This ensures witness path segments match what gets stored in the database
            let creator = resolve_creator(msg, Some(state_db));

            // Build path segments for witness tracking
            let path_segments = StateDb::object_to_segments(&msg.path, &creator, &msg.id);
            // Use get_first_object_at_path_id to find existing object regardless of creator
            let existing = state_db.get_first_object_at_path_id(&msg.path, &msg.id).ok().flatten();

            if matches!(msg.action, sbo_core::message::Action::Delete) {
                // Delete operation
                if let Some(old_obj) = existing {
                    touched.deletes.push(TouchedDelete {
                        path_segments: path_segments.clone(),
                        old_object_hash: old_obj.object_hash,
                    });
                }
            } else if let Some(old_obj) = existing {
                // Update operation (object existed)
                touched.updates.push(TouchedUpdate {
                    path_segments: path_segments.clone(),
                    old_object_hash: old_obj.object_hash,
                    new_object_hash: object_hash,
                });
            } else {
                // Create operation (object didn't exist)
                touched.creates.push(TouchedCreate {
                    path_segments: path_segments.clone(),
                    new_object_hash: object_hash,
                });
            }
        }

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
