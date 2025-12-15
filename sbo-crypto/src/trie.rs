//! Sparse Path-Segment Trie for SBO State Commitment
//!
//! Implements a hierarchical trie where tree structure mirrors path structure.
//! Each node has children keyed by segment name, with values being either
//! child node hashes or object hashes (for leaves).
//!
//! Node serialization format (canonical JSON):
//! ```json
//! {"children":{"segment1":"sha256:...","segment2":"sha256:..."}}
//! ```

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::sha256;

/// Error type for trie operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieError {
    InvalidProof,
    PathNotFound,
    RootMismatch,
    InvalidSegment(String),
    EmptyPath,
}

impl core::fmt::Display for TrieError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "Invalid trie proof"),
            Self::PathNotFound => write!(f, "Path not found in trie"),
            Self::RootMismatch => write!(f, "Trie root mismatch"),
            Self::InvalidSegment(s) => write!(f, "Invalid segment: {}", s),
            Self::EmptyPath => write!(f, "Empty path"),
        }
    }
}

/// A node in the sparse path-segment trie
///
/// Each node contains a map of segment names to hashes.
/// The hash can be either:
/// - Another node's hash (for internal nodes)
/// - An object_hash (for leaf nodes - the final segment)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrieNode {
    /// Map of segment name to hash
    pub children: BTreeMap<String, [u8; 32]>,
}

impl TrieNode {
    pub fn new() -> Self {
        Self { children: BTreeMap::new() }
    }

    /// Serialize to deterministic JSON for hashing
    /// Format: {"children":{"a":"sha256:...","b":"sha256:..."}}
    /// Keys are sorted lexicographically (BTreeMap guarantees this)
    /// No whitespace
    pub fn to_canonical_json(&self) -> Vec<u8> {
        let mut json = String::from(r#"{"children":{"#);
        let mut first = true;
        for (segment, hash) in &self.children {
            if !first {
                json.push(',');
            }
            first = false;
            json.push('"');
            json.push_str(&escape_json_string(segment));
            json.push_str(r#"":"sha256:"#);
            json.push_str(&hex_encode(hash));
            json.push('"');
        }
        json.push_str("}}");
        json.into_bytes()
    }

    /// Compute node hash = sha256(canonical_json)
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.to_canonical_json())
    }

    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

/// A single step in a trie proof
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrieProofStep {
    /// The segment taken at this level (None for non-existence proof at this level)
    pub segment: Option<String>,
    /// Sibling hashes at this level (other children of the parent node)
    pub siblings: BTreeMap<String, [u8; 32]>,
}

/// Complete trie proof for object inclusion/non-existence
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrieProof {
    /// State root this proof is anchored to
    pub state_root: [u8; 32],
    /// Path segments being proven
    pub path_segments: Vec<String>,
    /// Object hash at the path (None for non-existence proof)
    pub object_hash: Option<[u8; 32]>,
    /// Proof steps from root to leaf
    pub proof: Vec<TrieProofStep>,
}

// ============================================================================
// Witness Types for State Transitions
// ============================================================================

/// Witness for a single object state change
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ObjectWitness {
    /// Object created - didn't exist before
    Create {
        path_segments: Vec<String>,
        new_object_hash: [u8; 32],
        /// Proves path wasn't in prev_state
        nonexistence_proof: TrieProof,
    },

    /// Object updated - existed with old hash
    Update {
        path_segments: Vec<String>,
        old_object_hash: [u8; 32],
        new_object_hash: [u8; 32],
        /// Proves old object was in prev_state
        inclusion_proof: TrieProof,
    },

    /// Object deleted - existed before
    Delete {
        path_segments: Vec<String>,
        old_object_hash: [u8; 32],
        /// Proves old object was in prev_state
        inclusion_proof: TrieProof,
    },
}

impl ObjectWitness {
    /// Get the path segments for this witness
    pub fn path_segments(&self) -> &[String] {
        match self {
            ObjectWitness::Create { path_segments, .. } => path_segments,
            ObjectWitness::Update { path_segments, .. } => path_segments,
            ObjectWitness::Delete { path_segments, .. } => path_segments,
        }
    }

    /// Get the new object hash (None for Delete)
    pub fn new_hash(&self) -> Option<[u8; 32]> {
        match self {
            ObjectWitness::Create { new_object_hash, .. } => Some(*new_object_hash),
            ObjectWitness::Update { new_object_hash, .. } => Some(*new_object_hash),
            ObjectWitness::Delete { .. } => None,
        }
    }
}

/// Hint for reconstructing sibling hashes when multiple witnesses share path prefixes
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SiblingHint {
    /// The path to the parent node containing this sibling
    pub parent_path: Vec<String>,
    /// The sibling's segment name
    pub sibling_segment: String,
    /// The sibling's hash
    pub sibling_hash: [u8; 32],
}

/// Complete witness for a state transition
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateTransitionWitness {
    /// State root before the transition
    pub prev_state_root: [u8; 32],
    /// Individual object witnesses
    pub witnesses: Vec<ObjectWitness>,
    /// Additional sibling hints for shared path prefixes
    pub sibling_hints: Vec<SiblingHint>,
}

impl Default for StateTransitionWitness {
    fn default() -> Self {
        Self {
            prev_state_root: [0u8; 32],
            witnesses: Vec::new(),
            sibling_hints: Vec::new(),
        }
    }
}

// ============================================================================
// Partial Trie for Witness Verification
// ============================================================================

/// A partial trie that can be constructed from proofs and incrementally updated
#[derive(Debug, Clone)]
pub struct PartialTrie {
    root: Option<PartialNode>,
    known_root_hash: [u8; 32],
}

/// Node in a partial trie
#[derive(Debug, Clone)]
enum PartialNode {
    /// A node with all children known
    Complete {
        children: BTreeMap<String, PartialNode>,
    },
    /// A node with some children known and others as hash stubs
    Partial {
        known_children: BTreeMap<String, PartialNode>,
        sibling_hashes: BTreeMap<String, [u8; 32]>,
    },
    /// A leaf node containing an object hash
    Leaf {
        object_hash: [u8; 32],
    },
    /// An unexpanded subtree represented only by its hash
    Stub {
        hash: [u8; 32],
    },
}

impl PartialTrie {
    /// Create an empty partial trie
    pub fn new(known_root_hash: [u8; 32]) -> Self {
        if known_root_hash == [0u8; 32] {
            Self {
                root: None,
                known_root_hash,
            }
        } else {
            Self {
                root: Some(PartialNode::Stub { hash: known_root_hash }),
                known_root_hash,
            }
        }
    }

    /// Expand a path in the trie using proof data
    /// This merges the proof path into the existing partial trie structure
    pub fn expand_from_proof(&mut self, proof: &TrieProof) -> Result<(), TrieError> {
        if proof.state_root != self.known_root_hash {
            return Err(TrieError::RootMismatch);
        }

        if proof.proof.is_empty() {
            return Ok(());
        }

        // Build the path structure from the proof
        let new_path = Self::build_path_from_proof(
            &proof.proof,
            &proof.path_segments,
            proof.object_hash,
            0,
        )?;

        // Merge into existing structure instead of replacing
        match &mut self.root {
            None => {
                self.root = Some(new_path);
            }
            Some(existing) => {
                Self::merge_nodes(existing, new_path);
            }
        }

        Ok(())
    }

    /// Merge two partial nodes, combining their children
    fn merge_nodes(existing: &mut PartialNode, new_node: PartialNode) {
        match (existing, new_node) {
            // Both are Partial - merge children and siblings
            (
                PartialNode::Partial {
                    known_children: existing_children,
                    sibling_hashes: existing_siblings,
                },
                PartialNode::Partial {
                    known_children: new_children,
                    sibling_hashes: new_siblings,
                },
            ) => {
                // Merge sibling hashes (new ones take precedence if different)
                for (seg, hash) in new_siblings {
                    // Only add if not already a known child
                    if !existing_children.contains_key(&seg) {
                        existing_siblings.insert(seg, hash);
                    }
                }

                // Merge known children recursively
                for (seg, new_child) in new_children {
                    // Remove from siblings if it was there
                    existing_siblings.remove(&seg);

                    if let Some(existing_child) = existing_children.get_mut(&seg) {
                        Self::merge_nodes(existing_child, new_child);
                    } else {
                        existing_children.insert(seg, new_child);
                    }
                }
            }
            // Existing is a Stub - replace with new detailed structure
            (existing @ PartialNode::Stub { .. }, new_node) => {
                *existing = new_node;
            }
            // New is a Stub but existing has detail - keep existing
            (_, PartialNode::Stub { .. }) => {
                // Keep existing, it has more detail
            }
            // Both are Leaves - they should have same hash
            (PartialNode::Leaf { .. }, PartialNode::Leaf { .. }) => {
                // Keep existing
            }
            // Mixed cases - prefer the Partial node
            (existing @ PartialNode::Leaf { .. }, new_node @ PartialNode::Partial { .. }) => {
                *existing = new_node;
            }
            (PartialNode::Partial { .. }, PartialNode::Leaf { .. }) => {
                // Keep existing Partial
            }
            // Complete nodes - merge children
            (
                PartialNode::Complete { children: existing_children },
                PartialNode::Complete { children: new_children },
            ) => {
                for (seg, new_child) in new_children {
                    if let Some(existing_child) = existing_children.get_mut(&seg) {
                        Self::merge_nodes(existing_child, new_child);
                    } else {
                        existing_children.insert(seg, new_child);
                    }
                }
            }
            // Complete + Partial - convert to Partial and merge
            (
                existing @ PartialNode::Complete { .. },
                PartialNode::Partial { known_children: new_children, sibling_hashes: new_siblings },
            ) => {
                if let PartialNode::Complete { children } = core::mem::replace(existing, PartialNode::Partial {
                    known_children: BTreeMap::new(),
                    sibling_hashes: BTreeMap::new(),
                }) {
                    if let PartialNode::Partial { known_children, sibling_hashes } = existing {
                        *known_children = children;
                        *sibling_hashes = new_siblings;
                        for (seg, new_child) in new_children {
                            if let Some(existing_child) = known_children.get_mut(&seg) {
                                Self::merge_nodes(existing_child, new_child);
                            } else {
                                known_children.insert(seg, new_child);
                            }
                        }
                    }
                }
            }
            (
                PartialNode::Partial { known_children, sibling_hashes: _ },
                PartialNode::Complete { children: new_children },
            ) => {
                for (seg, new_child) in new_children {
                    if let Some(existing_child) = known_children.get_mut(&seg) {
                        Self::merge_nodes(existing_child, new_child);
                    } else {
                        known_children.insert(seg, new_child);
                    }
                }
            }
            // Complete + Leaf: keep existing (invalid combination, shouldn't happen)
            (PartialNode::Complete { .. }, PartialNode::Leaf { .. }) => {
                // Keep existing - a path with children can't also be a leaf
            }
            // Leaf + Complete: keep existing (invalid combination, shouldn't happen)
            (PartialNode::Leaf { .. }, PartialNode::Complete { .. }) => {
                // Keep existing - a leaf can't have children
            }
        }
    }

    /// Build a partial path from proof steps
    fn build_path_from_proof(
        steps: &[TrieProofStep],
        segments: &[String],
        object_hash: Option<[u8; 32]>,
        depth: usize,
    ) -> Result<PartialNode, TrieError> {
        if depth >= steps.len() {
            // Reached the end of the proof
            return match object_hash {
                Some(hash) => Ok(PartialNode::Leaf { object_hash: hash }),
                None => Ok(PartialNode::Partial {
                    known_children: BTreeMap::new(),
                    sibling_hashes: BTreeMap::new(),
                }),
            };
        }

        let step = &steps[depth];

        // At the last step and we have an object hash, the next level is a leaf
        if depth == steps.len() - 1 && object_hash.is_some() {
            let segment = step.segment.as_ref().ok_or(TrieError::InvalidProof)?;
            let mut known_children = BTreeMap::new();
            known_children.insert(
                segment.clone(),
                PartialNode::Leaf {
                    object_hash: object_hash.unwrap(),
                },
            );

            return Ok(PartialNode::Partial {
                known_children,
                sibling_hashes: step.siblings.clone(),
            });
        }

        match &step.segment {
            Some(segment) => {
                // Continue down the path
                let child = Self::build_path_from_proof(steps, segments, object_hash, depth + 1)?;

                let mut known_children = BTreeMap::new();
                known_children.insert(segment.clone(), child);

                Ok(PartialNode::Partial {
                    known_children,
                    sibling_hashes: step.siblings.clone(),
                })
            }
            None => {
                // Non-existence proof divergence point
                Ok(PartialNode::Partial {
                    known_children: BTreeMap::new(),
                    sibling_hashes: step.siblings.clone(),
                })
            }
        }
    }

    /// Insert or update an object at the given path
    pub fn insert(&mut self, segments: &[String], object_hash: [u8; 32]) {
        if segments.is_empty() {
            return;
        }

        match &mut self.root {
            None => {
                // Build new path
                self.root = Some(Self::build_new_path(segments, object_hash));
            }
            Some(node) => {
                Self::insert_into_node(node, segments, object_hash);
            }
        }
    }

    /// Build a new path ending in a leaf
    fn build_new_path(segments: &[String], object_hash: [u8; 32]) -> PartialNode {
        if segments.len() == 1 {
            let mut known_children = BTreeMap::new();
            known_children.insert(
                segments[0].clone(),
                PartialNode::Leaf { object_hash },
            );
            PartialNode::Partial {
                known_children,
                sibling_hashes: BTreeMap::new(),
            }
        } else {
            let child = Self::build_new_path(&segments[1..], object_hash);
            let mut known_children = BTreeMap::new();
            known_children.insert(segments[0].clone(), child);
            PartialNode::Partial {
                known_children,
                sibling_hashes: BTreeMap::new(),
            }
        }
    }

    /// Insert into an existing node
    fn insert_into_node(node: &mut PartialNode, segments: &[String], object_hash: [u8; 32]) {
        if segments.is_empty() {
            return;
        }

        match node {
            PartialNode::Leaf { .. } | PartialNode::Stub { .. } => {
                // Replace with a new path
                *node = Self::build_new_path(segments, object_hash);
            }
            PartialNode::Complete { children } => {
                let segment = &segments[0];
                if segments.len() == 1 {
                    children.insert(segment.clone(), PartialNode::Leaf { object_hash });
                } else if let Some(child) = children.get_mut(segment) {
                    Self::insert_into_node(child, &segments[1..], object_hash);
                } else {
                    let child = Self::build_new_path(&segments[1..], object_hash);
                    children.insert(segment.clone(), child);
                }
            }
            PartialNode::Partial {
                known_children,
                sibling_hashes,
            } => {
                let segment = &segments[0];
                // Remove from sibling_hashes if it was there (it's now being expanded)
                sibling_hashes.remove(segment);

                if segments.len() == 1 {
                    known_children.insert(segment.clone(), PartialNode::Leaf { object_hash });
                } else if let Some(child) = known_children.get_mut(segment) {
                    Self::insert_into_node(child, &segments[1..], object_hash);
                } else {
                    let child = Self::build_new_path(&segments[1..], object_hash);
                    known_children.insert(segment.clone(), child);
                }
            }
        }
    }

    /// Delete an object at the given path
    pub fn delete(&mut self, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match &mut self.root {
            None => false,
            Some(node) => {
                let deleted = Self::delete_from_node(node, segments);
                // Check if root is now empty
                if let PartialNode::Partial {
                    known_children,
                    sibling_hashes,
                } = node
                {
                    if known_children.is_empty() && sibling_hashes.is_empty() {
                        self.root = None;
                    }
                }
                deleted
            }
        }
    }

    /// Delete from a node
    fn delete_from_node(node: &mut PartialNode, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match node {
            PartialNode::Leaf { .. } | PartialNode::Stub { .. } => false,
            PartialNode::Complete { children } => {
                let segment = &segments[0];
                if segments.len() == 1 {
                    children.remove(segment).is_some()
                } else if let Some(child) = children.get_mut(segment) {
                    let deleted = Self::delete_from_node(child, &segments[1..]);
                    // Clean up empty children
                    if let PartialNode::Partial {
                        known_children,
                        sibling_hashes,
                    } = child
                    {
                        if known_children.is_empty() && sibling_hashes.is_empty() {
                            children.remove(segment);
                        }
                    }
                    deleted
                } else {
                    false
                }
            }
            PartialNode::Partial {
                known_children,
                sibling_hashes: _,
            } => {
                let segment = &segments[0];
                if segments.len() == 1 {
                    known_children.remove(segment).is_some()
                } else if let Some(child) = known_children.get_mut(segment) {
                    let deleted = Self::delete_from_node(child, &segments[1..]);
                    // Clean up empty children
                    if let PartialNode::Partial {
                        known_children: child_known,
                        sibling_hashes: child_sibs,
                    } = child
                    {
                        if child_known.is_empty() && child_sibs.is_empty() {
                            known_children.remove(segment);
                        }
                    }
                    deleted
                } else {
                    false
                }
            }
        }
    }

    /// Compute the root hash of the partial trie
    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            None => [0u8; 32],
            Some(node) => Self::compute_node_hash(node),
        }
    }

    /// Compute hash for a partial node
    fn compute_node_hash(node: &PartialNode) -> [u8; 32] {
        match node {
            PartialNode::Leaf { object_hash } => *object_hash,
            PartialNode::Stub { hash } => *hash,
            PartialNode::Complete { children } => {
                let mut trie_node = TrieNode::new();
                for (segment, child) in children {
                    trie_node
                        .children
                        .insert(segment.clone(), Self::compute_node_hash(child));
                }
                trie_node.hash()
            }
            PartialNode::Partial {
                known_children,
                sibling_hashes,
            } => {
                let mut trie_node = TrieNode::new();
                // Add sibling hashes (these are already computed)
                for (segment, hash) in sibling_hashes {
                    trie_node.children.insert(segment.clone(), *hash);
                }
                // Add known children (need to compute their hashes)
                for (segment, child) in known_children {
                    trie_node
                        .children
                        .insert(segment.clone(), Self::compute_node_hash(child));
                }
                trie_node.hash()
            }
        }
    }
}

// ============================================================================
// State Transition Verification
// ============================================================================

/// Verify a state transition and compute the new state root
///
/// This function:
/// 1. Verifies each object witness against prev_state_root
/// 2. Applies all changes to a partial trie
/// 3. Returns the new state root
pub fn verify_state_transition(witness: &StateTransitionWitness) -> Result<[u8; 32], TrieError> {
    // For empty witness, return the same state root
    if witness.witnesses.is_empty() {
        return Ok(witness.prev_state_root);
    }

    // Step 1: Verify all proofs against prev_state_root
    for obj_witness in &witness.witnesses {
        verify_object_witness(obj_witness, witness.prev_state_root)?;
    }

    // Step 2: Build partial trie and apply changes
    let new_root = apply_witness_changes(witness)?;

    Ok(new_root)
}

/// Verify a single object witness against the expected state root
fn verify_object_witness(witness: &ObjectWitness, expected_root: [u8; 32]) -> Result<(), TrieError> {
    match witness {
        ObjectWitness::Create {
            nonexistence_proof, ..
        } => {
            // Verify path didn't exist
            if nonexistence_proof.state_root != expected_root {
                return Err(TrieError::RootMismatch);
            }
            if nonexistence_proof.object_hash.is_some() {
                return Err(TrieError::InvalidProof);
            }
            let valid = verify_trie_proof(nonexistence_proof)?;
            if !valid {
                return Err(TrieError::InvalidProof);
            }
        }
        ObjectWitness::Update {
            old_object_hash,
            inclusion_proof,
            ..
        } => {
            // Verify old object was present
            if inclusion_proof.state_root != expected_root {
                return Err(TrieError::RootMismatch);
            }
            if inclusion_proof.object_hash != Some(*old_object_hash) {
                return Err(TrieError::InvalidProof);
            }
            let valid = verify_trie_proof(inclusion_proof)?;
            if !valid {
                return Err(TrieError::InvalidProof);
            }
        }
        ObjectWitness::Delete {
            old_object_hash,
            inclusion_proof,
            ..
        } => {
            // Verify old object was present
            if inclusion_proof.state_root != expected_root {
                return Err(TrieError::RootMismatch);
            }
            if inclusion_proof.object_hash != Some(*old_object_hash) {
                return Err(TrieError::InvalidProof);
            }
            let valid = verify_trie_proof(inclusion_proof)?;
            if !valid {
                return Err(TrieError::InvalidProof);
            }
        }
    }
    Ok(())
}

/// Apply all witness changes to compute the new state root
fn apply_witness_changes(witness: &StateTransitionWitness) -> Result<[u8; 32], TrieError> {
    let mut partial_trie = PartialTrie::new(witness.prev_state_root);

    // First, expand all proofs into the partial trie
    for obj_witness in &witness.witnesses {
        let proof = match obj_witness {
            ObjectWitness::Create {
                nonexistence_proof, ..
            } => nonexistence_proof,
            ObjectWitness::Update {
                inclusion_proof, ..
            } => inclusion_proof,
            ObjectWitness::Delete {
                inclusion_proof, ..
            } => inclusion_proof,
        };
        partial_trie.expand_from_proof(proof)?;
    }

    // Add sibling hints
    for hint in &witness.sibling_hints {
        // These help when multiple witnesses share path prefixes
        // The partial trie needs to know about siblings that weren't in the proofs
        // This is handled during proof expansion, but hints can override
        // For now, we trust the proof expansion handles this correctly
        let _ = hint; // Reserved for future use
    }

    // Then, apply all changes
    for obj_witness in &witness.witnesses {
        match obj_witness {
            ObjectWitness::Create {
                path_segments,
                new_object_hash,
                ..
            } => {
                partial_trie.insert(path_segments, *new_object_hash);
            }
            ObjectWitness::Update {
                path_segments,
                new_object_hash,
                ..
            } => {
                partial_trie.insert(path_segments, *new_object_hash);
            }
            ObjectWitness::Delete { path_segments, .. } => {
                partial_trie.delete(path_segments);
            }
        }
    }

    Ok(partial_trie.root_hash())
}

/// In-memory sparse trie for building and proof generation
#[derive(Debug, Clone, Default)]
pub struct SparseTrie {
    root: Option<InternalNode>,
}

#[derive(Debug, Clone)]
enum InternalNode {
    /// Internal node with children
    Branch {
        children: BTreeMap<String, InternalNode>,
    },
    /// Leaf node containing object hash
    Leaf {
        object_hash: [u8; 32],
    },
}

impl SparseTrie {
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Insert or update an object at the given path segments
    pub fn insert(&mut self, segments: Vec<String>, object_hash: [u8; 32]) {
        if segments.is_empty() {
            return;
        }

        match &mut self.root {
            None => {
                // Create new trie from scratch
                self.root = Some(Self::build_path(&segments, object_hash));
            }
            Some(node) => {
                Self::insert_into(node, &segments, object_hash);
            }
        }
    }

    /// Build a path from segments ending in a leaf
    fn build_path(segments: &[String], object_hash: [u8; 32]) -> InternalNode {
        if segments.len() == 1 {
            // Last segment - create branch with leaf child
            let mut children = BTreeMap::new();
            children.insert(segments[0].clone(), InternalNode::Leaf { object_hash });
            InternalNode::Branch { children }
        } else {
            // More segments - create branch with nested child
            let mut children = BTreeMap::new();
            let child = Self::build_path(&segments[1..], object_hash);
            children.insert(segments[0].clone(), child);
            InternalNode::Branch { children }
        }
    }

    /// Insert into existing node
    fn insert_into(node: &mut InternalNode, segments: &[String], object_hash: [u8; 32]) {
        if segments.is_empty() {
            return;
        }

        match node {
            InternalNode::Leaf { .. } => {
                // Replace leaf with branch containing the new path
                // This shouldn't normally happen if paths are properly constructed
                *node = Self::build_path(segments, object_hash);
            }
            InternalNode::Branch { children } => {
                let segment = &segments[0];
                if segments.len() == 1 {
                    // This is the final segment - insert/update leaf
                    children.insert(segment.clone(), InternalNode::Leaf { object_hash });
                } else {
                    // More segments to go
                    if let Some(child) = children.get_mut(segment) {
                        // Child exists - recurse
                        Self::insert_into(child, &segments[1..], object_hash);
                    } else {
                        // Child doesn't exist - create path
                        let child = Self::build_path(&segments[1..], object_hash);
                        children.insert(segment.clone(), child);
                    }
                }
            }
        }
    }

    /// Delete an object at the given path segments
    /// Returns true if something was deleted
    pub fn delete(&mut self, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match &mut self.root {
            None => false,
            Some(node) => {
                let deleted = Self::delete_from(node, segments);
                // Clean up empty root
                if let InternalNode::Branch { children } = node {
                    if children.is_empty() {
                        self.root = None;
                    }
                }
                deleted
            }
        }
    }

    /// Delete from a node, returns true if deleted
    fn delete_from(node: &mut InternalNode, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match node {
            InternalNode::Leaf { .. } => false,
            InternalNode::Branch { children } => {
                let segment = &segments[0];
                if segments.len() == 1 {
                    // Remove this segment
                    children.remove(segment).is_some()
                } else {
                    // Recurse
                    if let Some(child) = children.get_mut(segment) {
                        let deleted = Self::delete_from(child, &segments[1..]);
                        // Clean up empty branches
                        if let InternalNode::Branch { children: child_children } = child {
                            if child_children.is_empty() {
                                children.remove(segment);
                            }
                        }
                        deleted
                    } else {
                        false
                    }
                }
            }
        }
    }

    /// Compute the root hash of the trie
    /// Returns [0u8; 32] for empty trie
    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            None => [0u8; 32],
            Some(node) => Self::compute_hash(node),
        }
    }

    /// Compute hash for a node
    fn compute_hash(node: &InternalNode) -> [u8; 32] {
        match node {
            InternalNode::Leaf { object_hash } => *object_hash,
            InternalNode::Branch { children } => {
                let mut trie_node = TrieNode::new();
                for (segment, child) in children {
                    let child_hash = Self::compute_hash(child);
                    trie_node.children.insert(segment.clone(), child_hash);
                }
                trie_node.hash()
            }
        }
    }

    /// Generate an inclusion proof for an existing object
    pub fn generate_proof(&self, segments: &[String]) -> Result<TrieProof, TrieError> {
        if segments.is_empty() {
            return Err(TrieError::EmptyPath);
        }

        let root = self.root.as_ref().ok_or(TrieError::PathNotFound)?;
        let state_root = self.root_hash();

        let mut proof_steps = Vec::new();
        let object_hash = Self::collect_proof(root, segments, &mut proof_steps)?;

        Ok(TrieProof {
            state_root,
            path_segments: segments.to_vec(),
            object_hash: Some(object_hash),
            proof: proof_steps,
        })
    }

    /// Collect proof steps while traversing to the target
    fn collect_proof(
        node: &InternalNode,
        segments: &[String],
        proof_steps: &mut Vec<TrieProofStep>,
    ) -> Result<[u8; 32], TrieError> {
        if segments.is_empty() {
            return Err(TrieError::EmptyPath);
        }

        match node {
            InternalNode::Leaf { object_hash: _ } => {
                // Shouldn't reach a leaf before exhausting segments
                Err(TrieError::PathNotFound)
            }
            InternalNode::Branch { children } => {
                let segment = &segments[0];

                // Collect siblings (all children except the one we're following)
                let mut siblings = BTreeMap::new();
                for (child_seg, child_node) in children {
                    if child_seg != segment {
                        siblings.insert(child_seg.clone(), Self::compute_hash(child_node));
                    }
                }

                // Add this step
                proof_steps.push(TrieProofStep {
                    segment: Some(segment.clone()),
                    siblings,
                });

                // Get the child we're following
                let child = children.get(segment).ok_or(TrieError::PathNotFound)?;

                if segments.len() == 1 {
                    // This should be a leaf
                    match child {
                        InternalNode::Leaf { object_hash } => Ok(*object_hash),
                        InternalNode::Branch { .. } => Err(TrieError::PathNotFound),
                    }
                } else {
                    // Continue traversing
                    Self::collect_proof(child, &segments[1..], proof_steps)
                }
            }
        }
    }

    /// Generate a non-existence proof
    pub fn generate_nonexistence_proof(&self, segments: &[String]) -> Result<TrieProof, TrieError> {
        if segments.is_empty() {
            return Err(TrieError::EmptyPath);
        }

        let state_root = self.root_hash();
        let mut proof_steps = Vec::new();

        match &self.root {
            None => {
                // Empty trie - path trivially doesn't exist
                proof_steps.push(TrieProofStep {
                    segment: None,
                    siblings: BTreeMap::new(),
                });
            }
            Some(node) => {
                Self::collect_nonexistence_proof(node, segments, &mut proof_steps)?;
            }
        }

        Ok(TrieProof {
            state_root,
            path_segments: segments.to_vec(),
            object_hash: None,
            proof: proof_steps,
        })
    }

    /// Collect non-existence proof steps
    fn collect_nonexistence_proof(
        node: &InternalNode,
        segments: &[String],
        proof_steps: &mut Vec<TrieProofStep>,
    ) -> Result<(), TrieError> {
        if segments.is_empty() {
            return Err(TrieError::EmptyPath);
        }

        match node {
            InternalNode::Leaf { .. } => {
                // Hit a leaf before exhausting path - path doesn't exist
                proof_steps.push(TrieProofStep {
                    segment: None,
                    siblings: BTreeMap::new(),
                });
                Ok(())
            }
            InternalNode::Branch { children } => {
                let segment = &segments[0];

                if !children.contains_key(segment) {
                    // Path diverges here - this is where non-existence is proven
                    let mut siblings = BTreeMap::new();
                    for (child_seg, child_node) in children {
                        siblings.insert(child_seg.clone(), Self::compute_hash(child_node));
                    }
                    proof_steps.push(TrieProofStep {
                        segment: None,
                        siblings,
                    });
                    Ok(())
                } else {
                    // Segment exists - collect siblings and continue
                    let mut siblings = BTreeMap::new();
                    for (child_seg, child_node) in children {
                        if child_seg != segment {
                            siblings.insert(child_seg.clone(), Self::compute_hash(child_node));
                        }
                    }
                    proof_steps.push(TrieProofStep {
                        segment: Some(segment.clone()),
                        siblings,
                    });

                    let child = children.get(segment).unwrap();
                    if segments.len() == 1 {
                        // Expected more path but this is a branch not pointing to our target
                        // Or it's a leaf (which means the path exists as something else)
                        match child {
                            InternalNode::Leaf { .. } => {
                                // Path exists! This shouldn't be called for existing paths
                                Err(TrieError::InvalidProof)
                            }
                            InternalNode::Branch { .. } => {
                                // Path continues but we expected a leaf here
                                Err(TrieError::InvalidProof)
                            }
                        }
                    } else {
                        Self::collect_nonexistence_proof(child, &segments[1..], proof_steps)
                    }
                }
            }
        }
    }

    /// Check if a path exists in the trie
    pub fn contains(&self, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match &self.root {
            None => false,
            Some(node) => Self::contains_path(node, segments),
        }
    }

    fn contains_path(node: &InternalNode, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match node {
            InternalNode::Leaf { .. } => false,
            InternalNode::Branch { children } => {
                let segment = &segments[0];
                match children.get(segment) {
                    None => false,
                    Some(child) => {
                        if segments.len() == 1 {
                            matches!(child, InternalNode::Leaf { .. })
                        } else {
                            Self::contains_path(child, &segments[1..])
                        }
                    }
                }
            }
        }
    }
}

/// Compute trie root from a collection of objects
/// Each object is represented as (path_segments, object_hash)
pub fn compute_trie_root(objects: &[(Vec<String>, [u8; 32])]) -> [u8; 32] {
    let mut trie = SparseTrie::new();
    for (segments, object_hash) in objects {
        trie.insert(segments.clone(), *object_hash);
    }
    trie.root_hash()
}

/// Verify a trie proof
pub fn verify_trie_proof(proof: &TrieProof) -> Result<bool, TrieError> {
    // Special case: empty proof against empty state
    // If state_root is all zeros (empty state), any path trivially doesn't exist
    if proof.proof.is_empty() {
        if proof.state_root == [0u8; 32] && proof.object_hash.is_none() {
            // Valid non-existence proof for empty state
            return Ok(true);
        }
        return Err(TrieError::InvalidProof);
    }

    match &proof.object_hash {
        Some(object_hash) => verify_inclusion_proof(proof, *object_hash),
        None => verify_nonexistence_proof(proof),
    }
}

/// Verify an inclusion proof
fn verify_inclusion_proof(proof: &TrieProof, object_hash: [u8; 32]) -> Result<bool, TrieError> {
    if proof.proof.len() != proof.path_segments.len() {
        return Err(TrieError::InvalidProof);
    }

    // Start from the leaf (object_hash) and work up to the root
    let mut current_hash = object_hash;

    // Process proof steps from bottom to top (reverse order)
    for (i, step) in proof.proof.iter().enumerate().rev() {
        let segment = step.segment.as_ref().ok_or(TrieError::InvalidProof)?;

        // Verify segment matches expected path
        if segment != &proof.path_segments[i] {
            return Err(TrieError::InvalidProof);
        }

        // Reconstruct the node: siblings + {segment: current_hash}
        let mut node = TrieNode::new();
        for (sib_seg, sib_hash) in &step.siblings {
            node.children.insert(sib_seg.clone(), *sib_hash);
        }
        node.children.insert(segment.clone(), current_hash);

        // Compute this node's hash
        current_hash = node.hash();
    }

    // Final hash must match state root
    Ok(current_hash == proof.state_root)
}

/// Verify a non-existence proof
fn verify_nonexistence_proof(proof: &TrieProof) -> Result<bool, TrieError> {
    if proof.proof.is_empty() {
        return Err(TrieError::InvalidProof);
    }

    // Find where the path diverges (segment is None)
    let diverge_idx = proof.proof.iter().position(|s| s.segment.is_none());

    match diverge_idx {
        None => {
            // No divergence point found - invalid non-existence proof
            Err(TrieError::InvalidProof)
        }
        Some(idx) => {
            // Verify the target segment is NOT in siblings at divergence point
            let expected_segment = &proof.path_segments[idx];
            let diverge_step = &proof.proof[idx];

            if diverge_step.siblings.contains_key(expected_segment) {
                // The segment exists! Invalid non-existence proof
                return Err(TrieError::InvalidProof);
            }

            // Build node from siblings at divergence
            let mut node = TrieNode::new();
            for (sib_seg, sib_hash) in &diverge_step.siblings {
                node.children.insert(sib_seg.clone(), *sib_hash);
            }
            let mut current_hash = if node.is_empty() {
                // Empty node at divergence - this is valid for completely missing subtree
                // But we need to handle the special case of empty trie
                if idx == 0 && proof.proof.len() == 1 {
                    // Empty trie case
                    return Ok(proof.state_root == [0u8; 32]);
                }
                node.hash()
            } else {
                node.hash()
            };

            // Now verify from divergence point up to root
            for i in (0..idx).rev() {
                let step = &proof.proof[i];
                let segment = step.segment.as_ref().ok_or(TrieError::InvalidProof)?;

                // Reconstruct the node
                let mut node = TrieNode::new();
                for (sib_seg, sib_hash) in &step.siblings {
                    node.children.insert(sib_seg.clone(), *sib_hash);
                }
                node.children.insert(segment.clone(), current_hash);
                current_hash = node.hash();
            }

            Ok(current_hash == proof.state_root)
        }
    }
}

/// Escape special characters for JSON string
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Simple hex encoding (avoids dependency on hex crate in no_std)
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_node_canonical_json() {
        let mut node = TrieNode::new();
        node.children.insert("alice".to_string(), [0x11; 32]);
        node.children.insert("bob".to_string(), [0x22; 32]);

        let json = node.to_canonical_json();
        let json_str = core::str::from_utf8(&json).unwrap();

        // Keys must be sorted lexicographically
        assert!(json_str.contains(r#""alice":"sha256:"#));
        assert!(json_str.find("alice").unwrap() < json_str.find("bob").unwrap());
        // No whitespace
        assert!(!json_str.contains(' '));
        // Proper format
        assert!(json_str.starts_with(r#"{"children":{"#));
        assert!(json_str.ends_with("}}"));
    }

    #[test]
    fn test_trie_node_hash_deterministic() {
        let mut node1 = TrieNode::new();
        node1.children.insert("a".to_string(), [1; 32]);
        node1.children.insert("b".to_string(), [2; 32]);

        let mut node2 = TrieNode::new();
        // Insert in different order
        node2.children.insert("b".to_string(), [2; 32]);
        node2.children.insert("a".to_string(), [1; 32]);

        assert_eq!(node1.hash(), node2.hash());
    }

    #[test]
    fn test_sparse_trie_insert_and_root() {
        let mut trie = SparseTrie::new();

        // Empty trie
        assert_eq!(trie.root_hash(), [0u8; 32]);

        // Insert one object
        trie.insert(vec!["sys".to_string(), "names".to_string(), "user1".to_string(), "alice".to_string()], [1; 32]);
        let root1 = trie.root_hash();
        assert_ne!(root1, [0u8; 32]);

        // Insert another object
        trie.insert(vec!["sys".to_string(), "names".to_string(), "user2".to_string(), "bob".to_string()], [2; 32]);
        let root2 = trie.root_hash();
        assert_ne!(root2, root1);
    }

    #[test]
    fn test_inclusion_proof_roundtrip() {
        let mut trie = SparseTrie::new();
        trie.insert(vec!["sys".to_string(), "names".to_string(), "user1".to_string(), "alice".to_string()], [1; 32]);
        trie.insert(vec!["sys".to_string(), "names".to_string(), "user2".to_string(), "bob".to_string()], [2; 32]);

        // Generate proof for alice
        let proof = trie.generate_proof(&["sys".to_string(), "names".to_string(), "user1".to_string(), "alice".to_string()]).unwrap();

        assert_eq!(proof.object_hash, Some([1; 32]));
        assert!(verify_trie_proof(&proof).unwrap());
    }

    #[test]
    fn test_compute_trie_root() {
        let objects = vec![
            (vec!["a".to_string(), "b".to_string()], [1; 32]),
            (vec!["a".to_string(), "c".to_string()], [2; 32]),
        ];

        let root = compute_trie_root(&objects);
        assert_ne!(root, [0u8; 32]);

        // Same objects in different order should produce same root
        let objects2 = vec![
            (vec!["a".to_string(), "c".to_string()], [2; 32]),
            (vec!["a".to_string(), "b".to_string()], [1; 32]),
        ];
        let root2 = compute_trie_root(&objects2);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_delete() {
        let mut trie = SparseTrie::new();
        trie.insert(vec!["a".to_string(), "b".to_string()], [1; 32]);
        trie.insert(vec!["a".to_string(), "c".to_string()], [2; 32]);

        assert!(trie.contains(&["a".to_string(), "b".to_string()]));

        trie.delete(&["a".to_string(), "b".to_string()]);

        assert!(!trie.contains(&["a".to_string(), "b".to_string()]));
        assert!(trie.contains(&["a".to_string(), "c".to_string()]));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[0x12, 0x34]), "1234");
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_witness_creates_with_shared_prefix() {
        // Test that witness verification correctly handles multiple creates
        // with shared path prefixes (like /sys/names and /sys/policies)

        // Start with empty state
        let empty_root = [0u8; 32];

        // Create paths that share the "sys" prefix
        let path1 = vec!["sys".to_string(), "names".to_string(), "sys".to_string()];
        let path2 = vec!["sys".to_string(), "policies".to_string(), "root".to_string()];
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        // Build expected state using full trie
        let mut expected_trie = SparseTrie::new();
        expected_trie.insert(path1.clone(), hash1);
        expected_trie.insert(path2.clone(), hash2);
        let expected_root = expected_trie.root_hash();

        // Generate non-existence proofs from empty state (since we're creating)
        // For creates from empty state, proofs are trivial
        let proof1 = TrieProof {
            state_root: empty_root,
            path_segments: path1.clone(),
            object_hash: None,
            proof: vec![],
        };
        let proof2 = TrieProof {
            state_root: empty_root,
            path_segments: path2.clone(),
            object_hash: None,
            proof: vec![],
        };

        // Build witness with two creates that share "sys" prefix
        let witness = StateTransitionWitness {
            prev_state_root: empty_root,
            witnesses: vec![
                ObjectWitness::Create {
                    path_segments: path1,
                    new_object_hash: hash1,
                    nonexistence_proof: proof1,
                },
                ObjectWitness::Create {
                    path_segments: path2,
                    new_object_hash: hash2,
                    nonexistence_proof: proof2,
                },
            ],
            sibling_hints: vec![],
        };

        // Verify that witness produces the same root as full trie
        let computed_root = verify_state_transition(&witness).unwrap();
        assert_eq!(computed_root, expected_root,
            "Witness verification produced different root than full trie. \
             Expected: {:?}, Got: {:?}",
            hex_encode(&expected_root), hex_encode(&computed_root));
    }

    #[test]
    fn test_witness_updates_with_shared_prefix() {
        // Test that witness verification correctly handles multiple updates
        // with shared path prefixes

        // Build initial state with objects sharing "sys" prefix
        let path1 = vec!["sys".to_string(), "names".to_string(), "sys".to_string()];
        let path2 = vec!["sys".to_string(), "policies".to_string(), "root".to_string()];
        let old_hash1 = [1u8; 32];
        let old_hash2 = [2u8; 32];
        let new_hash1 = [11u8; 32];
        let new_hash2 = [22u8; 32];

        let mut initial_trie = SparseTrie::new();
        initial_trie.insert(path1.clone(), old_hash1);
        initial_trie.insert(path2.clone(), old_hash2);
        let prev_root = initial_trie.root_hash();

        // Generate inclusion proofs from initial state
        let proof1 = initial_trie.generate_proof(&path1).unwrap();
        let proof2 = initial_trie.generate_proof(&path2).unwrap();

        // Build expected final state
        let mut expected_trie = SparseTrie::new();
        expected_trie.insert(path1.clone(), new_hash1);
        expected_trie.insert(path2.clone(), new_hash2);
        let expected_root = expected_trie.root_hash();

        // Build witness with two updates
        let witness = StateTransitionWitness {
            prev_state_root: prev_root,
            witnesses: vec![
                ObjectWitness::Update {
                    path_segments: path1,
                    old_object_hash: old_hash1,
                    new_object_hash: new_hash1,
                    inclusion_proof: proof1,
                },
                ObjectWitness::Update {
                    path_segments: path2,
                    old_object_hash: old_hash2,
                    new_object_hash: new_hash2,
                    inclusion_proof: proof2,
                },
            ],
            sibling_hints: vec![],
        };

        // Verify that witness produces the same root as full trie
        let computed_root = verify_state_transition(&witness).unwrap();
        assert_eq!(computed_root, expected_root,
            "Witness verification produced different root than full trie. \
             Expected: {:?}, Got: {:?}",
            hex_encode(&expected_root), hex_encode(&computed_root));
    }
}
