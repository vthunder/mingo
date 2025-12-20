//! Types for zkVM proof input and output

use serde::{Serialize, Deserialize};

// Re-export witness types from sbo-crypto for convenience
pub use sbo_crypto::trie::{
    ObjectWitness, StateTransitionWitness, SiblingHint, TrieProof, TrieProofStep,
};

/// Kind of proof receipt (affects size and verification cost)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptKind {
    /// Composite STARK receipt (~MB, fast to generate)
    Composite,
    /// Succinct STARK receipt (~100KB, aggregated)
    Succinct,
    /// Groth16 SNARK receipt (~256 bytes, on-chain verifiable)
    Groth16,
}

impl Default for ReceiptKind {
    fn default() -> Self {
        ReceiptKind::Composite
    }
}

/// KZG commitment (48 bytes compressed G1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgCommitment(pub [u8; 48]);

impl Serialize for KzgCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for KzgCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = [u8; 48];

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("48 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 48 {
                    return Err(E::custom("expected 48 bytes"));
                }
                let mut arr = [0u8; 48];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 48];
                for i in 0..48 {
                    arr[i] = seq.next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor).map(KzgCommitment)
    }
}

/// KZG proof (48 bytes compressed G1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgProof(pub [u8; 48]);

impl Serialize for KzgProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for KzgProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = [u8; 48];

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("48 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 48 {
                    return Err(E::custom("expected 48 bytes"));
                }
                let mut arr = [0u8; 48];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 48];
                for i in 0..48 {
                    arr[i] = seq.next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor).map(KzgProof)
    }
}

/// Cell data with KZG proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellProof {
    /// Row index
    pub row: u32,
    /// Column index
    pub col: u32,
    /// Cell data
    pub data: Vec<u8>,
    /// KZG proof bytes
    pub proof: KzgProof,
}

/// Merkle proof for data inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof {
    /// Data root from header
    pub data_root: [u8; 32],
    /// Merkle proof elements
    pub proof: Vec<[u8; 32]>,
    /// Number of leaves
    pub number_of_leaves: u32,
    /// Leaf index
    pub leaf_index: u32,
    /// Leaf hash
    pub leaf: [u8; 32],
}

/// App lookup entry from header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLookupEntry {
    pub app_id: u32,
    pub start: u32,  // Start chunk index
}

/// Complete app lookup from header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLookup {
    /// Total chunks in the block
    pub size: u32,
    /// App entries (sorted by start)
    pub index: Vec<AppLookupEntry>,
}

/// Header verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderData {
    /// Block number
    pub block_number: u64,
    /// Header hash (blake2b-256 of SCALE-encoded header)
    pub header_hash: [u8; 32],
    /// Parent header hash
    pub parent_hash: [u8; 32],
    /// State root from header
    pub state_root: [u8; 32],
    /// Extrinsics root from header
    pub extrinsics_root: [u8; 32],
    /// Data root from Kate commitment
    pub data_root: [u8; 32],
    /// Row commitments (48 bytes each, concatenated)
    pub row_commitments: Vec<u8>,
    /// Grid dimensions
    pub rows: u32,
    pub cols: u32,
    /// App lookup for our app_id
    pub app_lookup: AppLookup,
    /// Our app_id
    pub app_id: u32,
}

/// Full row data for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowData {
    /// Row index
    pub row: u32,
    /// Cell values (32 bytes each, cols cells total)
    /// First 31 bytes are data, last byte is padding
    pub cells: Vec<[u8; 32]>,
}

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    /// Previous block's state root (32 bytes)
    pub prev_state_root: [u8; 32],

    /// Block number being proven
    pub block_number: u64,

    /// Block hash (for header chain verification)
    pub block_hash: [u8; 32],

    /// Parent block hash
    pub parent_hash: [u8; 32],

    /// Previous proof's journal (for chain verification)
    /// None for genesis proof or first proof in chain
    pub prev_journal: Option<Vec<u8>>,

    /// Previous proof's receipt bytes (for recursive verification)
    /// None for genesis proof - passed via assumption mechanism
    pub prev_receipt_bytes: Option<Vec<u8>>,

    /// Bootstrap mode: first proof in chain (no previous proof required)
    /// Use this when starting to prove from an arbitrary block (not genesis).
    /// When true, prev_journal and prev_receipt_bytes are not required even if block_number != 0.
    #[serde(default)]
    pub is_first_proof: bool,

    // --- State Commitment fields ---

    /// Witness for state transition (creates, updates, deletes with proofs)
    /// Replaces pre_objects/post_objects - scales with touched objects, not total state
    #[serde(default)]
    pub state_witness: StateTransitionWitness,

    // --- Data Availability fields ---

    /// Header data for verification
    pub header_data: Option<HeaderData>,

    /// Full row data for rows containing app data
    pub row_data: Vec<RowData>,

    /// Pre-decoded SBO actions (from SCALE extrinsics)
    /// Host decodes, guest verifies hash matches row data
    pub actions_data: Vec<u8>,

    /// Hash of raw cell data before SCALE decoding
    /// Guest computes this from row_data and verifies
    pub raw_cells_hash: [u8; 32],
}

/// Output committed by the zkVM (the "journal")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockProofOutput {
    /// State root before this block
    pub prev_state_root: [u8; 32],

    /// State root after this block
    pub new_state_root: [u8; 32],

    /// Block number that was proven
    pub block_number: u64,

    /// Hash of the block that was proven
    pub block_hash: [u8; 32],

    /// Data root that was verified (for DA anchoring)
    pub data_root: [u8; 32],

    /// Protocol version
    pub version: u32,
}

impl BlockProofOutput {
    /// Current protocol version
    pub const VERSION: u32 = 1;

    /// Empty state root (for genesis)
    pub const EMPTY_STATE_ROOT: [u8; 32] = [0u8; 32];

    /// Empty data root (for blocks with no DA proof)
    pub const EMPTY_DATA_ROOT: [u8; 32] = [0u8; 32];
}

impl Default for BlockProofInput {
    fn default() -> Self {
        Self {
            prev_state_root: [0u8; 32],
            block_number: 0,
            block_hash: [0u8; 32],
            parent_hash: [0u8; 32],
            prev_journal: None,
            prev_receipt_bytes: None,
            is_first_proof: false,
            state_witness: StateTransitionWitness::default(),
            header_data: None,
            row_data: Vec::new(),
            actions_data: Vec::new(),
            raw_cells_hash: [0u8; 32],
        }
    }
}
