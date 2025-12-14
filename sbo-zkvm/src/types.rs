//! Types for zkVM proof input and output

use serde::{Serialize, Deserialize};

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

    /// Raw SBO actions data
    pub actions_data: Vec<u8>,

    /// Previous proof's journal (for chain verification)
    /// None for genesis proof
    pub prev_journal: Option<Vec<u8>>,

    /// Previous proof's receipt bytes (for recursive verification)
    /// None for genesis proof - passed via assumption mechanism
    pub prev_receipt_bytes: Option<Vec<u8>>,

    // --- Data Availability fields ---

    /// Data inclusion proof (merkle)
    pub data_proof: Option<DataProof>,

    /// Row commitments from block header
    pub row_commitments: Vec<KzgCommitment>,

    /// KZG proofs for relevant cells
    pub cell_proofs: Vec<CellProof>,

    /// Grid dimensions (columns)
    pub grid_cols: u32,
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
            actions_data: Vec::new(),
            prev_journal: None,
            prev_receipt_bytes: None,
            data_proof: None,
            row_commitments: Vec::new(),
            cell_proofs: Vec::new(),
            grid_cols: 256, // Avail default
        }
    }
}
