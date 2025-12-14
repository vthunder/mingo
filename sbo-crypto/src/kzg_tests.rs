#[cfg(feature = "kzg")]
use crate::kzg::{KzgCommitment, KzgProof, CellProof, G1_COMPRESSED_SIZE};

#[cfg(feature = "kzg")]
#[test]
fn test_commitment_from_bytes() {
    let bytes = [0u8; G1_COMPRESSED_SIZE];
    let commitment = KzgCommitment::from_bytes(&bytes);
    assert!(commitment.is_some());
}

#[cfg(feature = "kzg")]
#[test]
fn test_commitment_wrong_size() {
    let bytes = [0u8; 32]; // Wrong size
    let commitment = KzgCommitment::from_bytes(&bytes);
    assert!(commitment.is_none());
}

#[cfg(feature = "kzg")]
#[test]
fn test_proof_from_bytes() {
    let bytes = [0u8; G1_COMPRESSED_SIZE];
    let proof = KzgProof::from_bytes(&bytes);
    assert!(proof.is_some());
}

#[cfg(feature = "kzg")]
#[test]
fn test_cell_proof_struct() {
    let cell = CellProof {
        row: 0,
        col: 5,
        data: vec![1, 2, 3, 4],
        proof: KzgProof([0u8; G1_COMPRESSED_SIZE]),
    };

    assert_eq!(cell.row, 0);
    assert_eq!(cell.col, 5);
    assert_eq!(cell.data.len(), 4);
}
