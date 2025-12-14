use crate::merkle::{DataProof, compute_root};
use crate::sha256;

#[test]
fn test_compute_root_single() {
    let leaf = sha256(b"test");
    let root = compute_root(&[leaf]);
    assert_eq!(root, leaf);
}

#[test]
fn test_compute_root_two() {
    let leaf1 = sha256(b"leaf1");
    let leaf2 = sha256(b"leaf2");
    let root = compute_root(&[leaf1, leaf2]);

    // Manual calculation
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&leaf1);
    combined[32..].copy_from_slice(&leaf2);
    let expected = sha256(&combined);

    assert_eq!(root, expected);
}

#[test]
fn test_verify_proof() {
    let leaf1 = sha256(b"leaf1");
    let leaf2 = sha256(b"leaf2");
    let root = compute_root(&[leaf1, leaf2]);

    // Proof for leaf1 (index 0)
    let proof = DataProof {
        data_root: root,
        proof: vec![leaf2], // sibling
        number_of_leaves: 2,
        leaf_index: 0,
        leaf: leaf1,
    };

    assert!(proof.verify().unwrap());
}

#[test]
fn test_verify_proof_index_1() {
    let leaf1 = sha256(b"leaf1");
    let leaf2 = sha256(b"leaf2");
    let root = compute_root(&[leaf1, leaf2]);

    // Proof for leaf2 (index 1)
    let proof = DataProof {
        data_root: root,
        proof: vec![leaf1], // sibling
        number_of_leaves: 2,
        leaf_index: 1,
        leaf: leaf2,
    };

    assert!(proof.verify().unwrap());
}

#[test]
fn test_verify_proof_invalid() {
    let leaf1 = sha256(b"leaf1");
    let leaf2 = sha256(b"leaf2");
    let _root = compute_root(&[leaf1, leaf2]);

    // Wrong root
    let proof = DataProof {
        data_root: [0u8; 32],
        proof: vec![leaf2],
        number_of_leaves: 2,
        leaf_index: 0,
        leaf: leaf1,
    };

    assert!(proof.verify().is_err());
}
