//! Proof verification for SBO blocks

use crate::types::BlockProofOutput;
use sbo_zkvm_methods::SBO_ZKVM_GUEST_ID;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Journal decode error: {0}")]
    JournalError(String),

    #[error("Receipt decode error: {0}")]
    ReceiptError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

/// Verify a proof receipt
pub fn verify_receipt(receipt_bytes: &[u8]) -> Result<BlockProofOutput, VerifierError> {
    use risc0_zkvm::Receipt;

    // Deserialize receipt using postcard (same as prover)
    let receipt: Receipt = postcard::from_bytes(receipt_bytes)
        .map_err(|e| VerifierError::ReceiptError(e.to_string()))?;

    // Verify proof against our guest program
    receipt
        .verify(SBO_ZKVM_GUEST_ID)
        .map_err(|e| VerifierError::InvalidProof(e.to_string()))?;

    // Decode and return journal
    let output: BlockProofOutput = receipt
        .journal
        .decode()
        .map_err(|e| VerifierError::JournalError(e.to_string()))?;

    Ok(output)
}

/// Verify proof and check it matches expected block
pub fn verify_block_proof(
    receipt_bytes: &[u8],
    expected_block_number: u64,
    expected_block_hash: [u8; 32],
) -> Result<BlockProofOutput, VerifierError> {
    let output = verify_receipt(receipt_bytes)?;

    if output.block_number != expected_block_number {
        return Err(VerifierError::InvalidProof(format!(
            "Block number mismatch: expected {}, got {}",
            expected_block_number, output.block_number
        )));
    }

    if output.block_hash != expected_block_hash {
        return Err(VerifierError::InvalidProof(
            "Block hash mismatch".to_string()
        ));
    }

    Ok(output)
}

/// Verify proof matches expected block and data root (DA anchored)
pub fn verify_block_proof_with_da(
    receipt_bytes: &[u8],
    expected_block_number: u64,
    expected_block_hash: [u8; 32],
    expected_data_root: [u8; 32],
) -> Result<BlockProofOutput, VerifierError> {
    let output = verify_block_proof(receipt_bytes, expected_block_number, expected_block_hash)?;

    if output.data_root != expected_data_root {
        return Err(VerifierError::InvalidProof(
            "Data root mismatch".to_string()
        ));
    }

    Ok(output)
}

/// Verify a chain of proofs
pub fn verify_proof_chain(
    receipts: &[Vec<u8>],
) -> Result<BlockProofOutput, VerifierError> {
    if receipts.is_empty() {
        return Err(VerifierError::InvalidProof("Empty proof chain".to_string()));
    }

    let mut prev_output: Option<BlockProofOutput> = None;

    for (i, receipt_bytes) in receipts.iter().enumerate() {
        let output = verify_receipt(receipt_bytes)?;

        // Verify chain continuity
        if let Some(prev) = &prev_output {
            if output.block_number != prev.block_number + 1 {
                return Err(VerifierError::InvalidProof(format!(
                    "Block number discontinuity at {}",
                    i
                )));
            }
            if output.prev_state_root != prev.new_state_root {
                return Err(VerifierError::InvalidProof(format!(
                    "State root mismatch at block {}",
                    output.block_number
                )));
            }
        } else {
            // First proof should be genesis
            if output.block_number != 0 {
                return Err(VerifierError::InvalidProof(
                    "Chain must start at genesis".to_string()
                ));
            }
        }

        prev_output = Some(output);
    }

    Ok(prev_output.unwrap())
}

/// Get the kind of a serialized receipt
pub fn get_receipt_kind(receipt_bytes: &[u8]) -> Result<crate::types::ReceiptKind, VerifierError> {
    use risc0_zkvm::Receipt;

    let receipt: Receipt = postcard::from_bytes(receipt_bytes)
        .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

    // Check the inner receipt type
    match &receipt.inner {
        risc0_zkvm::InnerReceipt::Composite(_) => Ok(crate::types::ReceiptKind::Composite),
        risc0_zkvm::InnerReceipt::Succinct(_) => Ok(crate::types::ReceiptKind::Succinct),
        risc0_zkvm::InnerReceipt::Groth16(_) => Ok(crate::types::ReceiptKind::Groth16),
        _ => Ok(crate::types::ReceiptKind::Composite), // Default for unknown
    }
}
