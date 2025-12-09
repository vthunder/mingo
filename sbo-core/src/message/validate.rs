//! Message validation

use crate::error::ValidationError;
use crate::crypto;
use super::Message;

/// Verify message signature
pub fn verify_message(msg: &Message) -> Result<(), ValidationError> {
    let content = msg.canonical_signing_content();

    crypto::verify(&msg.signing_key, &content, &msg.signature)
        .map_err(|_| ValidationError::InvalidAction("Signature verification failed".to_string()))
}
