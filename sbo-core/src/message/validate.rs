//! Message validation

use crate::error::ValidationError;
use super::Message;

/// Verify message signature and structure
pub fn verify_message(_msg: &Message, _raw_bytes: &[u8]) -> Result<(), ValidationError> {
    todo!("Implement message verification")
}
