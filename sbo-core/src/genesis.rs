//! Genesis block handling

use crate::error::ValidationError;
use crate::message::Message;

/// Genesis block validator
pub struct Genesis;

impl Genesis {
    /// Validate genesis block (must contain sys identity + root policy)
    pub fn validate(_messages: &[Message]) -> Result<(), ValidationError> {
        todo!("Implement genesis validation")
    }
}
