//! Wire format parser

use crate::error::ParseError;
use crate::message::Message;

/// Parse raw bytes into a validated Message
pub fn parse(_bytes: &[u8]) -> Result<Message, ParseError> {
    todo!("Implement wire format parsing")
}
