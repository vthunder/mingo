//! Wire format parser

use crate::error::ParseError;
use crate::message::Message;

/// Parse a single header line "Name: value"
pub fn parse_header_line(line: &[u8]) -> Result<(&str, &str), ParseError> {
    // Reject CRLF
    if line.contains(&b'\r') {
        return Err(ParseError::CrlfNotAllowed);
    }

    let line_str = std::str::from_utf8(line)
        .map_err(|_| ParseError::InvalidHeader("Invalid UTF-8".to_string()))?;

    let colon_pos = line_str.find(": ")
        .ok_or_else(|| ParseError::InvalidHeader("Missing ': ' separator".to_string()))?;

    let name = &line_str[..colon_pos];
    let value = &line_str[colon_pos + 2..];

    Ok((name, value))
}

/// Parse raw bytes into a validated Message
pub fn parse(_bytes: &[u8]) -> Result<Message, ParseError> {
    todo!("Implement wire format parsing")
}
