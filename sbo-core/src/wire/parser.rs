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

/// Split message into header lines and payload at blank line
pub fn split_message(bytes: &[u8]) -> Result<(Vec<(&str, &str)>, &[u8]), ParseError> {
    // Find blank line (double LF)
    let mut pos = 0;
    let mut headers = Vec::new();

    while pos < bytes.len() {
        // Find next LF
        let line_end = bytes[pos..].iter().position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(bytes.len());

        let line = &bytes[pos..line_end];

        // Empty line = end of headers
        if line.is_empty() {
            let payload = &bytes[line_end + 1..];
            return Ok((headers, payload));
        }

        let (name, value) = parse_header_line(line)?;
        headers.push((name, value));

        pos = line_end + 1;
    }

    Err(ParseError::MissingBlankLine)
}

/// Parse raw bytes into a validated Message
pub fn parse(_bytes: &[u8]) -> Result<Message, ParseError> {
    todo!("Implement wire format parsing")
}
