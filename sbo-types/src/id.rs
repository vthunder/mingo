//! Validated identifier type (no_std compatible)

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::error::{ParseError, InvalidIdentifierReason};

/// Validated identifier (1-256 chars, RFC 3986 unreserved)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    /// Maximum identifier length
    pub const MAX_LEN: usize = 256;

    /// Create a new validated identifier
    pub fn new(s: &str) -> Result<Self, ParseError> {
        // Length check
        if s.is_empty() {
            return Err(ParseError::InvalidIdentifier(InvalidIdentifierReason::Empty));
        }
        if s.len() > Self::MAX_LEN {
            return Err(ParseError::InvalidIdentifier(InvalidIdentifierReason::TooLong));
        }

        // Character check: RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        for c in s.chars() {
            if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~') {
                return Err(ParseError::InvalidIdentifier(InvalidIdentifierReason::InvalidChar));
            }
        }

        Ok(Self(String::from(s)))
    }

    /// Get the identifier as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_id() {
        assert!(Id::new("alice").is_ok());
        assert!(Id::new("Bob-123").is_ok());
        assert!(Id::new("test_id.v1").is_ok());
    }

    #[test]
    fn test_invalid_id() {
        assert!(Id::new("").is_err());
        assert!(Id::new("has space").is_err());
        assert!(Id::new("has/slash").is_err());
    }
}
