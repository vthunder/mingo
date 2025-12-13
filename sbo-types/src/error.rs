//! Error types for sbo-types (no_std compatible)

/// Parse error for SBO types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Invalid identifier format
    InvalidIdentifier(InvalidIdentifierReason),
    /// Invalid path format
    InvalidPath(InvalidPathReason),
    /// Invalid action
    InvalidAction,
}

/// Reason for invalid identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidIdentifierReason {
    Empty,
    TooLong,
    InvalidChar,
}

/// Reason for invalid path
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPathReason {
    MustStartWithSlash,
    MustEndWithSlash,
    InvalidSegment,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::InvalidIdentifier(reason) => {
                write!(f, "Invalid identifier: {:?}", reason)
            }
            ParseError::InvalidPath(reason) => {
                write!(f, "Invalid path: {:?}", reason)
            }
            ParseError::InvalidAction => {
                write!(f, "Invalid action")
            }
        }
    }
}
