//! Path type for SBO objects (no_std compatible)

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec, format};

use crate::error::{ParseError, InvalidPathReason};
use crate::id::Id;

/// Path (e.g., "/alice/nfts/")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path(Vec<Id>);

impl Path {
    /// Parse a path string like "/alice/nfts/"
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        if !s.starts_with('/') {
            return Err(ParseError::InvalidPath(InvalidPathReason::MustStartWithSlash));
        }

        if !s.ends_with('/') {
            return Err(ParseError::InvalidPath(InvalidPathReason::MustEndWithSlash));
        }

        // Root path
        if s == "/" {
            return Ok(Self(Vec::new()));
        }

        let segments: Result<Vec<Id>, _> = s
            .trim_matches('/')
            .split('/')
            .map(Id::new)
            .collect();

        segments
            .map(Self)
            .map_err(|_| ParseError::InvalidPath(InvalidPathReason::InvalidSegment))
    }

    /// Get the root path
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Check if this is the root path
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the path segments
    pub fn segments(&self) -> &[Id] {
        &self.0
    }

    /// Get parent path (or None if root)
    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            None
        } else {
            Some(Self(self.0[..self.0.len() - 1].to_vec()))
        }
    }

    /// Format as string
    pub fn to_string(&self) -> String {
        if self.0.is_empty() {
            String::from("/")
        } else {
            let segments: Vec<&str> = self.0.iter().map(|id| id.as_str()).collect();
            format!("/{}/", segments.join("/"))
        }
    }
}

impl core::fmt::Display for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_path() {
        let path = Path::parse("/").unwrap();
        assert!(path.is_root());
        assert_eq!(path.to_string(), "/");
    }

    #[test]
    fn test_simple_path() {
        let path = Path::parse("/alice/nfts/").unwrap();
        assert!(!path.is_root());
        assert_eq!(path.segments().len(), 2);
        assert_eq!(path.to_string(), "/alice/nfts/");
    }

    #[test]
    fn test_parent() {
        let path = Path::parse("/alice/nfts/").unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent.to_string(), "/alice/");
    }

    #[test]
    fn test_invalid_paths() {
        assert!(Path::parse("no-leading-slash/").is_err());
        assert!(Path::parse("/no-trailing-slash").is_err());
    }
}
