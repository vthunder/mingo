//! SBO message envelope

use crate::crypto::{ContentHash, PublicKey, Signature};
use super::actions::Action;

/// Object type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Object,
    Collection,
}

/// Related object reference
#[derive(Debug, Clone)]
pub struct Related {
    pub rel: String,
    pub reference: String,
}

/// Validated identifier (1-256 chars, RFC 3986 unreserved)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

/// Path (e.g., "/alice/nfts/")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path(Vec<Id>);

/// Full SBO message
#[derive(Debug, Clone)]
pub struct Message {
    // Required fields
    pub action: Action,
    pub path: Path,
    pub id: Id,
    pub object_type: ObjectType,
    pub signing_key: PublicKey,
    pub signature: Signature,

    // Content fields (required for objects, optional for collections)
    pub content_type: Option<String>,
    pub content_hash: Option<ContentHash>,
    pub payload: Option<Vec<u8>>,

    // Optional fields
    pub owner: Option<Id>,
    pub creator: Option<Id>,
    pub content_encoding: Option<String>,
    pub content_schema: Option<String>,
    pub policy_ref: Option<String>,
    pub related: Option<Vec<Related>>,
}

impl Id {
    /// Create a new validated identifier
    pub fn new(s: impl AsRef<str>) -> Result<Self, crate::error::ParseError> {
        let s = s.as_ref();

        // Length check
        if s.is_empty() || s.len() > 256 {
            return Err(crate::error::ParseError::InvalidIdentifier(
                format!("Length must be 1-256, got {}", s.len())
            ));
        }

        // Character check: RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        for c in s.chars() {
            if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~') {
                return Err(crate::error::ParseError::InvalidIdentifier(
                    format!("Invalid character: {}", c)
                ));
            }
        }

        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Path {
    /// Parse a path string like "/alice/nfts/"
    pub fn parse(s: &str) -> Result<Self, crate::error::ParseError> {
        if !s.starts_with('/') {
            return Err(crate::error::ParseError::InvalidPath(
                "Path must start with /".to_string()
            ));
        }

        if !s.ends_with('/') {
            return Err(crate::error::ParseError::InvalidPath(
                "Path must end with /".to_string()
            ));
        }

        // Root path
        if s == "/" {
            return Ok(Self(vec![]));
        }

        let segments: Result<Vec<Id>, _> = s
            .trim_matches('/')
            .split('/')
            .map(Id::new)
            .collect();

        Ok(Self(segments?))
    }

    /// Get the root path
    pub fn root() -> Self {
        Self(vec![])
    }

    /// Format as string
    pub fn to_string(&self) -> String {
        if self.0.is_empty() {
            "/".to_string()
        } else {
            format!("/{}/", self.0.iter().map(|id| id.as_str()).collect::<Vec<_>>().join("/"))
        }
    }

    /// Get parent path (or None if root)
    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            None
        } else {
            Some(Self(self.0[..self.0.len() - 1].to_vec()))
        }
    }

    /// Iterate over ancestor paths (including self, excluding root)
    pub fn ancestors(&self) -> impl Iterator<Item = Path> + '_ {
        (0..=self.0.len()).rev().map(|i| Path(self.0[..i].to_vec()))
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
