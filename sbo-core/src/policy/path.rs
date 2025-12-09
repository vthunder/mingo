//! Path pattern matching

use serde::{Deserialize, Serialize};
use crate::message::Path;

/// Path pattern for matching (e.g., "/users/**", "/$owner/*")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PathPattern(String);

impl PathPattern {
    /// Create a new path pattern
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Check if this pattern matches a path
    pub fn matches(&self, path: &Path, owner: Option<&str>) -> bool {
        let pattern = self.resolve_variables(owner);
        Self::match_pattern(&pattern, &path.to_string())
    }

    /// Resolve variables like $owner
    fn resolve_variables(&self, owner: Option<&str>) -> String {
        let mut result = self.0.clone();
        if let Some(owner) = owner {
            result = result.replace("$owner", owner);
        }
        result
    }

    /// Match a resolved pattern against a path string
    fn match_pattern(pattern: &str, path: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        Self::match_parts(&pattern_parts, &path_parts)
    }

    fn match_parts(pattern: &[&str], path: &[&str]) -> bool {
        match (pattern.first(), path.first()) {
            // Both empty = match
            (None, None) => true,

            // Pattern empty but path not = no match
            (None, Some(_)) => false,

            // ** matches zero or more segments
            (Some(&"**"), _) => {
                // Try matching ** with 0, 1, 2, ... segments
                for i in 0..=path.len() {
                    if Self::match_parts(&pattern[1..], &path[i..]) {
                        return true;
                    }
                }
                false
            }

            // Path empty but pattern not (unless **)
            (Some(_), None) => false,

            // * matches exactly one segment
            (Some(&"*"), Some(_)) => Self::match_parts(&pattern[1..], &path[1..]),

            // Exact match required
            (Some(p), Some(s)) => {
                if *p == *s {
                    Self::match_parts(&pattern[1..], &path[1..])
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = PathPattern::new("/users/alice");
        assert!(pattern.matches(&Path::parse("/users/alice/").unwrap(), None));
    }

    #[test]
    fn test_wildcard() {
        let pattern = PathPattern::new("/users/*");
        assert!(pattern.matches(&Path::parse("/users/alice/").unwrap(), None));
        assert!(pattern.matches(&Path::parse("/users/bob/").unwrap(), None));
    }

    #[test]
    fn test_double_wildcard() {
        let pattern = PathPattern::new("/users/**");
        assert!(pattern.matches(&Path::parse("/users/alice/").unwrap(), None));
        assert!(pattern.matches(&Path::parse("/users/alice/nfts/").unwrap(), None));
    }
}
