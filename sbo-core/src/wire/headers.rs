//! Header types and parsing

use std::collections::HashMap;

/// Map of header names to values
#[derive(Debug, Default)]
pub struct HeaderMap(HashMap<String, String>);

impl HeaderMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.insert(name.into(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }

    pub fn require(&self, name: &str) -> Result<&str, crate::error::ParseError> {
        self.get(name)
            .ok_or_else(|| crate::error::ParseError::MissingHeader(name.to_string()))
    }
}
