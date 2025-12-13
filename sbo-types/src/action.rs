//! SBO action types (no_std compatible)

use crate::error::ParseError;

/// SBO message action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Create a new object at a specific path (deterministic naming)
    Create,
    /// Post a new object (system assigns ID)
    Post,
    /// Update an existing object
    Update,
    /// Delete an object
    Delete,
    /// Transfer ownership or move an object
    Transfer,
    /// Import an object from another chain
    Import,
}

impl Action {
    /// Parse action from string
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        match s.to_lowercase().as_str() {
            "create" => Ok(Action::Create),
            "post" => Ok(Action::Post),
            "update" => Ok(Action::Update),
            "delete" => Ok(Action::Delete),
            "transfer" => Ok(Action::Transfer),
            "import" => Ok(Action::Import),
            _ => Err(ParseError::InvalidAction),
        }
    }

    /// Get action name as string
    pub fn name(&self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Post => "post",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Transfer => "transfer",
            Action::Import => "import",
        }
    }
}

impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_actions() {
        assert_eq!(Action::parse("create").unwrap(), Action::Create);
        assert_eq!(Action::parse("POST").unwrap(), Action::Post);
        assert_eq!(Action::parse("Update").unwrap(), Action::Update);
    }

    #[test]
    fn test_invalid_action() {
        assert!(Action::parse("invalid").is_err());
    }
}
