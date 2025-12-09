//! Action types

use super::envelope::{Id, Path};

/// SBO action types
#[derive(Debug, Clone)]
pub enum Action {
    /// Create or update an object
    Post,

    /// Transfer ownership, path, and/or ID
    Transfer {
        new_owner: Option<Id>,
        new_path: Option<Path>,
        new_id: Option<Id>,
    },

    /// Delete an object (transfer to null owner)
    Delete,

    /// Import from external chain
    Import {
        origin: String,
        registry_path: Path,
        object_path: Path,
        attestation: Vec<u8>,
    },
}

impl Action {
    /// Parse action from header value
    pub fn parse(s: &str) -> Result<Self, crate::error::ValidationError> {
        match s {
            "post" => Ok(Action::Post),
            "delete" => Ok(Action::Delete),
            "transfer" => Ok(Action::Transfer {
                new_owner: None,
                new_path: None,
                new_id: None,
            }),
            "import" => Ok(Action::Import {
                origin: String::new(),
                registry_path: Path::root(),
                object_path: Path::root(),
                attestation: vec![],
            }),
            _ => Err(crate::error::ValidationError::InvalidAction(s.to_string())),
        }
    }

    /// Get the action name for wire format
    pub fn name(&self) -> &'static str {
        match self {
            Action::Post => "post",
            Action::Transfer { .. } => "transfer",
            Action::Delete => "delete",
            Action::Import { .. } => "import",
        }
    }
}
