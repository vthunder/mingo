//! Identity name resolution

use serde::{Deserialize, Serialize};

/// Identity claim stored at /sys/names/*
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaim {
    pub public_key: String,
    pub display_name: Option<String>,
}
