//! SBO Core Library
//!
//! Core implementation of the SBO (Simple Blockchain Objects) specification.
//!
//! # Modules
//!
//! - [`wire`] - Wire format parsing and serialization
//! - [`crypto`] - Cryptographic operations (ed25519, hashing)
//! - [`message`] - Message types and validation
//! - [`policy`] - Policy evaluation
//! - [`state`] - State management with RocksDB

pub mod wire;
pub mod crypto;
pub mod message;
pub mod policy;
pub mod state;
pub mod error;
pub mod presets;

mod genesis;
mod indexer;

pub use error::SboError;
pub use genesis::Genesis;
pub use indexer::Indexer;

// Re-export types from sbo-types
pub use sbo_types::id::Id;
pub use sbo_types::path::Path;
pub use sbo_types::action::Action;
pub use sbo_types::error::ParseError as TypesParseError;

// Re-export crypto from sbo-crypto
pub use sbo_crypto::{sha256, ContentHash, HashAlgo, CryptoError};
pub use sbo_crypto::ed25519 as ed25519_new;
#[cfg(feature = "bls")]
pub use sbo_crypto::bls;
