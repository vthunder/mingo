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
