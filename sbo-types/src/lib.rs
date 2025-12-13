//! SBO Core Types
//!
//! This crate provides the fundamental types for SBO (Simple Blockchain Objects).
//! It is `no_std` compatible for use in zkVM environments.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-export alloc types for convenience
#[cfg(feature = "alloc")]
pub use alloc::{string::String, vec::Vec, vec};

pub mod error;
pub mod id;
pub mod path;
pub mod action;
