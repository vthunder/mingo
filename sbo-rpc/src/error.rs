//! Error types for the RPC crate

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Decode error: {0}")]
    Decode(String),

    #[error("No RPC endpoints configured")]
    NoEndpoints,
}

pub type Result<T> = std::result::Result<T, Error>;
