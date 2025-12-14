//! ZK proof message types (SBOP, SBOQ)

mod sbop;
mod sboq;

pub use sbop::{SbopMessage, parse_sbop, serialize_sbop, is_sbop_message, SbopError};
pub use sboq::{SboqMessage, parse_sboq, serialize_sboq, is_sboq_message, SboqError};
