//! ZK proof message types (SBOP, SBOQ)

mod sbop;

pub use sbop::{SbopMessage, parse_sbop, serialize_sbop, is_sbop_message, SbopError};
