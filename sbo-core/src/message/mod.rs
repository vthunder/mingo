//! Message types and validation

mod envelope;
mod actions;
mod validate;

pub use envelope::{Message, ObjectType, Id, Path, Related};
pub use actions::Action;
pub use validate::verify_message;
