//! Content-layer schemas — `post.v1`, `comment.v1`, `reaction.v1` (see the SBO
//! Content Specification §Content Schemas).
//!
//! These are intentionally **thin**: the ordering/conflict machinery lives in the
//! envelope (`HLC`, `Prev`) and the daemon's write model, not in the payload. This
//! module validates only payload field presence and types. `created_at` is a
//! cosmetic, **unverified** author wall-clock — ordering uses `HLC`, never this.
//! Threading (`parent`) and reaction targets are opaque references resolved by
//! readers/indexers, so they are not dereferenced here.

use serde::Deserialize;

use super::{SchemaError, SchemaResult};
use crate::message::Message;

/// A parsed `post.v1` payload — a top-level post.
#[derive(Debug, Clone, Deserialize)]
pub struct Post {
    /// Content (text/Markdown by convention).
    pub body: String,
    /// URI of a post this references (e.g. a cross-post); absent for a plain
    /// top-level post.
    #[serde(default)]
    pub parent: Option<String>,
    /// Cosmetic author wall-clock (Unix seconds); **unverified**.
    #[serde(default)]
    pub created_at: Option<i64>,
}

/// A parsed `comment.v1` payload — a reply. Identical to a post but `parent` is
/// required (threading).
#[derive(Debug, Clone, Deserialize)]
pub struct Comment {
    /// Content.
    pub body: String,
    /// URI of the post or comment being replied to (required for threading).
    pub parent: String,
    /// Cosmetic; unverified.
    #[serde(default)]
    pub created_at: Option<i64>,
}

/// A parsed `reaction.v1` payload — a toggle-able reaction by one author on one
/// target, keyed by `(author, target, kind)` and resolved LWW by `HLC`.
#[derive(Debug, Clone, Deserialize)]
pub struct Reaction {
    /// URI of the reacted-to object.
    pub target: String,
    /// Reaction kind (e.g. `upvote`, `❤️`).
    pub kind: String,
    /// `true` = present (default), `false` = removed (tombstone).
    #[serde(default = "default_true")]
    pub state: bool,
}

fn default_true() -> bool {
    true
}

/// Parse a `post.v1` payload.
pub fn parse_post(payload: &[u8]) -> SchemaResult<Post> {
    Ok(serde_json::from_slice(payload)?)
}

/// Parse a `comment.v1` payload.
pub fn parse_comment(payload: &[u8]) -> SchemaResult<Comment> {
    Ok(serde_json::from_slice(payload)?)
}

/// Parse a `reaction.v1` payload.
pub fn parse_reaction(payload: &[u8]) -> SchemaResult<Reaction> {
    Ok(serde_json::from_slice(payload)?)
}

/// Validate a `post.v1` message's payload: `body` required and non-empty.
pub fn validate_post(msg: &Message) -> SchemaResult<()> {
    let payload = msg.payload.as_ref().ok_or(SchemaError::EmptyPayload)?;
    let post = parse_post(payload)?;
    if post.body.is_empty() {
        return Err(SchemaError::MissingField("body".into()));
    }
    Ok(())
}

/// Validate a `comment.v1` message's payload: `body` and `parent` required and
/// non-empty.
pub fn validate_comment(msg: &Message) -> SchemaResult<()> {
    let payload = msg.payload.as_ref().ok_or(SchemaError::EmptyPayload)?;
    let comment = parse_comment(payload)?;
    if comment.body.is_empty() {
        return Err(SchemaError::MissingField("body".into()));
    }
    if comment.parent.is_empty() {
        return Err(SchemaError::MissingField("parent".into()));
    }
    Ok(())
}

/// Validate a `reaction.v1` message's payload: `target` and `kind` required and
/// non-empty.
pub fn validate_reaction(msg: &Message) -> SchemaResult<()> {
    let payload = msg.payload.as_ref().ok_or(SchemaError::EmptyPayload)?;
    let reaction = parse_reaction(payload)?;
    if reaction.target.is_empty() {
        return Err(SchemaError::MissingField("target".into()));
    }
    if reaction.kind.is_empty() {
        return Err(SchemaError::MissingField("kind".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_parses_and_defaults() {
        let p = parse_post(br#"{"body":"hi"}"#).unwrap();
        assert_eq!(p.body, "hi");
        assert!(p.parent.is_none());
        assert!(p.created_at.is_none());
    }

    #[test]
    fn post_requires_body() {
        assert!(parse_post(br#"{"parent":"/x"}"#).is_err());
    }

    #[test]
    fn comment_requires_parent() {
        // body present but parent missing → deserialize error.
        assert!(parse_comment(br#"{"body":"hi"}"#).is_err());
        let c = parse_comment(br#"{"body":"hi","parent":"/spaces/g/alice/post-1"}"#).unwrap();
        assert_eq!(c.parent, "/spaces/g/alice/post-1");
    }

    #[test]
    fn reaction_state_defaults_to_true() {
        let r = parse_reaction(br#"{"target":"/x","kind":"upvote"}"#).unwrap();
        assert!(r.state, "state defaults to present");
        let r2 = parse_reaction(br#"{"target":"/x","kind":"upvote","state":false}"#).unwrap();
        assert!(!r2.state, "explicit tombstone");
    }

    #[test]
    fn reaction_requires_target_and_kind() {
        assert!(parse_reaction(br#"{"kind":"upvote"}"#).is_err());
        assert!(parse_reaction(br#"{"target":"/x"}"#).is_err());
    }
}
