//! Mingo's forum-application layer atop the application-agnostic SBO reference
//! implementation (`sbo-core` and friends).
//!
//! SBO itself knows nothing about communities, memberships, or Mingo's genesis
//! layout — those are *application* concepts and live here, composed from the
//! generic primitives `sbo-core` exposes (objects, attestations, policies,
//! genesis builders). Keeping them out of `sbo-core` is what lets the daemon and
//! CLI stay app-agnostic.
//!
//! - [`community`] — the `community.v1` descriptor schema (parse/validate).
//! - [`genesis`] — the community/policy builders and the aggregated Mingo
//!   genesis batch.

pub mod community;
pub mod genesis;
