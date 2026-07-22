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
//! - [`seed`] — the demo-corpus seeder behind `mingo seed` (personas, posts,
//!   vouches — a lived-in starting state for a fresh deployment).

pub mod appoint;
pub mod community;
pub mod device_login;
pub mod genesis;
pub mod livetest;
pub mod login;
pub mod seed;
pub mod set_root_admin;
