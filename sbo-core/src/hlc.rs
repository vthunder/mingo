//! Hybrid Logical Clock — the content layer's **ordering** key (see the SBO
//! Content Specification §Author Clock).
//!
//! An `HLC` combines wall-clock milliseconds with a logical counter so causally
//! related writes order correctly without synchronized clocks. It is an ordering
//! key only — it **carries no authority** (a forged or back-dated `HLC` can only
//! *lose* last-writer-wins, never override another author). Authority comes from
//! attribution, validated separately at inclusion time.
//!
//! The wire encoding is `HLC: <physical>.<counter>` (e.g. `1703001234567.0`).
//! Ordering within a collection is by `physical`, then `counter`; the daemon
//! extends this to a fully deterministic total order across distinct authors by
//! appending signer-public-key then `object_hash` (see [`Hlc::cmp`] note).

use std::cmp::Ordering;

/// A parsed hybrid logical clock timestamp.
///
/// `Ord` compares by `physical` then `counter` — the intra-collection authoring
/// order. The full cross-author total order (Content Spec §Total order) appends
/// signer public key then `object_hash`, which live on the message, so the
/// daemon composes those tiebreakers around this type rather than here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hlc {
    /// Unix milliseconds — the author's wall clock at write time.
    pub physical: i64,
    /// Logical counter, breaking ties on equal `physical` and preserving
    /// monotonicity against observed timestamps.
    pub counter: u64,
}

/// Default skew tolerance `ε`: how far into the future a write's `physical` may
/// lead the block inclusion time. A few minutes, preventing future-dating.
pub const DEFAULT_SKEW_TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// Default maximum authoring lag `W` when a collection declares none: small, so
/// back-dated insertion into append-only history is tightly bounded.
pub const DEFAULT_MAX_AUTHORING_LAG_MS: i64 = 5 * 60 * 1000;

impl Hlc {
    /// Parse the wire form `<physical>.<counter>`. Both components are decimal;
    /// `physical` is non-negative Unix ms, `counter` a non-negative integer.
    /// Exactly one `.` separator is required.
    pub fn parse(s: &str) -> Result<Hlc, HlcParseError> {
        let (phys_str, ctr_str) = s.split_once('.').ok_or(HlcParseError::MissingSeparator)?;
        if ctr_str.contains('.') {
            return Err(HlcParseError::ExtraSeparator);
        }
        let physical: i64 = phys_str.parse().map_err(|_| HlcParseError::BadPhysical)?;
        let counter: u64 = ctr_str.parse().map_err(|_| HlcParseError::BadCounter)?;
        if physical < 0 {
            return Err(HlcParseError::BadPhysical);
        }
        Ok(Hlc { physical, counter })
    }

    /// Render back to the wire form `<physical>.<counter>`.
    pub fn to_wire(&self) -> String {
        format!("{}.{}", self.physical, self.counter)
    }

    /// Whether `physical` satisfies the validity bound against block inclusion
    /// time `t_b` (both in ms): `t_b − W ≤ physical ≤ t_b + ε`. A write outside
    /// the bound is disregarded on replay (an ordering-integrity rule; it does
    /// not touch attribution).
    pub fn within_bound(&self, t_b_ms: i64, max_lag_ms: i64, skew_ms: i64) -> bool {
        self.physical >= t_b_ms - max_lag_ms && self.physical <= t_b_ms + skew_ms
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.physical
            .cmp(&other.physical)
            .then(self.counter.cmp(&other.counter))
    }
}

/// The full cross-author total-order key for last-writer-wins (Content Spec
/// §Total order): `HLC`, then signer public key, then `object_hash`. All terms
/// are on-chain and deterministic, so every client computes the same order.
///
/// Borrows its components so callers can build it cheaply from a stored object or
/// an incoming message without cloning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LwwKey<'a> {
    pub hlc: Hlc,
    pub signer: &'a str,
    pub object_hash: &'a [u8; 32],
}

impl<'a> PartialOrd for LwwKey<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for LwwKey<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hlc
            .cmp(&other.hlc)
            .then_with(|| self.signer.cmp(other.signer))
            .then_with(|| self.object_hash.cmp(other.object_hash))
    }
}

/// Whether an incoming write `new` wins last-writer-wins over the current value
/// `old` — i.e. `new` is **strictly greater** in the total order. A tie (the
/// identical key) does not win, so a replayed duplicate never flips state.
pub fn lww_wins(new: LwwKey<'_>, old: LwwKey<'_>) -> bool {
    new > old
}

/// Errors parsing an `HLC` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HlcParseError {
    #[error("HLC missing '.' separator")]
    MissingSeparator,
    #[error("HLC has more than one '.' separator")]
    ExtraSeparator,
    #[error("HLC physical component is not a non-negative integer")]
    BadPhysical,
    #[error("HLC counter component is not a non-negative integer")]
    BadCounter,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let h = Hlc::parse("1703001234567.0").unwrap();
        assert_eq!(h.physical, 1703001234567);
        assert_eq!(h.counter, 0);
        assert_eq!(h.to_wire(), "1703001234567.0");
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(Hlc::parse("123").unwrap_err(), HlcParseError::MissingSeparator);
        assert_eq!(Hlc::parse("1.2.3").unwrap_err(), HlcParseError::ExtraSeparator);
        assert_eq!(Hlc::parse("-1.0").unwrap_err(), HlcParseError::BadPhysical);
        assert_eq!(Hlc::parse("x.0").unwrap_err(), HlcParseError::BadPhysical);
        assert_eq!(Hlc::parse("1.-2").unwrap_err(), HlcParseError::BadCounter);
    }

    #[test]
    fn total_order_physical_then_counter() {
        let a = Hlc { physical: 100, counter: 0 };
        let b = Hlc { physical: 100, counter: 1 };
        let c = Hlc { physical: 101, counter: 0 };
        assert!(a < b, "counter breaks ties on equal physical");
        assert!(b < c, "physical dominates counter");
        assert!(a < c);
    }

    #[test]
    fn lww_total_order_tiebreaks() {
        let h_lo = Hlc { physical: 100, counter: 0 };
        let h_hi = Hlc { physical: 100, counter: 1 };
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];

        // Higher HLC wins regardless of signer/hash.
        assert!(lww_wins(
            LwwKey { hlc: h_hi, signer: "aaa", object_hash: &hash_a },
            LwwKey { hlc: h_lo, signer: "zzz", object_hash: &hash_b },
        ));
        // Equal HLC → signer breaks the tie.
        assert!(lww_wins(
            LwwKey { hlc: h_lo, signer: "bbb", object_hash: &hash_a },
            LwwKey { hlc: h_lo, signer: "aaa", object_hash: &hash_a },
        ));
        // Equal HLC + signer → object_hash breaks the tie.
        assert!(lww_wins(
            LwwKey { hlc: h_lo, signer: "aaa", object_hash: &hash_b },
            LwwKey { hlc: h_lo, signer: "aaa", object_hash: &hash_a },
        ));
        // Identical key does not win (idempotent replay).
        assert!(!lww_wins(
            LwwKey { hlc: h_lo, signer: "aaa", object_hash: &hash_a },
            LwwKey { hlc: h_lo, signer: "aaa", object_hash: &hash_a },
        ));
    }

    #[test]
    fn validity_bound_rejects_future_and_stale() {
        let t_b = 1_000_000;
        let w = 60_000; // 60s lag
        let eps = 30_000; // 30s skew
        assert!(Hlc { physical: t_b, counter: 0 }.within_bound(t_b, w, eps));
        assert!(Hlc { physical: t_b - w, counter: 0 }.within_bound(t_b, w, eps), "at lower edge");
        assert!(Hlc { physical: t_b + eps, counter: 0 }.within_bound(t_b, w, eps), "at upper edge");
        assert!(!Hlc { physical: t_b - w - 1, counter: 0 }.within_bound(t_b, w, eps), "too far back-dated");
        assert!(!Hlc { physical: t_b + eps + 1, counter: 0 }.within_bound(t_b, w, eps), "future-dated");
    }
}
