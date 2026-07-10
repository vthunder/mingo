---
# mingo-jyzt
title: Object resolution at (path,id) with multiple creators is under-specified (first-creator-wins)
status: todo
type: bug
priority: high
created_at: 2026-07-09T23:09:09Z
updated_at: 2026-07-09T23:11:12Z
---

## Problem

Objects are stored in the state trie keyed by **(path, creator, id)** — the creator segment is part of the key (see sbo `StateDb::object_to_segments`: `[...path, creator, id]`, and `resolve_creator` → `e_<first16hex(pubkey)>` for key-rooted writes / attributed-email for browserid writes).

When two *different creators* write an object at the same logical `(path, id)`, they do NOT collide — they create two separate trie entries. Read/resolution via `StateDb::get_first_object_at_path_id` then returns the **lexicographically-first creator's** object, with **no validity, freshness, or authority check**. LWW (`lww_admits`, HLC-based) only applies *within the same creator segment*, so it does nothing to arbitrate across creators.

This surfaced concretely with `/sys/dnssec/<domain>` (self-authorizing evidence objects):
- The daemon's attribution path (`fetch_evidence_object`) and freshness endpoint (`dnssec_v1`) both call `get_first_object_at_path_id` and take the first creator blindly.
- browserid.me's first proof was written by mingo-web's **per-write ephemeral key** (each `writeContent` self-auth call generates a fresh Ed25519 key → a fresh creator segment). So the proof can never be updated in place; every refresh forks a new creator entry, and resolution keeps returning the arbitrary first-creator fork — which was a stale-key proof. Result: broker-certified email attribution fails even though a valid, current proof exists on-chain under a different creator.
- mingo.place only worked by luck: its proof was written once by a stable CLI keyring key, so there's a single fork.

## Why this is likely a SPEC issue, not just a daemon bug

The Content/Authorization specs define per-object LWW conflict resolution but do not clearly specify what `(path, id)` *resolves to* when multiple authorized creators have written there. "First creator wins (lexicographic)" is an implementation accident of `get_first_object_at_path_id`, not a stated rule, and it is:
- **Non-deterministic w.r.t. intent** — the "current" value is whoever has the smallest pubkey/email, not the latest or the valid one.
- **Grindable** — an attacker can mint a low-sorting key to squat the first-creator slot at any shared/creator-agnostic `(path, id)`.
- **Wrong for self-authorizing namespaces** (`/sys/dnssec`): ANY valid proof for the domain should satisfy attribution, regardless of who posted it.

## Broader contexts to analyze (pros/cons of changing the logic)

1. **Creator-scoped objects (the common case).** `/u/<name>/...` etc. are implicitly single-creator; creator-in-key is correct and desirable (isolation, no clobbering). Changing cross-creator resolution must NOT break this.
2. **Shared spaces / collaborative writes.** A policy may grant *multiple* owners write access to the same location (shared doc, group inbox, CRDT-ish state). Here "first creator wins" is clearly wrong; you want either (a) LWW across creators, (b) explicit per-write identity (creator-in-path, app merges), or (c) app-defined merge. What does the spec promise? Probably needs an explicit resolution mode per path/policy.
3. **Self-authorizing namespaces** (`/sys/dnssec`, possibly others): resolution should be "any object satisfying an intrinsic validity predicate," not identity-ordered. Arguably these should be *content-addressed sets*, not single-value keys.
4. **First-claim-wins namespaces** (`/sys/names/<name>`?): here first-writer semantics may be *intended* (name registration). So the desired policy genuinely differs by namespace → argues for making resolution mode explicit rather than one global rule.

## Candidate designs (to weigh)

- **A. Validity-filtered resolution for evidence:** `fetch_evidence_object`/`dnssec_v1` iterate all creator-forks and pick the proof with the latest valid window covering inclusion time. Minimal, fixes `/sys/dnssec` generally and deterministically; does not address shared-space semantics.
- **B. Cross-creator LWW for creator-agnostic paths:** define certain paths as single-value/creator-agnostic and arbitrate by the existing LWW total order (HLC, signer, object_hash) across creators. General; needs a way to mark such paths.
- **C. Per-namespace resolution mode in policy:** policy declares resolution = {creator-scoped | lww-merged | first-claim | valid-set}. Most expressive; biggest spec/impl surface.
- **D. Stable-key convention (no protocol change):** require `/sys/dnssec` writes to use a single well-known shared key so there's one creator segment + in-place LWW. Cheap but conventions are fragile and don't fix already-poisoned slots; doesn't generalize to shared spaces.

## Meantime unblock (done separately)

DNS `_browserid.browserid.me` was stale (advertised an old broker key `oBxScFH3…` while the broker signs with `RJSV6bcy…`); fixed at Namecheap. A valid new-key proof is on-chain. To make resolution return it without a daemon change, we write the browserid.me proof under a **grinded low-sorting creator key** (pubkey starting `00`) so `get_first_object_at_path_id` returns it. This is a stopgap that expires with the proof (~2026-07-14) and must be superseded by a real fix (A/B/C) before/near then. Re-genesis is also an option if we want a clean slate.

## Related
- Ephemeral-per-write signing for self-auth `/sys/dnssec` in mingo-web (`writeContent` keyRooted path) is what forks creators — revisit alongside whichever resolution design is chosen.

## Meantime unblock APPLIED (2026-07-09)

browserid.me DNS corrected at Namecheap (`_browserid` TXT now = `RJSV6bcy…`, the broker's real signing key). Fresh valid proof written under a grinded low-sorting creator key `ed25519:00ee1b7ac5091c0e…` (creator `e_00ee1b7ac5091c0e`, sorts before the stale `e_3eb1b33c…` fork). Canonical `/sys/dnssec/browserid.me` now resolves to the new-key proof (confirmed). Builder: sbo-cli `examples/dnssec_hlc.rs` (captures live proof, current-ms HLC, grinds creator). Expires with the RRSIG window (~2026-07-14) — must land a real resolution fix (A/B/C) before then, or re-grind/re-genesis.
