---
# mingo-hcff
title: 'Mempool Phase B: pending-aware validation (StateView/Overlay)'
status: completed
type: feature
priority: normal
tags:
    - mempool
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T20:19:49Z
---

Phase A (shipped) validates submits against CONFIRMED state only. Phase B introduces a StateView trait + Overlay{db,pending} so validate_message runs against confirmed+pending — enabling chained optimistic writes (join→post) and letting the SPA relax membership gating to count pending memberships. See docs/plans 2026-06-25-mempool-overlay-plan.md (the plan moved with the impl).

## Plan / Todos

Design: a `StateView` trait (read surface = get_object, get_first_object_at_path_id, resolve_policy) defined in sbo-daemon; `impl StateView for StateDb` (confirmed) and `Overlay{db, pending-snapshot}` (confirmed+pending). validate_message + helpers become generic over `&dyn StateView` instead of `&StateDb`. Submit path validates against an Overlay, staging each message into the overlay as it validates so intra-batch chains (join→post) see prior writes.

- [x] Add StateView trait + impl for StateDb (sbo-daemon/src/state_view.rs)
- [x] Add Overlay{db, pending snapshot} impl StateView (pending wins via overlay_wins)
- [x] Add PendingPool::snapshot()
- [x] Convert validate.rs signatures &StateDb -> &dyn StateView (incl. Option<&_>)
- [x] Wire submit path to validate against Overlay, staging each msg incrementally
- [x] Keep sync.rs block-processing on confirmed StateDb (no overlay)
- [x] Unit tests: overlay read-through, pending-wins, chained join->post validation
- [x] cargo test green
- [x] SPA membership-gating relaxed to count pending memberships (mingo-web/app.js)

## Summary of Changes

Added a StateView read abstraction so submit-time validation runs against confirmed+pending state.

- New sbo-daemon/src/state_view.rs: StateView trait (get_object, get_first_object_at_path_id, resolve_policy, list_objects_by_path_prefix, list_objects_by_schema, get_name_for_pubkey). impl for StateDb (confirmed) and Overlay{db, pending snapshot} (confirmed+pending, pending wins via overlay_wins; object lists merged by (path,id)).
- PendingPool::snapshot() for lock-free overlay construction.
- validate.rs: all helpers + validate_message now take &dyn StateView instead of &StateDb (read surface unchanged).
- main.rs submit: builds an Overlay from the pending snapshot and validates each message against it, staging each validated object into the overlay so intra-batch chains (join->post) see prior writes before they hit the pool/chain.
- sync.rs block processing stays on confirmed StateDb (coerced to &dyn StateView).
- 6 new unit tests (read-through, pending-only, pending-wins-LWW, creator filter, list merge, staged chaining). Full sbo-daemon suite green (23 integration + 32 lib); workspace builds clean.

Note: the SPA-side relaxation (count pending memberships in membership gating) is a mingo-web change not included here; the daemon already serves pending memberships via the read-merge + this validation overlay. Tracked as potential follow-on.

## Update: SPA membership gating (done in-scope)

mingo-web/app.js: hasMembership() now counts pending memberships (dropped the confirmed-only filter) since the daemon validates posts against confirmed+pending. joinHub() flow flips Join → New post immediately on submit instead of polling ~30s for on-chain confirmation. node --check passes; no SPA test harness exists.
