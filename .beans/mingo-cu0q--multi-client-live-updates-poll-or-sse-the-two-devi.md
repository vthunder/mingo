---
# mingo-cu0q
title: Multi-client live updates (poll or SSE) — the two-device demo moment
status: completed
type: feature
priority: normal
created_at: 2026-07-16T00:26:19Z
updated_at: 2026-07-16T01:00:46Z
parent: mingo-y9gb
---

Auto-refresh so content posted on one device appears on another within ~1s, without manual reload — the 'two-phone' demo beat.

## Notes
- The daemon overlay already serves pending+confirmed writes to all clients immediately; the SPA just doesn't poll. So the cheap version is client-side polling of the current view's list endpoint on an interval (e.g. 2-5s), diffing and appending new items with the existing pending badge.
- Better: SSE/long-poll from the daemon if it exposes (or can expose) a change feed / head-change stream (check sbo-daemon /v1 for anything like a subscribe/stream endpoint or sync-points polling). SSE avoids constant re-list.
- Must interoperate with the optimistic-render path already in place (posts show pending immediately locally); don't double-insert an item the local client just wrote.
- Scope v1 to the feed + thread views. Show a subtle 'new posts' affordance or just live-append.
- This pairs naturally with a demo script: post on phone A, watch it land on phone B with the pending→confirmed transition and a tappable receipt.

## Summary
Live updates SHIPPED (overnight). Single 4s poller per active view, cleared on route change; diff-and-append with uri dedup + in-place vote refresh, coexists with confirm loops, never innerHTML-replaces. No server change. Poll stability verified (no dup rows). AWAITS ON-DEVICE: genuine cross-device append.
