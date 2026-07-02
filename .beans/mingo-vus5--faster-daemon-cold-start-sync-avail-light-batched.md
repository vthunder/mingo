---
# mingo-vus5
title: Faster daemon cold-start sync (avail-light / batched RPC / snapshot)
status: todo
type: feature
priority: low
tags:
    - deploy
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-07-02T18:45:09Z
blocked_by:
    - mingo-o5t1
---

State now persists across deploys, so this only bites on volume loss. RPC-only sync replays genesis→tip one block at a time (~15-20 min). Options: run avail-light, batch/concurrent RPC range fetch, or ship/restore a RocksDB state snapshot.

## Partially delivered 2026-07-02 by the fast-sync epic [[mingo-o5t1]]: `sbo-daemon bootstrap --node <url>` loads a verified snapshot to reach the tip in ~3s instead of a 15-20 min genesis replay — for any node that can bootstrap from a peer's snapshot. The remaining vus5 scope (fast FIRST sync from genesis without a snapshot source: avail-light/DAS, batched RPC) is separate.
