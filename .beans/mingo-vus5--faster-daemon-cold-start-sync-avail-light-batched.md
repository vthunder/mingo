---
# mingo-vus5
title: Faster daemon cold-start sync (avail-light / batched RPC / snapshot)
status: todo
type: feature
priority: low
tags:
    - deploy
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T19:12:29Z
---

State now persists across deploys, so this only bites on volume loss. RPC-only sync replays genesis→tip one block at a time (~15-20 min). Options: run avail-light, batch/concurrent RPC range fetch, or ship/restore a RocksDB state snapshot.
