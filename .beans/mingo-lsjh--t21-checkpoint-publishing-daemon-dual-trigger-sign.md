---
# mingo-lsjh
title: 'T2.1 checkpoint publishing (daemon): dual-trigger, sign+submit checkpoint.v1'
status: todo
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T16:25:37Z
parent: mingo-o5t1
---

[checkpoint] config (authority, writes>=100/blocks>=1000). On trigger h: state_root(h) -> sign+submit checkpoint.v1 via turbo.submit_raw. Genesis policy grants /sys/checkpoints/**; exclude checkpoint objects from write count.
