---
# mingo-chfi
title: 'T2.1 checkpoint publishing (daemon): dual-trigger, sign+submit checkpoint.v1'
status: todo
type: task
priority: high
created_at: 2026-07-02T16:25:07Z
updated_at: 2026-07-02T16:25:07Z
---

[checkpoint] config (authority key, thresholds writes>=100 / blocks>=1000). On trigger at height h: read state_root(h), build+sign checkpoint.v1{block:h,state_root,prev_checkpoint}, submit via turbo.submit_raw. Genesis policy must grant /sys/checkpoints/**. Excludes checkpoint objects from the write trigger count.
