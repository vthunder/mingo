---
# mingo-lsjh
title: 'T2.1 checkpoint publishing (daemon): dual-trigger, sign+submit checkpoint.v1'
status: in-progress
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T17:34:58Z
parent: mingo-o5t1
---

[checkpoint] config (authority, writes>=100/blocks>=1000). On trigger h: state_root(h) -> sign+submit checkpoint.v1 via turbo.submit_raw. Genesis policy grants /sys/checkpoints/**; exclude checkpoint objects from write count.

## Progress 2026-07-02 (sbo 7e1a7f9)
DONE: config [checkpoint] (enabled/publish/key_file/every_writes=100/every_blocks=1000/snapshots_dir); dual-trigger scheduling in the sync task (caught-up + writes/blocks since last), computes state root + object set, generates snapshot at the tip (keep newest 3).
REMAINING (on-chain publish path): build+sign+submit checkpoint.v1 via turbo.submit_raw. Gated behind publish=true + key_file — currently WARNs and skips (a deliberate deploy decision; needs the sys/authority signing key on the daemon, or a delegated checkpoint identity + genesis policy grant). Enabled locally (snapshots generated + served); on-chain checkpoint objects not yet published.

## LIVE + VERIFIED 2026-07-02 (sbo ce7d450, da.sandmill.org)
Local checkpoint scheduling + snapshot generation working in prod:
- Log: 'checkpoint @ block 3562408: snapshot 17 objects, 44543 -> 9449 bytes (gz)'.
- /v1/sync-points advertises snapshots [3562408, 3562400] (survived redeploy — persistent /data), genesis, head, latest_state_root (matches snapshot root).
- /v1/snapshot?block=latest streams gzip + X-Snapshot-* headers; decompresses to 17 objects.
- Fast test cadence every_blocks=20 / every_writes=5; env-tunable (SBO_CHECKPOINT_EVERY_*).
STILL REMAINING (this bean): on-chain checkpoint.v1 publishing (publish path, needs authority key).
