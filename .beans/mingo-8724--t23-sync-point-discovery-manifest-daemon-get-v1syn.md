---
# mingo-8724
title: 'T2.3 sync-point discovery manifest (daemon): GET /v1/sync-points'
status: completed
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T16:57:26Z
parent: mingo-o5t1
blocked_by:
    - mingo-sscg
---

Advertise genesis + checkpoints + snapshots + known attestations (+ later proofs). _sbo checkpoint=/node= points here.

## Done 2026-07-02 (sbo 7e1a7f9). GET /v1/sync-points: format, genesis (first_block+hash), head, latest_state_root, snapshots (from disk metas), checkpoints (on-chain /sys/checkpoints objects). RepoApi sync_points/snapshot_meta/snapshot_bytes (default no-op; DaemonState impls).
