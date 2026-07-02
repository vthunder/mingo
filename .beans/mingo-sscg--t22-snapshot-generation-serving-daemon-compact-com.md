---
# mingo-sscg
title: 'T2.2 snapshot generation + serving (daemon): compact compressed object-set at checkpoint height'
status: completed
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T16:57:26Z
parent: mingo-o5t1
blocked_by:
    - mingo-lsjh
---

Export all objects to compact compressed snapshot {block:h, claimed_state_root}; store under /data; serve GET /v1/snapshot?block=h + metadata; checkpoint heights only.

## Done 2026-07-02 (sbo 7e1a7f9). Snapshot module (gzip object-set + meta sidecar, atomic write, round-trip test reproducing the DB state root) + generation at checkpoint heights in the sync task + GET /v1/snapshot?block=<n|latest> (streamed, X-Snapshot-* headers). Enabled on the daemon (deploying).
