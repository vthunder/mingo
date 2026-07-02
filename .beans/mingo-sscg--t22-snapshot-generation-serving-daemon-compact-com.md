---
# mingo-sscg
title: 'T2.2 snapshot generation + serving (daemon): compact compressed object-set at checkpoint height'
status: todo
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T16:25:37Z
parent: mingo-o5t1
blocked_by:
    - mingo-lsjh
---

Export all objects to compact compressed snapshot {block:h, claimed_state_root}; store under /data; serve GET /v1/snapshot?block=h + metadata; checkpoint heights only.
