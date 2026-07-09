---
# mingo-cy17
title: 'Fast-sync snapshot is policy-incomplete: fast-synced node rejects /sys/* writes (No applicable policy found)'
status: todo
type: bug
priority: high
created_at: 2026-07-07T22:04:47Z
updated_at: 2026-07-07T22:05:21Z
parent: mingo-o5t1
blocking:
    - mingo-u1be
---

Found 2026-07-07 (mingo-hqp2 e2e). A node that fast-synced from a snapshot REJECTS subsequent /sys/checkpoints/* (and likely other policy-gated /sys) writes during walk-forward with 'policy:✗ (No applicable policy found)'. A full-replay-from-genesis node validates the same writes fine. So the snapshot state lacks the genesis policy context needed to L2-authorize later writes -> a fast-synced node's /sys state diverges going forward. See [[fast-sync-snapshot-policy-gap]].

Impact: affects ALL fast-sync consumers, not just attestors. The trustless CLIENT (mingo-8gau) works only because its trust-evidence path is signature-rooted (bypasses L2); but the client still can't correctly APPLY /sys writes post-bootstrap. Blocks mingo-u1be (fast-synced attestors) and undermines general fast-sync correctness.

Investigate: is the snapshot genuinely missing policy objects (snapshot generation omits them / a path filter), or is policy RESOLUTION broken by fast-sync (e.g. it walks a prev/policy_ref chain the snapshot truncated)? Fix so a fast-synced node has the full policy context. Relates to mingo-o5t1, mingo-u1be.
