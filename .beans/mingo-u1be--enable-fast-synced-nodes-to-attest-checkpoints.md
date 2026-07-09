---
# mingo-u1be
title: Enable fast-synced nodes to attest checkpoints
status: todo
type: feature
priority: normal
created_at: 2026-07-06T21:45:27Z
updated_at: 2026-07-06T21:45:45Z
parent: mingo-o5t1
blocked_by:
    - mingo-blpo
---

Enable a node that FAST-SYNCED (loaded a snapshot, didn't full-replay) to also act as a checkpoint attestor. Today it cannot, for two reasons found during the mingo-hqp2 e2e test (2026-07-06):

1. A fast-synced node REJECTS `/sys/checkpoints/*` writes during walk-forward with `policy:✗ (No applicable policy found)` — its snapshot state lacks the genesis policy context to L2-authorize them (see [[fast-sync-snapshot-policy-gap]]). So the checkpoint objects never enter its state.
2. `attest_if_due` (main.rs) reads checkpoints from its STATE DB (`list_objects_by_path_prefix("/sys/checkpoints/")`) and reproduces roots via `get_state_root_at_block`. Both require the checkpoint object + recorded roots to be in state — which #1 prevents.

NOTE: the trustless-CLIENT fix (mingo-8gau, signature-rooted evidence) does NOT help the attestor — it's a consumer-side path; the attestor is a producer reading from state.

## Options
- A. Fix the underlying fast-sync snapshot policy-completeness gap so a fast-synced node can apply /sys writes normally (also fixes general fast-sync correctness). Preferred if the gap is a snapshot-content bug.
- B. Decouple `attest_if_due` from state: observe checkpoints via a signature-rooted stream (like the client), independently reproduce the root forward from the snapshot height, and attest — without needing the checkpoint object applied to state.

Depends on / relates to mingo-blpo (attestation owner bug) and mingo-8gau.
