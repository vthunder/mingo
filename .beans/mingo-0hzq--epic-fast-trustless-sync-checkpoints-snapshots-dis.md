---
# mingo-0hzq
title: 'Epic: fast trustless sync — checkpoints, snapshots, discovery, attestations, proofs'
status: todo
type: epic
priority: high
created_at: 2026-07-02T16:25:07Z
updated_at: 2026-07-02T16:25:07Z
---

Progressive path to fast client sync (minutes→seconds) at selectable trust levels, per the plan agreed 2026-07-02.

Trust spectrum (same snapshot download path, differ in why you trust the root):
- T2-sys: trust the checkpoint authority (sys) signature on the state_root.
- T2-attest: web-of-trust — parties post on-chain checkpoint attestations; client accepts once enough trusted attestors agree (client-chosen set, no fixed validator set).
- T1-zk: verify a proof; trustless.

Cadence: configurable dual-trigger — checkpoint after >=100 confirmed writes (excluding checkpoint objects) OR >=1000 DA blocks, whichever first. Spec RECOMMENDS a max-staleness bound, never mandates a cadence.

Quirk (by design): snapshot@h and state_root(h) exclude the checkpoint object itself (computed before submit); client rebuilds trie from snapshot -> matches root; checkpoint object picked up in tail replay. Confirmed + tip-height only; no historical snapshots.

Reuses: compute_trie_state_root, record_state_root/get_state_root_at_block, list_objects, turbo.submit_raw, validate_message, attestation model.
