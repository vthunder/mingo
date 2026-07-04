---
# mingo-b0y5
title: 'Spec edits: State Commitment (checkpoints/snapshots/attestations/discovery) + Genesis/Policy/Indexer notes'
status: scrapped
type: task
priority: high
created_at: 2026-07-02T16:25:07Z
updated_at: 2026-07-04T17:52:39Z
---

State Commitment spec: flesh out Checkpoints (optional, publisher-chosen cadence w/ RECOMMENDED max-staleness bound, sys-or-delegated authority, exclude-self root rule); add Snapshots section (compact+compressed object-set at checkpoint height, self-verifying rebuild-trie==checkpoint root, tip-only); add Checkpoint attestations (checkpoint-attestation.v1, /u/<attestor>/attestations/checkpoints/block-<h>, client-chosen trust); add Sync-point discovery (node manifest). Indexer/Client: bootstrap/fast-sync subsection. Genesis+Policy: grant /sys/checkpoints/** to authority. URI/Genesis: checkpoint=/node= may point at the manifest.

## Reasons for Scrapping
Duplicate bean. The real, worked copy lives under epic mingo-o5t1: mingo-0hzq duplicates that epic (no children); mingo-chfi duplicates the completed T2.1 checkpoint-publishing task mingo-lsjh; mingo-b0y5 duplicates the completed spec-edits task mingo-eg7g. Scrapped 2026-07-04 during fast-sync thread review.
