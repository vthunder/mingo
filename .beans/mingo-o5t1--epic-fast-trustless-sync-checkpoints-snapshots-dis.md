---
# mingo-o5t1
title: 'Epic: fast trustless sync — checkpoints, snapshots, discovery, attestations, proofs'
status: todo
type: epic
priority: high
created_at: 2026-07-02T16:25:19Z
updated_at: 2026-07-02T18:44:38Z
---

## T2 read-side LIVE 2026-07-02
Spec v0.3 + snapshot module + checkpoint scheduling + /v1/snapshot + /v1/sync-points deployed and verified on da.sandmill.org (sbo ce7d450). Snapshots generate at tip on a fast test cadence (env-tunable), compress ~79%, serve + manifest working, survive redeploys.
NEXT: T2.1 on-chain publish (key), T2.4 client fast-sync (consume snapshot+checkpoint, tail from h+1), T2.5 checkpoint attestations, T1 prover.

## T2.4 client fast-sync LIVE 2026-07-02: ~3s bootstrap from da.sandmill.org (verified snapshot -> block 3.56M) vs 15-20 min replay. Read-side (T2.1-local/T2.2/T2.3) + client bootstrap (T2.4) all done. REMAINING: T2.1 on-chain publish (authority key), T2.5 checkpoint attestations, T1 prover. This effectively delivers mingo-vus5 (faster cold-start) — link/close it.
