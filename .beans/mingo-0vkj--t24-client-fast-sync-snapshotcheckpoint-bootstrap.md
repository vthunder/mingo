---
# mingo-0vkj
title: 'T2.4 client fast-sync: snapshot+checkpoint bootstrap, tail from h+1'
status: completed
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T18:44:38Z
parent: mingo-o5t1
blocked_by:
    - mingo-8724
---

Fetch manifest -> snapshot -> rebuild trie -> fetch on-chain checkpoint.v1 -> assert root match -> load state, head=h, tail. Selectable trust.

## DONE + demonstrated live 2026-07-02 (sbo cd9a773)
bootstrap module (verify_and_load: rebuild trie == trusted root BEFORE any write, refuse forged; fetch_manifest + fetch_snapshot HTTP; bootstrap() orchestrator) + `sbo-daemon bootstrap --node <url> [--state-dir]` subcommand. Trust selectable: OnChainCheckpoint if advertised at the snapshot height, else ServingNode (node's root).
VERIFIED LIVE: bootstrap --node https://da.sandmill.org loaded a fresh state DB to block 3,562,608 with a verified root in ~3.4s (vs ~15-20 min genesis replay). trust=ServingNode (upgrades to OnChainCheckpoint once T2.1 publish is on). Tests: verify_and_load accepts matching / rejects forged.
