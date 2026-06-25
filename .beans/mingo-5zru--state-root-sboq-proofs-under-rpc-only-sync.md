---
# mingo-5zru
title: State-root / SBOQ proofs under rpc_only sync
status: todo
type: task
priority: deferred
tags:
    - proofs
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T20:09:53Z
---

Older Phase 7.8 item: verify state-root recording and SBOQ proof generation (?proof=1) behave correctly under the RPC-only (no light client) sync path.

## Reclassified

Recategorized from bug → task (future hardening), priority → deferred. No known failure or repro; this is a verification/hardening item to confirm state-root recording + ?proof=1 SBOQ proofs hold up under RPC-only sync (DAS skipped, full-node RPC trusted). Pick up when the RPC-only path becomes load-bearing.
