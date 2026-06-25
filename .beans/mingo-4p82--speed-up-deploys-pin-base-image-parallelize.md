---
# mingo-4p82
title: 'Speed up deploys: pin base image + parallelize'
status: completed
type: task
priority: normal
created_at: 2026-06-25T20:31:05Z
updated_at: 2026-06-25T21:40:10Z
---

Deploys take ~8min. Root cause: Dockerfiles use moving tag rust:1-bookworm with no pin, so any Docker Hub rust:1 patch invalidates the cargo-chef/apt/rocksdb cache layers; and make deploy runs the two apps sequentially. Fixes: (1) pin base to rust:1.93-bookworm in both Dockerfiles so the dep+rocksdb layers stay cached; (2) parallelize make deploy (independent dokku apps).

- [x] Pin deploy/sbo-daemon/Dockerfile base to rust:1.93-bookworm
- [x] Pin deploy/mingo/Dockerfile base to rust:1.93-bookworm
- [x] Parallelize make deploy (make -j2)
- [x] Verified (see findings) — but the verify deploy itself cost 58min (one-time cache re-warm)

## Findings

- The base-tag change (rust:1-bookworm -> rust:1.93-bookworm) invalidated the cargo-chef dep layer, forcing a **one-time** full rebuild. On the dokku host the bundled rocksdb C++ compile alone is ~47min (librocksdb-sys+rocksdb). Total verify deploy = **58min**. This cost is now paid and cached under the pinned tag; it will NOT recur on normal deploys, and crucially can no longer be triggered randomly by a Docker Hub rust:1 patch (the original failure mode).
- BUT: the steady-state ~8min warm deploy is dominated by recompiling OUR crates (sbo-core + sbo-daemon) at opt-level=3 and linking the static rocksdb binary — not by deps. The pin does not reduce this; it only prevents the occasional much-worse rebuild.
- Both apps healthy post-deploy (mingo.place 200; daemon /v1/state-root 200 @ block 3532453). The brief 500 was old-container shutdown overlap.

## Follow-up lever (not yet applied — costs one more ~47min rebuild)

To cut the recurring ~8min warm deploy, set in root Cargo.toml:
  [profile.release] opt-level = 2  (daemon is I/O-bound on RocksDB/network, not CPU)
  incremental = true  (the BuildKit target/ cache mount persists, so only changed codegen units recompile next time)
Caveat: changing [profile.release] invalidates the dep cook once -> one more full rocksdb rebuild to bank it. Worth batching if/when other dep changes land. Deferred pending decision.

## Resolution

Shipped three changes (all deployed):
1. Pinned both Dockerfiles to rust:1.93-bookworm — eliminates the random ~47min rocksdb rebuild that a moving rust:1 tag could trigger.
2. Parallelized make deploy (make -j2) — independent dokku apps build concurrently.
3. [profile.release] incremental = true — cache-safe (Cargo never compiles registry deps incrementally, so rocksdb fingerprint unchanged). Verified: the deploy banking this change compiled ONLY sbo-core (~40s) + sbo-daemon (~110s+link), zero rocksdb compilation. Subsequent code-change deploys now recompile only changed codegen units.

Both apps healthy post-deploy (mingo.place 200, daemon 200). opt-level deliberately left at 3 to avoid a dep rebuild.
