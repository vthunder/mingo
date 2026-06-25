---
# mingo-4p82
title: 'Speed up deploys: pin base image + parallelize'
status: in-progress
type: task
priority: normal
created_at: 2026-06-25T20:31:05Z
updated_at: 2026-06-25T20:31:05Z
---

Deploys take ~8min. Root cause: Dockerfiles use moving tag rust:1-bookworm with no pin, so any Docker Hub rust:1 patch invalidates the cargo-chef/apt/rocksdb cache layers; and make deploy runs the two apps sequentially. Fixes: (1) pin base to rust:1.93-bookworm in both Dockerfiles so the dep+rocksdb layers stay cached; (2) parallelize make deploy (independent dokku apps).

- [ ] Pin deploy/sbo-daemon/Dockerfile base to rust:1.93-bookworm
- [ ] Pin deploy/mingo/Dockerfile base to rust:1.93-bookworm
- [ ] Parallelize make deploy (run both pushes concurrently)
- [ ] Verify a deploy is faster
