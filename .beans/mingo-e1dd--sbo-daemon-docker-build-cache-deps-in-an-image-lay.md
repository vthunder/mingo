---
# mingo-e1dd
title: 'sbo-daemon Docker build: cache deps in an image layer (cargo-chef)'
status: in-progress
type: task
priority: high
created_at: 2026-07-04T18:21:34Z
updated_at: 2026-07-04T18:42:55Z
---

Every sbo-daemon deploy cold-rebuilds the ENTIRE dependency tree (rocksdb, frame-metadata, rustls, bindgen, zstd/lz4/bzip2-sys, risc0 deps…), even for a one-line code change. Observed live on the f4c6e69 deploy: 300s+ still compiling third-party deps.

## Root cause
deploy/sbo-daemon/Dockerfile builds in a single `cargo build` RUN whose only caching is BuildKit `--mount=type=cache` on /src/target + cargo registry. Dokku does NOT persist BuildKit cache mounts across deploys, so target/ is empty every build → full cold compile. Bumping SBO_REV also resets source mtimes on the fresh `git clone`, forcing all workspace crates to recompile regardless.

## Fix: cargo-chef multi-stage (durable image-layer dep cache)
- planner stage: clone sbo@REV, `cargo chef prepare` → recipe.json (content-stable; changes only when the dep graph changes).
- builder stage: `cargo chef cook --release -p sbo-daemon` → dependency compilation becomes a normal IMAGE LAYER keyed on recipe.json content. Dokku persists image layers, so a code-only rev bump = cook cache HIT (deps not rebuilt). Then copy source + `cargo build --release -p sbo-daemon` (only the changed sbo workspace crates recompile — small).
- Keep the BuildKit cache mounts too as a second-level accelerator (harmless when cold).

## Acceptance
- After one warm build, a code-only SBO_REV bump deploys without recompiling rocksdb/frame-metadata/etc.
- da.sandmill.org daemon still builds + runs.

## Implemented (2026-07-04), pending deploy-verification
Rewrote deploy/sbo-daemon/Dockerfile to cargo-chef multi-stage: planner (clone sbo@REV → recipe.json) + build (cargo chef cook deps as an image layer, then cargo build the daemon). Removed the /src/target cache mount from the cook/build stages (cooked deps must land in the image LAYER, not an ephemeral mount). Kept registry/git cache mounts as a second-level accelerator.
- [ ] Deploy + confirm first (warm) build succeeds and daemon runs.
- [ ] Prove a code-only SBO_REV bump then skips the dep tree (cook cache HIT).
