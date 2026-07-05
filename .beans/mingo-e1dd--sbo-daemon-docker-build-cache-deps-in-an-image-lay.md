---
# mingo-e1dd
title: 'sbo-daemon Docker build: cache deps in an image layer (cargo-chef)'
status: in-progress
type: task
priority: high
created_at: 2026-07-04T18:21:34Z
updated_at: 2026-07-05T10:14:04Z
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

## First cache test did NOT hit (2026-07-04) — diagnosis
Deployed a code-only SBO_REV bump (f4c6e69 -> 386a890). The cargo chef cook layer (#16) cache-MISSED and recompiled the dep tree; #15 'COPY recipe.json' was also not cached, so recipe.json DIFFERED between the two builds.
Cause (likely): no Cargo.toml/lock changed, BUT 386a890 also ADDED crates/sbo-zkvm/tests/recursion.rs — a new auto-discovered integration-test TARGET. cargo-chef's recipe.json captures workspace targets, so adding a target changes the recipe → cook re-runs. Base/apt/cargo-chef-install layers DID cache (#3,#9,#10,#11), so Dokku IS persisting image layers; only the recipe-derived cook layer changed.
Implication: a PURE src edit to existing files (no added/removed bin/test/example targets) should cache-hit. NOT yet proven.
- [ ] Definitive test: deploy a trivial src-only change (no new targets) and confirm cook shows CACHED.
- [ ] If recipe is still unstable, consider the manual dummy-src dep layer (copy only Cargo.toml/lock) instead of cargo-chef, which is target-insensitive.

## Definitive src-only cache test: recipe STABLE, cook layer EVICTED (2026-07-05)
Deployed a pure src-only bump (386a890 -> 5424058, mingo 765a455). Layer results:
- #15 COPY recipe.json = CACHED → recipe.json is now byte-identical for a src-only change (cargo-chef structure works as intended).
- #16 cargo chef cook = MISS → recompiled the full dep tree (~40min: frame-metadata, rocksdb, ...).
Small layers (#10/#11/#15) cache but the giant cook layer is evicted between deploys = BuildKit build-cache GC dropping the largest layer on the Dokku host. NOT a Dockerfile-shape problem; cargo-chef was necessary but insufficient.

## Real fix: persist deps as a registry artifact, not build cache
Build cache is GC'd; a pushed image layer is not. Options:
- (recommended) Bake cooked deps into a BASE IMAGE pushed to a registry: a deps stage runs cargo chef cook, tagged registry/sbo-deps:<Cargo.lock hash>; the daemon Dockerfile does FROM it. Rebuild the base only when Cargo.lock changes; every deploy PULLS it (fast). Survives GC.
- (alt) BuildKit registry cache export: --cache-to type=registry,ref=... / --cache-from same, or BUILDKIT_INLINE_CACHE=1 with a pushed image. Needs Dokku buildx/cache config.
- (alt) Raise the Dokku host BuildKit GC keep-bytes so the cook layer isn't evicted (fragile; host-level).
- [ ] Implement the registry base-image approach; verify a src-only bump then pulls deps instead of recompiling.

Also update the global CLAUDE.md Dokku note: cargo-chef/image-layer caching still loses to BuildKit GC on Dokku for very large layers — persist expensive layers as a pushed registry image, not build cache.

## Resolution: build in CI, deploy by image (2026-07-05)
Root cause is the dokku host's 24G disk (8.6G free) — too small to hold a warm Rust build cache, so BuildKit GC evicts the dep layer every deploy. No on-host Dockerfile trick can fix a too-small disk.
Fix: GitHub Actions (free for these PUBLIC repos) builds deploy/sbo-daemon/Dockerfile with a persistent type=gha layer cache, pushes ghcr.io/vthunder/sbo-daemon:<sha>, and dokku deploys via git:from-image (PULLS the ~100MB image; host never compiles). cargo-chef finally pays off since GHA retains the cook layer.
Added: .github/workflows/deploy-daemon.yml; Makefile deploy-daemon -> gh workflow run (old host build kept as deploy-daemon-onhost).
- [ ] One-time setup: add DOKKU_SSH_KEY repo secret; make the GHCR package public (or give dokku registry creds); confirm dokku git:from-image works for this app version.
- [ ] First workflow run + verify da.sandmill.org serves + subsequent src-only deploy is fast (cook cached).
