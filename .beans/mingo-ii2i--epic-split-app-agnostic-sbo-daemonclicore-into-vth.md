---
# mingo-ii2i
title: 'Epic: split app-agnostic SBO (daemon/cli/core) into vthunder/sbo'
status: completed
type: epic
priority: normal
created_at: 2026-06-25T22:34:36Z
updated_at: 2026-06-26T09:41:34Z
---

Keep SBO app-agnostic by moving the generic crates back to vthunder/sbo and depending on them via pinned git dep (like browserid-ng). Decisions: revive vthunder/sbo; boundary B (generic content schemas stay in sbo as reference, community.v1 + mingo_genesis move to mingo); pinned git dep.

Boundary B is mechanically simple: sbo-core's validate_schema already passes through unknown schemas (_ => Ok(())), so removing community.v1 from core needs NO registry — community writes pass through; policy+attribution still enforce; mingo validates the descriptor client-side.

Phases:
1. Extract-in-place (this repo, tests green): new mingo-app crate (community.v1 schema + community/mingo_genesis presets) + thin mingo CLI (genesis --mingo, open-community); drop community.v1 dispatch arm; move wasm membership(); neutralize @mingo.place test fixtures in sbo crates.
2. Sync generic crates into vthunder/sbo (history-preserving), tag pinned rev.
3. Repoint mingo at sbo git deps.
4. Deploy rework: da builds stock sbo-daemon from sbo; mingo.place builds idp+spa+app from mingo; entrypoint seed stays in mingo.

One behavior change on record: daemon no longer schema-validates community.v1 (pass-through); acceptable since descriptors are sys-key-only and mingo validates at authoring.

## Progress (overnight, 2026-06-26)

- [x] Phase 1: extract mingo-app (community.v1 + mingo genesis + thin mingo CLI); sbo-core/cli app-agnostic. Committed 0a2d3af on mingo main. Tests green.
- [x] Phase 2: vthunder/sbo repopulated with the 10 generic crates as a standalone workspace; builds green (sbo-daemon 24+32 tests). Pushed a3483a1 on sbo main.
- [x] Phase 3: mingo depends on sbo-core via pinned git dep (rev a3483a1); removed the 10 sbo-* dirs from mingo; daemon Dockerfile now builds sbo-daemon from the sbo repo at SBO_REV. Committed d8bd4a1 on mingo main. mingo workspace builds against git dep; mingo-app 7 tests pass.
- [~] Phase 4: mingo.place redeployed green (idp+spa, 1m4s, 200). Daemon (da.sandmill.org) rebuilding from the sbo repo — long one-time rocksdb compile in progress. Persistent /data volume means no state re-sync.

## Phase 4 complete + Summary (2026-06-26)

Split done end-to-end and deployed.

- da.sandmill.org now runs the generic sbo-daemon built from vthunder/sbo @ a3483a1 (deploy/sbo-daemon/Dockerfile clones the sbo repo at SBO_REV, layers mingos entrypoint/config). Healthy: /v1/state-root 200; all 3 community policies serve membership:<id>; persistent /data volume meant no state re-sync.
- mingo.place rebuilt green from the lean workspace (mingo-idp has no sbo dep).

Incident: first daemon deploy failed with No space left on device on the dokku host (accumulated Docker layers from the days many deploys; build deps were cached so it reached the final link fast). Resolved with `ssh dokku@sandmill.org cleanup`; redeploy succeeded.

Follow-ups (non-blocking):
- Keep SBO_REV in deploy/sbo-daemon/Dockerfile in sync with the sbo-core git pin in mingo Cargo.toml when bumping sbo.
- The new daemon Dockerfile dropped cargo-chef for a git-clone+build (cache-mount incremental); fine, but a periodic `dokku cleanup` / docker builder prune on the host is advisable given disk pressure.
- Cosmetic: sbo crates still carry @mingo.place/cooks test fixtures; sbo-wasm still has a membership() helper. Neither couples; left for a later tidy.
- Optional: preserve per-crate git history into vthunder/sbo (currently a single re-add commit; full history remains in mingo).

## History preservation (done)

vthunder/sbo main rewritten to carry full per-crate history instead of the single re-add commit. Method: git filter-repo on a clone of mingo @ Phase-1 (0a2d3af) keeping only the 10 generic crate paths (158 commits, crates always at root — no path rewrite needed), merged --allow-unrelated-histories with sbo's deb0089 (preserving docs/specs 25-commit history), then the workspace manifest on top. Final tree byte-identical to the prior a3483a1 (verified git diff empty). New HEAD 8d66ec7 (400 commits; e.g. sbo-core/src/state/db.rs shows 11 commits). Force-pushed (safe — no consumers).

Re-pinned mingo (Cargo.toml rev + Dockerfile SBO_REV) to 8d66ec7; mingo builds green against it. Running daemon was built from the now-orphaned a3483a1 but is byte-identical, so NOT redeployed — SBO_REV updated for the next deploy. Both sites healthy.
