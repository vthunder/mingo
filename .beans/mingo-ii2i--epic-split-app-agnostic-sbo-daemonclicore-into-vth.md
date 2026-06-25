---
# mingo-ii2i
title: 'Epic: split app-agnostic SBO (daemon/cli/core) into vthunder/sbo'
status: in-progress
type: epic
priority: normal
created_at: 2026-06-25T22:34:36Z
updated_at: 2026-06-25T22:34:36Z
---

Keep SBO app-agnostic by moving the generic crates back to vthunder/sbo and depending on them via pinned git dep (like browserid-ng). Decisions: revive vthunder/sbo; boundary B (generic content schemas stay in sbo as reference, community.v1 + mingo_genesis move to mingo); pinned git dep.

Boundary B is mechanically simple: sbo-core's validate_schema already passes through unknown schemas (_ => Ok(())), so removing community.v1 from core needs NO registry — community writes pass through; policy+attribution still enforce; mingo validates the descriptor client-side.

Phases:
1. Extract-in-place (this repo, tests green): new mingo-app crate (community.v1 schema + community/mingo_genesis presets) + thin mingo CLI (genesis --mingo, open-community); drop community.v1 dispatch arm; move wasm membership(); neutralize @mingo.place test fixtures in sbo crates.
2. Sync generic crates into vthunder/sbo (history-preserving), tag pinned rev.
3. Repoint mingo at sbo git deps.
4. Deploy rework: da builds stock sbo-daemon from sbo; mingo.place builds idp+spa+app from mingo; entrypoint seed stays in mingo.

One behavior change on record: daemon no longer schema-validates community.v1 (pass-through); acceptable since descriptors are sys-key-only and mingo validates at authoring.
