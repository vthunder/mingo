---
# mingo-3go6
title: 'Author delete: users delete their own posts/comments'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-16T21:22:22Z
updated_at: 2026-07-16T21:26:56Z
parent: mingo-6phv
---

Phase 1 of moderation (mingo-6phv): owner-delete affordance, live-chain-ready today with zero policy changes.

## Scope

Authors delete their own posts and comments. No policy change, no chain ops, no boards dependency — verified 2026-07-16 that the owner-can-always-act fast path in sbo (`validate_transfer`, sbo `crates/sbo-daemon/src/validate.rs:912-928`) runs BEFORE the policy check, so owner-delete is authorized on the live chain today regardless of community policy grants.

## Mechanism (verified in sbo)

- `Action::Delete` hard-removes the object from head state + file mirror (`sync.rs:990-1007` — `state_db.delete_object`, not a tombstone). Only the delete envelope remains in block history; content is recoverable only by replaying from before the delete. Exactly the credible-delete requirement.
- sbo-wasm kit already supports `action: "delete"` in `EnvelopeSpec` (sbo `crates/sbo-wasm/src/kit.rs:46-48,102-105`). mingo-web hardcodes `action: ""` in `writeContent` (`mingo-web/app.js:612`) — delete is a new write path setting `action:"delete"`.
- Feeds/threads read head via `/v1/list` with no persistent client cache — deleted items vanish on next `route()` re-render, no invalidation needed (same pattern as edit).

## Todos

- [ ] Client delete path: `writeContent` variant with `action:"delete"` targeting the object's (path,id)
- [ ] Poster support (mobile): add `action:delete` warrant scope to mingo-poster (`mingo-idp/src/poster.rs:104` default_scopes are `action:post` only) — decided (dan, 2026-07-16)
- [ ] UI: delete item in the kebab menu (placeholder slot at `mingo-web/app.js:1160`), owner-gated via `ownItem`, with confirmation
- [ ] Cascade UI: comments are independent objects — no chain-side cascade; hide orphaned comments / the thread when the parent post is deleted
- [ ] Verify delete of a comment (not just posts) end-to-end
