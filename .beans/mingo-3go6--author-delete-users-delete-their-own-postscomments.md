---
# mingo-3go6
title: 'Author delete: users delete their own posts/comments'
status: completed
type: feature
priority: normal
created_at: 2026-07-16T21:22:22Z
updated_at: 2026-07-16T21:36:10Z
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

- [x] Client delete path: `writeContent` variant with `action:"delete"` targeting the object's (path,id)
- [x] Poster support (mobile): add `action:delete` warrant scope to mingo-poster (`mingo-idp/src/poster.rs:104` default_scopes are `action:post` only) — decided (dan, 2026-07-16)
- [x] UI: delete item in the kebab menu (placeholder slot at `mingo-web/app.js:1160`), owner-gated via `ownItem`, with confirmation
- [x] Cascade UI: comments are independent objects — no chain-side cascade; hide orphaned comments / the thread when the parent post is deleted
- [x] Verify delete of a comment (not just posts) end-to-end

## Summary of Changes

Owner-delete for posts and comments, wired through both signing paths.

**Client delete path (`mingo-web/app.js`).** `writeContent` now takes an
optional `action` (defaults to the previous empty/`post` behavior), threaded
into both the sbo-wasm `EnvelopeSpec` (client signing) and `submitViaPoster`.
New `deleteContent(item)` issues an `action:"delete"` write to the object's
`(path,id)` with an empty payload, passing the object's schema
(`post.v1`/`comment.v1`) so a poster-signed delete satisfies the warrant's
`schema:` scope. The email-rooted path already sets `Owner = session.email`
(required by the broker signer and equal to the object's `owner_ref`), so the
daemon's owner fast path authorizes it — verified in sbo that `Action::Delete`
routes through `validate_transfer` and authorizes via
`l2_authorize(owner_ref)` against the stored owner, using the envelope's
`Auth-Cert` + on-chain `/sys/dnssec` proof (kept fresh by the existing
`ensureDnssecFresh`). No policy, genesis, or sbo changes.

**Poster support (`mingo-idp/src/poster.rs`).** Added `action:delete` to the
warrant `default_scopes` (kept tight — only post + delete, same path/schema
scoping). `SubmitReq` gained an optional `action` field; `/poster/submit`
parses it to `Action::Post`/`Action::Delete` (rejecting anything else) instead
of hardcoding post. The daemon's agent-authorization checks the warrant's
`action:`/`schema:` scopes against `msg.action.name()` (`"delete"`) and
`msg.content_schema`, and resolves the effective author to the delegating user
via the `as:` scope — so a poster-signed delete attributes to and is authorized
as the user, same as their posts.

**UI (`mingo-web/app.js`, `style.css`).** Owner-only Delete item in the post
kebab menu (`cardMenu`) and a `delete` link on comment meta-lines
(`commentBox` via new `deleteLink`), both gated by `ownItem`. `beginDelete`
mirrors `beginEdit`: it swaps the `data-body` element for an inline
confirmation ("removes it for everyone… can't be undone"); Cancel restores,
Delete writes then re-renders via `route()` after the same ~1.2s settle. New
`wireDeleteButtons()` is called at every card-menu render site. A trash
`ICON_DELETE` and `.danger` styling for link/primary buttons were added.

**Cascade UI.** No chain-side cascade (comments are independent objects). A
deleted post is simply absent from head `posts`, so the feed omits it
automatically; `viewThread` now renders a graceful "This post was deleted or
doesn't exist." state (with a back link) instead of rendering the orphaned
thread — and since the post is the only entry point to its comments, orphaned
comments never surface.

## Verification

- `cargo test -p mingo-idp` — 27 tests pass, including two new poster tests:
  `default_scopes_authorize_owner_delete` (asserts `action:delete` in scope and
  that `scopes_authorize` admits a delete of `post.v1`/`comment.v1` while still
  refusing an out-of-grant action) and
  `assembled_delete_round_trips_as_the_delegating_user` (a `Action::Delete`
  agent write parses back attributed to the delegator).
- `node --check mingo-web/app.js` passes.
- Confirmed against pinned sbo (no pin bump needed): the sbo-wasm kit already
  supports `action:"delete"` (`kit.rs:46-48,102-105`); the broker signer
  (`sbo-sign.js`) is action-agnostic and signs the delete envelope unchanged;
  the delete round-trips through the wire parser (Content-Length:0 present →
  payload `Some(empty)`, signature verifies). Both posts and comments share the
  identical delete code path (only the schema differs), so comment-delete is
  covered by the same verification.
- Not run: a live browser→broker→daemon end-to-end (needs a running daemon +
  broker + live DNSSEC; out of scope per the no-deploy constraint). Verified by
  code trace + unit tests instead.

## Open issues

- **Existing poster users must re-enable to delete.** Warrants already granted
  carry only `action:post`; the new `action:delete` scope applies to warrants
  minted after this change, so a mobile user who delegated before it must
  re-enable mingo-poster (or the delete falls back to a client-signing popup)
  before a poster-signed delete authorizes. First-party (client-signed) delete
  is unaffected. Kept tight per the bean's scope decision rather than
  broadening existing grants.
