---
# mingo-1o7t
title: Deleted post lingers in pending state, never clears
status: completed
type: bug
priority: normal
created_at: 2026-07-17T06:33:30Z
updated_at: 2026-07-17T06:33:56Z
---

After an author (or moderator) deletes their own post/comment, the object leaves head on confirmation, but the daemon overlay serves it as confirmed:false (pending) through the delete's confirmation window. The feed/thread rendered it as a permanent 'pending…' card that never disappeared, because the live poll (liveAppend) only APPENDED rows and never removed them, and nothing filtered the just-deleted object out of re-renders. Follow-up to mingo-3go6 (author delete).

## Root cause

A post/edit clears its pending state by CONFIRMATION: the app polls `getSpaceItems`
until the object comes back `confirmed:true`, then re-renders. A delete has no such
signal — a deleted object confirms by being ABSENT from head, so there is no
confirmed record to match. Meanwhile the daemon's confirmed+pending overlay keeps
serving the object as `confirmed:false` for the whole confirmation window, so every
render drew it as a normal pending card. The live poll (`liveAppend`) only ever
APPENDED rows keyed by uri and never removed any, so once the object finally left
head the already-rendered pending card was never pulled — it lingered forever.

## Summary of Changes (mingo-web/app.js)

- Added a module-level `deletedUris` Set. `beginDelete` adds the item's uri right
  after `deleteContent` resolves.
- `getSpaceItems` filters out any object whose uri is in `deletedUris`, so the
  just-deleted post/comment drops out of every render (the 1.2s `route()` rebuild
  and all polls) and can't reappear from the stale pending overlay entry.
- `liveAppend` now RECONCILES both directions: besides appending new rows, it
  removes any rendered row whose uri is no longer in the fresh list (walking up
  from the `data-receipt` mark to the container's direct child). This makes a
  delete vanish once the object leaves head, and also fixes deletes made in
  another session lingering in this client's feed/thread/mod views.
- Thread top-post delete was already handled: `viewThread` shows "This post was
  deleted…" when the post isn't in `posts` (now also true via `deletedUris`).

## Verify on the live site

Sign in on mingo.place, open a post you authored, delete it via the kebab (or the
inline delete). The card should show briefly then DISAPPEAR within ~1.2s and stay
gone (previously it stuck as a "pending…" card forever). Same for a comment, and
for a moderator remove in the per-board mod view. Navigating away and back must not
bring it back.
