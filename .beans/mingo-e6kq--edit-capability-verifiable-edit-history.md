---
# mingo-e6kq
title: Edit capability + verifiable edit history
status: completed
type: feature
priority: normal
created_at: 2026-07-16T00:26:19Z
updated_at: 2026-07-16T01:00:46Z
parent: mingo-y9gb
---

Let authors edit their posts/comments, with a visible, cryptographically-verifiable edit history.

## Notes
- SBO objects carry a prev chain; an edit is a new signed version of the same object id referencing prev. LWW by HLC resolves the head version. So edit = re-sign the object with updated payload + prev = current head hash.
- UI: edit affordance on own content; an 'edited' badge; tap to see prior versions, each with its own signature/receipt (ties into the provenance panel — each version is independently attributable).
- Interacts with moderation/delete: a delete after edits removes the head; history retains the versions (same substrate semantics as the moderation bean).
- Confirm the daemon accepts an update to an existing (path,id) by the same owner and that prev is validated as expected; HLC must advance (mind the same authoring-lag bound the seeder hit).
- Nice demo: edit a post, open the receipt, show the version chain each signed by the same identity.

## Summary
Edit SHIPPED (overnight). Owner-only inline editor; Save re-writes same (path,id) with prev=head object_hash (owner update, same signing path as compose). 'edited' meta tag once an object has a prev. Owner-gating verified (0 affordances signed-out). DEFERRED: version-history viewer needs daemon history reads (HEAD-only today). AWAITS ON-DEVICE: the live edit WRITE.
