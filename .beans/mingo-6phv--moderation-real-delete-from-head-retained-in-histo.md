---
# mingo-6phv
title: 'Moderation: real delete (from head, retained in history) for users and moderators'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T00:25:52Z
updated_at: 2026-07-16T20:56:59Z
parent: mingo-y9gb
---

Both authors and board moderators need to DELETE content. Explicit product decision (dan, 2026-07-16), overriding the earlier hide+reveal/tombstone proposal:

## Requirement
- Delete removes the object from the CURRENT/head version of the repo — most clients read head, so the content is gone for them.
- It remains in on-chain HISTORY (append-only substrate; you can't unpublish from the ledger), BUT any node that does not retain history will not have the historical object. That history-less-node behavior is DESIRABLE, not a caveat.
- Rationale: credible deletion is mandatory for a real forum — illegal content, IP takedowns, or worse. 'Hide but always revealable' is not acceptable for those cases. Do NOT build reveal-anyway as the primary mechanism.

## Who can delete
- Authors: delete their own posts/comments (owner delete — the root policy already grants owner delete on /u/$owner/**; confirm it extends to authored content in /communities/**, may need a grant).
- Moderators: delete others' content in their board. Moderator = a board-scoped attestation (e.g. moderator:<commId>), issued by the board issuer/creator (ties into user-created-boards + passport). The community policy grants delete on /communities/<id>/spaces/** to the moderator role.

## Mechanism (verify in sbo at build)
- SBO has a delete action (crates/sbo-daemon/src/validate.rs validate_delete; hub root policy grants admin delete on /**). Confirm delete tombstones the object at head while the wire remains in block history, and that history-pruning nodes drop it. See bean mingo-0jkl (object move/admin authority) for prior art.
- UI: a delete affordance on posts/comments (author's own always; moderator on any in their board), with confirmation. Deleted items vanish from feed/thread on next read.
- Moderation surface: a minimal mod view per board (recent items + delete); grant/revoke moderator attestations (board creator only).

## Note
This reframes the provenance/receipt story: receipts show what IS at head; a deleted object simply isn't served. Don't contradict the 'credible delete' message with a prominent 'view removed anyway' button.

## Autonomous-run note (2026-07-16) — deferred, needs you
Confirmed tonight in sbo: Delete is a distinct action (transfer-to-null-owner); the community policy grants members only "post" (=create/update), NOT delete. So author-delete of own posts AND moderator-delete both require NEW policy grants (owner-delete on /communities/**/spaces/**, and a moderator-role delete grant) — i.e. a root/community policy change on the live chain, deferred as risky-unsupervised. Also depends on boards (moderator = board-scoped attestation). The delete MECHANISM itself (removes from head, retained in history, absent on history-pruning nodes) is exactly as you specified and is what Action::Delete does. Also surfaced: the space "post" grant is path-scoped, so today a member could in principle overwrite another member owner object via update — worth fixing with owner-scoped update grants when we touch this policy.

## Finding (2026-07-16): hub-root admin delete does NOT reach community content
Verified live: the community policy at /communities/<id>/ SHADOWS the hub root policy for its subtree (resolve_policy uses the closest policy). The hub root's {to:admin(sys), can:[...,delete], on:/**} therefore does NOT authorize deleting objects under /communities/**. Right now the community policy grants only member:create + owner:update (sbo-qv95) — NO delete — so the ONLY party that can delete community content is the content OWNER (via the owner-can-always-act fast path). sys/admin CANNOT delete a community post (observed: 'Policy: Signer does not control owner … and policy denies'). => moderation MUST add delete grants IN the community policy (owner-delete + moderator-role delete + issuer delete, per the earlier policy design), not rely on the hub-root admin grant. Ownership is by EMAIL, so an owner can delete after re-provisioning their email's cert (used this to clean the two_writer test posts).
