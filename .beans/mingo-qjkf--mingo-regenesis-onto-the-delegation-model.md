---
# mingo-qjkf
title: mingo regenesis onto the delegation model
status: todo
type: task
created_at: 2026-07-16T23:40:18Z
updated_at: 2026-07-16T23:40:18Z
---

Part of sbo-orvt composition. Once sbo P1-P4 land, regenesis the mingo chain onto the new root policy shape.

- Root policy (sys-owned) RESERVES {to: admin(key=sys), can:[delete], on:/communities/<id>/**} (community-removal hammer) + the illegal-content/abuse restriction; declares the descendant-constraint clause for community policies.
- Root delegates `govern` on /communities/<id>/ to the board creator identity (ties to user-created boards, mingo-gj9r).
- Community policies grant members create + owner update + moderator-role delete; members get NO govern.
- Communities may PIN root (chartered) or track (managed); both keep reserved community-removal.
- Enforcement lever = reserved community-removal (coarse: can't tighten a pinned community, so remove-the-board forces compliance).
- Depends on sbo P1-P4 (govern, pinning, constraint clause) + a daemon deploy + pin bump.

## Todos
- [ ] New genesis root policy (govern delegation + reserved community-delete + constraint clause)
- [ ] community_policy template with moderator delete grant + no govern for members
- [ ] regenesis + daemon SBO_REV bump + redeploy
