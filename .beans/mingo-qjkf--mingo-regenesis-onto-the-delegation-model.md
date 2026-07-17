---
# mingo-qjkf
title: mingo regenesis onto the delegation model
status: completed
type: task
priority: normal
created_at: 2026-07-16T23:40:18Z
updated_at: 2026-07-17T00:27:58Z
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

## Summary of Changes

LIVE. Genesis v5 anchored on Avail turing app 506 at block 3623864 (sha256:ca27c611...). The sbo P1 daemon (rev 4b28d8e) reseeded /data on deploy and verified healthy: all three communities resolve; DNSSEC evidence for mingo.place re-established at block 3623911 (/sys/dnssec/mingo.place present). Root policy grants admin govern; community policies grant moderator-role delete on spaces + reserved sys takedown on subtree; members create+owner-update, no govern (closes sbo-vos1 live). GENESIS.md v5 + new _sbo DNS record recorded.

FOR DAN: (1) old chain content is gone - re-run `mingo seed` to restore the demo corpus; (2) moderator delete needs a `role:moderator:<board>` attestation issued by the community issuer (sys) to a moderator; (3) set the new _sbo DNS record when convenient; (4) review + push/merge P2-P4 on branch p234-policy-delegation (~/src/sbo-p234).
