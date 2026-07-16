---
# mingo-ii01
title: 'mingo-idp: delete the 16 seeded accounts (handles squatted)'
status: todo
type: task
priority: normal
created_at: 2026-07-15T22:27:41Z
updated_at: 2026-07-16T18:27:00Z
parent: mingo-y9gb
---

The regenesis (mingo-4rvr) wiped the chain but mingo-idp's accounts table still holds the 15 seed personas + digest-bot (sentinel external emails *.seed@sandmill.org / @example.com). Inert but squatting handles like marisol. No sqlite3/python in the deployed image — add an admin-gated delete endpoint or a one-off migration. Keep dan's real accounts.

## Also (2026-07-16): two_writer_collision test handles
The uniqueness policy-fix production test left two more inert handles to clean when this lands: collisiontesta, collisiontestb (external emails collisiontesta.seed@sandmill.org / collisiontestb.seed@sandmill.org). Their on-chain memberships were already sys-deleted; only the mingo-idp account/handle rows remain.
