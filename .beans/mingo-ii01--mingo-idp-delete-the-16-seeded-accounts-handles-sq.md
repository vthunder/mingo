---
# mingo-ii01
title: 'mingo-idp: delete the 16 seeded accounts (handles squatted)'
status: todo
type: task
created_at: 2026-07-15T22:27:41Z
updated_at: 2026-07-15T22:27:41Z
parent: mingo-y9gb
---

The regenesis (mingo-4rvr) wiped the chain but mingo-idp's accounts table still holds the 15 seed personas + digest-bot (sentinel external emails *.seed@sandmill.org / @example.com). Inert but squatting handles like marisol. No sqlite3/python in the deployed image — add an admin-gated delete endpoint or a one-off migration. Keep dan's real accounts.
