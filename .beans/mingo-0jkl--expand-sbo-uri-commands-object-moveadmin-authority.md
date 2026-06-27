---
# mingo-0jkl
title: 'Expand sbo: uri commands + object move/admin authority'
status: completed
type: epic
priority: high
created_at: 2026-06-26T22:19:59Z
updated_at: 2026-06-26T23:02:11Z
---

Implement the user-facing object command surface in the sbo CLI and make object move/transfer + sys-level admin authority actually work end-to-end. Splits into: (1) read/write uri commands (pure CLI, daemon IPC already supports), (2) make transfer/move real in core+daemon (parser, builder, validate, apply), (3) admin authority model (policy role + spec). Layout redesign (/u/<handle>@domain/) tracked separately.

## Summary of Changes
All three tiers complete on branches feat/uri-commands-and-transfer (sbo) and feat/sys-admin-authority (mingo). uri get/list/post/transfer/mv/rm/chown implemented; Action::transfer made real end-to-end (parse/build/validate/apply) with owner-or-admin policy override; sys admin authority granted in mingo genesis; specs reconciled. See docs/plans/2026-06-27-object-transfer-and-admin-authority.md.
