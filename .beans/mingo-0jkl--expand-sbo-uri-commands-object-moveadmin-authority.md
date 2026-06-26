---
# mingo-0jkl
title: 'Expand sbo: uri commands + object move/admin authority'
status: in-progress
type: epic
priority: high
created_at: 2026-06-26T22:19:59Z
updated_at: 2026-06-26T22:35:10Z
---

Implement the user-facing object command surface in the sbo CLI and make object move/transfer + sys-level admin authority actually work end-to-end. Splits into: (1) read/write uri commands (pure CLI, daemon IPC already supports), (2) make transfer/move real in core+daemon (parser, builder, validate, apply), (3) admin authority model (policy role + spec). Layout redesign (/u/<handle>@domain/) tracked separately.
