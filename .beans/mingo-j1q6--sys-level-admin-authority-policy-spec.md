---
# mingo-j1q6
title: Sys-level admin authority (policy + spec)
status: completed
type: feature
priority: normal
created_at: 2026-06-26T22:19:59Z
updated_at: 2026-06-26T23:02:11Z
parent: mingo-0jkl
blocked_by:
    - mingo-e13s
---

Give sys/admin the ability to act on objects it doesn't own, via policy (SBO has no superuser).

- [ ] Add admin role + grant to root policy in mingo genesis ({to:{role:admin}, can:[transfer,delete,post], on:/**}); define role membership
- [ ] CLI ergonomics for signing as admin/sys identity
- [ ] Reconcile SBO Wire/Policy specs with implemented transfer: admin-override, destination-policy, collision, creator-preservation
- [ ] tests: admin moves a user object; non-admin denied

## Summary of Changes
Added an `admin` role (= sys identity) to the mingo hub root policy granting post/transfer/delete on /** (genesis.rs), with a unit test. CLI signing-as-admin is just `--key <sys-alias>` (no new flag needed). Reconciled the canonical SBO specs (Specification §transfer + State Commitment) to state transfer is creator-invariant. Admin-moves-user-object and stranger-denied are covered by sbo-daemon tests/transfer.rs.

Deploy note: enforcement needs the daemon built from sbo branch feat/uri-commands-and-transfer; the live repo root policy can be upgraded in place via `sbo uri post /sys/policies/ root` signed by sys.
