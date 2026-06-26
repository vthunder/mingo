---
# mingo-j1q6
title: Sys-level admin authority (policy + spec)
status: todo
type: feature
created_at: 2026-06-26T22:19:59Z
updated_at: 2026-06-26T22:19:59Z
parent: mingo-0jkl
blocked_by:
    - mingo-e13s
---

Give sys/admin the ability to act on objects it doesn't own, via policy (SBO has no superuser).

- [ ] Add admin role + grant to root policy in mingo genesis ({to:{role:admin}, can:[transfer,delete,post], on:/**}); define role membership
- [ ] CLI ergonomics for signing as admin/sys identity
- [ ] Reconcile SBO Wire/Policy specs with implemented transfer: admin-override, destination-policy, collision, creator-preservation
- [ ] tests: admin moves a user object; non-admin denied
