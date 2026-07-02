---
# mingo-0vkj
title: 'T2.4 client fast-sync: snapshot+checkpoint bootstrap, tail from h+1'
status: todo
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T16:25:37Z
parent: mingo-o5t1
blocked_by:
    - mingo-8724
---

Fetch manifest -> snapshot -> rebuild trie -> fetch on-chain checkpoint.v1 -> assert root match -> load state, head=h, tail. Selectable trust.
