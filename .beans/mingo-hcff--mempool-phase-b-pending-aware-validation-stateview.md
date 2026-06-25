---
# mingo-hcff
title: 'Mempool Phase B: pending-aware validation (StateView/Overlay)'
status: todo
type: feature
priority: normal
tags:
    - mempool
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T19:12:29Z
---

Phase A (shipped) validates submits against CONFIRMED state only. Phase B introduces a StateView trait + Overlay{db,pending} so validate_message runs against confirmed+pending — enabling chained optimistic writes (join→post) and letting the SPA relax membership gating to count pending memberships. See docs/plans 2026-06-25-mempool-overlay-plan.md (the plan moved with the impl).
