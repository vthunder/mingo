---
# mingo-4jqo
title: 'Rework Mingo identity UX: separate registration from login'
status: todo
type: feature
priority: high
tags:
    - identity
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T19:12:29Z
---

Handle is claimed at REGISTRATION only, never at login. Login = standard browserid discovery for the user's @mingo.place identity. Remove the wrong-layer flow=mingo path (broker stage_login/complete_login/provision_mingo + client prompt). Broker cleanup is already done locally in browserid-ng (commits 1f13a09, 8380ed2 — unpushed).
