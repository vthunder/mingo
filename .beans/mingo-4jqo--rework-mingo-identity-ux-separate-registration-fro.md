---
# mingo-4jqo
title: 'Rework Mingo identity UX: separate registration from login'
status: scrapped
type: feature
priority: high
tags:
    - identity
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T20:02:39Z
---

Handle is claimed at REGISTRATION only, never at login. Login = standard browserid discovery for the user's @mingo.place identity. Remove the wrong-layer flow=mingo path (broker stage_login/complete_login/provision_mingo + client prompt). Broker cleanup is already done locally in browserid-ng (commits 1f13a09, 8380ed2 — unpushed).

## Reasons for Scrapping

Bean premise was subtly wrong. The intended UX is the CURRENT behavior: a single login entrypoint where, if the authenticated external email has no handle yet, the user is prompted in-page to create one (signIn() in mingo-web/app.js:183 + promptHandle()). We do NOT want separate registration/login entrypoints.

The genuinely-needed cleanup (removing the wrong-layer broker flow=mingo / provision_mingo path) is already complete — verified zero references in mingo; broker now uses the generic provision_email dialog param (browserid-ng 1f13a09, pushed via mingo-8vec). Nothing further to do.
