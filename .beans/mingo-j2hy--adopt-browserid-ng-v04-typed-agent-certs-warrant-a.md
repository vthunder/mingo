---
# mingo-j2hy
title: 'Adopt browserid-ng v0.4: typed agent certs + warrant-aware verification'
status: in-progress
type: task
created_at: 2026-07-10T18:22:44Z
updated_at: 2026-07-10T18:22:44Z
---

Bump the pinned browserid-ng dep to v0.4 (warrants). mingo-idp: /provision/mint issues typed agent certs (typ browserid-agent-cert-v1 + agent{parent}); verify_external_assertion handles warrant-backed agent presentations (agents can root mingo sessions when their principal warranted https://mingo.place) and returns attribution. External-registrar mode per browserid-ng-1pnf: browserid.me stays the registrar (registry + endorsements + consent surface) — zero mingo changes needed for that. E2E test updated to the warrant flow.
