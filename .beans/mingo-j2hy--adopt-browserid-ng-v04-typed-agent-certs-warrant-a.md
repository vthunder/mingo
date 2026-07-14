---
# mingo-j2hy
title: 'Adopt browserid-ng v0.4: typed agent certs + warrant-aware verification'
status: completed
type: task
priority: normal
created_at: 2026-07-10T18:22:44Z
updated_at: 2026-07-10T18:40:28Z
---

Bump the pinned browserid-ng dep to v0.4 (warrants). mingo-idp: /provision/mint issues typed agent certs (typ browserid-agent-cert-v1 + agent{parent}); verify_external_assertion handles warrant-backed agent presentations (agents can root mingo sessions when their principal warranted https://mingo.place) and returns attribution. External-registrar mode per browserid-ng-1pnf: browserid.me stays the registrar (registry + endorsements + consent surface) — zero mingo changes needed for that. E2E test updated to the warrant flow.

## Summary of Changes

Shipped and prod-verified 2026-07-10: dep bumped to a849ade; mint issues typed agent certs (typ + agent{parent}); verify_external_assertion warrant-aware returning VerifiedExternal attribution; Option<PublicKey> discovery adaptation; e2e updated. Prod test: attestor@browserid.me presented agent_cert~warrant~assertion to POST /session/from-assertion → session established, whoami authenticated, server logged agent=attestor@browserid.me parent=vthunder@gmail.com; bare (warrant-less) presentation rejected.
