---
# mingo-sux8
title: 'Full identity model: sovereignty + canonical identity + policy vars + /u layout'
status: todo
type: epic
priority: high
created_at: 2026-06-27T21:35:55Z
updated_at: 2026-06-27T23:28:44Z
---

Build the full SBO identity model with mingo as the proving ground. See sbo docs/plans/2026-06-27-identity-sovereignty-and-policy-variables.md. Phases: (1) policy variables foundation, (2) Creator validation, (3) canonical identity + resolver email->name override, (4) anti-hijack name creation, (5) mingo genesis+app /u layout, (6) sovereignty e2e demo, (7) production migration.

## Phase 1 done
Four-variable literal-reference policy model (\$owner/\$user/\$email/\$name) implemented in sbo-core + daemon; \$owner de-circularized (declared Owner, not path segment). Fail-closed for undefined vars. /u/\$owner/** now works. Spec updated. 6 new tests + full suite green. sbo branch feat/identity-sovereignty-and-policy-vars.

## Phases 2 & 3 done
Phase 2: declared Creator validated against signer (closes trie-spoofing gap); Authorization spec updated.
Phase 3 (the heart): resolve_controller email->name override scoped to primary domain (record wins over browserid) + canonical-identity reverse edge (key-signed writer canonicalizes to <local>@<domain>); sovereign-key write under /u/ verified end-to-end with stable creator. Identity spec Sovereignty Upgrade section added.
All on sbo branch feat/identity-sovereignty-and-policy-vars. Commits: 30e4bd4 (P2), 8cbf93b (P3). Suites green (resolver+authorize+daemon).
Remaining: P4 anti-hijack name-claim policy; P5 mingo genesis+app /u layout; P6 sovereignty e2e demo; P7 production migration.

## Phases 4, 5, 6 done + Phase 7 runbook
P4: anti-hijack name-claim policy (primary-domain name requires controlling the email; genesis-safe). P5 (mingo feat/u-layout): genesis owner grant -> /u/$owner/**, app.js user paths under /u/, genesis test. P6: sovereignty lifecycle test (control flips browserid->key). P7: production migration runbook written (docs/plans/2026-06-28-u-layout-migration-runbook.md) — NOT executed, needs sys key + live verification.
Branches pushed: sbo feat/identity-sovereignty-and-policy-vars, mingo feat/u-layout. All suites green. Protocol phases 1-4 complete; mingo phase 5 complete; remaining = run Phase 7 (merge+deploy+migrate) when ready.
