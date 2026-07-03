---
# mingo-d7bi
title: 'LIVE privesc: IdP-issued sys@mingo.place ⇒ on-chain admin'
status: todo
type: bug
priority: critical
created_at: 2026-07-02T22:04:58Z
updated_at: 2026-07-03T19:10:23Z
---

## Live privilege escalation (opened 2026-07-02 by the engine-fix deploy)

mingo-idp issues `<handle>@mingo.place` certs for any handle a signed-in user claims, with NO reserved-name list (normalize_handle, routes.rs). `POST /claim_handle` is public (session-gated only). So:
1. Attacker signs in to mingo-idp with any external email → session.
2. POST /claim_handle {handle:"sys"} → if unclaimed, succeeds (first-come).
3. POST /cert_key {email:"sys@mingo.place", pubkey:<their SBO key>} → cert signed by the mingo provider key e021fda4 (DNSSEC-proven at _browserid.mingo.place).
4. Attacker signs an SBO write with Auth-Cert + the public _browserid DNSSEC evidence → daemon resolve_creator (validate.rs:268, attributed_email FIRST) → actor `sys@mingo.place`.
5. Root policy roles.admin:["sys"] → canonical_name_ref("sys","mingo.place")=="sys@mingo.place" (evaluate.rs, engine fix 01e3da5) → admin → post/transfer/delete on /**.

Was inert before the engine fix (bare to:"sys" matched nobody). Test infra, so blast radius is limited (moderation/transfer/delete on a disposable chain), but it is a real live escalation on the deployed validator.

## Immediate fix (committed, NOT deployed): bd6ac1e
Reserved-handle blocklist at normalize_handle (sys, checkpointer, admin, root, …). Covers /claim_handle, /cert_key, /admin/seed. **Deploy: `make deploy-mingo`** (redeploys the mingo.place site + IdP).

## Follow-ups
- [ ] Deploy bd6ac1e (make deploy-mingo).
- [ ] Verify `sys` (and checkpointer/admin/root) are NOT already claimed in the id-app DB (query handle column); if claimed, unbind.
- [ ] DEFENSE-IN-DEPTH: at the next regenesis, change roles.admin to KEY form {key: ed25519:564aafe4…} (like checkpointer) so admin authority never depends on IdP issuance. Batch with mingo-m6z7.
- [ ] Consider: does resolve_creator preferring attributed_email over the key-rooted name claim deserve a reserved-principal guard on-chain too? (belt-and-suspenders)

## sys-* structural reservation (done) + rename (regenesis)
- normalize_handle now reserves 'sys' + the whole 'sys-*' namespace (commit after bd6ac1e), so future sys-<role> authorities are auto-reserved without blocklist edits. 10 tests pass.
- [ ] Regenesis: rename the checkpointer identity/grant -> sys-checkpointer (fits the sys- convention; still key-matched in policy). Batch with mingo-m6z7.
