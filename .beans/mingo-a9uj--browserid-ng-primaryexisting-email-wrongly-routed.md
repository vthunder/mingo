---
# mingo-a9uj
title: 'browserid-ng: primary/existing email wrongly routed to create → ''already exists'' 409'
status: completed
type: bug
priority: high
created_at: 2026-06-28T23:01:28Z
updated_at: 2026-06-29T14:01:57Z
---

In ~/src/browserid-ng. Typing an existing primary email (e.g. danmills@sandmill.org) in the broker dialog dead-ends with 'Email already exists' (409 from stage_user), with no way to sign in.

## Root cause (chain)
1. dialog.js checkEmail (L108-118) swallows ANY address_info fetch error into a fake { type:'secondary', state:'unknown' } ('assume new user'). Server-side address_info is stable (8/8 primary/known), so the trigger is the dialog's own fetch failing.
2. New-email handler (dialog.js:687-734) secondary branch (L717-729) only handles state 'known' and 'transition_to_primary'; everything else (incl. 'unknown', 'transition_to_secondary', 'transition_no_password') falls to showScreen('create') → stage_user → EmailAlreadyExists (409). Note handleEmailChosen (L271-309) DOES handle the transition states — the two flows diverged.
3. Latent server bug (email.rs:320-327): discovery failure silently downgrades a primary email to secondary; for an existing primary record this yields transition_* states.

## Fix plan
- [x] dialog.js checkEmail: surfaces error instead of faking new-user.
- [x] dialog.js email-form handler: handles transition_* states; only create for unknown.
- [x] dialog.js create-form: recovers to sign-in on EmailAlreadyExists.
- [ ] email.rs address_info hardening (DEFERRED): a clean fix needs discovery-result CACHING — on transient discovery failure, fall back to last-known-good (incl. auth/prov URLs) instead of downgrading to secondary. A partial fix is incorrect because without discovery we lack the IdP auth/prov URLs the client needs. The dialog fixes already make a transient failure degrade gracefully (show retry / handle transition state), so this is resilience hardening, not the user-facing blocker.
- [ ] Tests where feasible (broker Rust tests for address_info hardening).

Spun off from the mingo fresh-genesis deploy thread (deploy itself succeeded).

## Status
Dialog fixes committed on browserid-ng branch fix/dialog-primary-email-409 (f57b167); broker builds, dialog.js syntax-checks. NOT deployed — browserid.me needs a redeploy to take effect.

Note: dialog fix stops the 409, but the user may still hit separate walls (sandmill.org /browserid/auth reachability; mingo-idp external-email-vs-handle circularity) — tracked separately.

## Status (dialog fixes done)
Committed on browserid-ng branch fix/dialog-primary-email-409 (f57b167); broker builds, dialog.js syntax-checks. NOT deployed — browserid.me needs a redeploy to take effect.

DONE (dialog): checkEmail surfaces errors instead of faking new-user; new-email handler handles transition_to_secondary/transition_no_password (only 'create' for unknown); create-form recovers to sign-in on EmailAlreadyExists.

DEFERRED (server email.rs): clean fix needs discovery-result CACHING (on transient discovery failure, fall back to last-known-good incl. auth/prov URLs) rather than downgrading primary->secondary. Partial fix is incorrect (no auth/prov without discovery). Dialog fixes already make transient failures degrade gracefully, so this is hardening, not the blocker.

Separate walls the user may still hit (tracked elsewhere): sandmill.org /browserid/auth reachability; mingo-idp external-email-vs-handle sign-in circularity.

## Summary
Dialog 409 fix committed (browserid-ng 027d3dc) and DEPLOYED to browserid.me — verified served /dialog/dialog.js has all three fixes. End-to-end sign-in/join/post confirmed working.
Also fixed the related mingo-idp namespace pollution: reject @mingo.place as external identity (mingo e11c0fd, deploying) + cleaned the junk handle accounts via DB.
DEFERRED follow-up (not this bean): browserid-ng server-side address_info discovery caching (don't downgrade known-primary on transient discovery failure). Captured in handoff doc.
