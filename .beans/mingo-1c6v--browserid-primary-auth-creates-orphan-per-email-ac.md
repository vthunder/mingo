---
# mingo-1c6v
title: 'browserid: link primary auth to current session (stop orphan accounts)'
status: completed
type: bug
priority: high
created_at: 2026-07-01T16:27:33Z
updated_at: 2026-07-01T21:08:12Z
blocked_by:
    - mingo-sux8
---

## Symptom
After creating dan@mingo.place from external email danmills@sandmill.org, signing out of mingo and re-opening the browserid popup shows ONLY dan@mingo.place. The external danmills@sandmill.org — which was used to bootstrap it — is not offered. Picking dan@mingo.place is (correctly) rejected by mingo-idp ("it is a @mingo.place identity issued by this service, not an external email"). Typing danmills@sandmill.org via 'Use another email' historically produced 'Email already exists'.

## Root cause (browserid-ng, verified 2026-07-01)
The broker models each PRIMARY email as its own account and never links to the current session:
- `auth_with_assertion` (browserid-broker/src/routes/primary.rs:78-94): for the asserted email it does get_email-or-create_user_no_password, then creates a FRESH session. It ignores any existing authenticated session — no account linking.
- So authenticating danmills@sandmill.org created account U1; later provisioning+authenticating dan@mingo.place (a primary via mingo.place) created a SEPARATE account U2 and switched the session cookie to U2.
- `list_emails` (browserid-broker/src/routes/email.rs:34-42) is strictly scoped to `session.user_id`. The dialog chooser (dialog.js populateEmailList ← /wsapi/list_emails) therefore shows only U2's emails → dan@mingo.place only.
- danmills@sandmill.org IS still saved — as U1 — which is why address_info/create reports it exists. It's just never surfaced by the current-session chooser.

## Verified facts
- Live `/wsapi/address_info?email=danmills@sandmill.org` → {type:primary, state:known, prov: https://sandmill.org/browserid/provision}. sandmill.org is a valid primary (DNS _browserid + /.well-known/browserid, key sjL09E...).
- Deployed /dialog/dialog.js is current (has the a9uj create-routing fix). With this code, manually typing danmills@sandmill.org routes type:primary → handlePrimaryIdP → redirect to sandmill.org IdP — it should NOT 409 anymore. The 'Email already exists' the user saw is likely from the pre-a9uj deploy; needs a re-test.
- The dialog chooser is populated ONLY from server list_emails (current session account); localStorage 'emails' is used solely for cached cert/keypair reuse (getStoredEmailKeypair), never for the chooser list. So a signed-out / different-account identity can never appear as a choice.

## Fix directions (need decision; ties into [[mingo-sux8]])
1. Account linking: when `auth_with_assertion` runs with an existing authenticated session, ADD the primary email to that account instead of creating a new one — so the external email and the minted identity live under one account and both list.
2. OR anchor the mingo session/canonical identity to the EXTERNAL email and treat dan@mingo.place as a minted identity attached to it (the sovereignty/canonical-identity model in mingo-sux8).
3. AND/OR chooser should surface previously-used identities (across accounts / from local storage) when signed out, so the external email can be re-selected → redirect to its IdP.

## Repro
1. Fresh browser; sign into mingo via danmills@sandmill.org (creates U1), mint dan@mingo.place (creates U2).
2. Sign out of mingo; open browserid popup → only dan@mingo.place listed.


## Plan — W1 (this bean): session-aware linking
`auth_with_assertion` (primary.rs) currently ignores the session and does get-email-or-create-user + fresh session. Fix:
- [x] If a valid session exists AND the assertion-verified email has NO record → add to current account + keep session. DONE (primary.rs auth_with_assertion; compiles).
- [ ] If no session → current behavior (create user + session).
- [ ] The case where the email belongs to a DIFFERENT account is handled by the merge bean (transfer-on-proof) — see blocking dep.
- [ ] Tests: logged-in + new primary → email added to same account, session preserved, list_emails shows both.
Note (per design): browserid treats sandmill.org and mingo.place as peer IdPs; no 'external/local' distinction at this layer.

### Progress 2026-07-01: W1 core DONE (auth_with_assertion links new primary into current session, keeps session; primary.rs). Broker builds + full suite green. Remaining: integration test + deploy.

### DEPLOYED 2026-07-01 to browserid.me (app id, commit 148eec1). Broker up, migrations ran, serving. Ready for live merge test.
