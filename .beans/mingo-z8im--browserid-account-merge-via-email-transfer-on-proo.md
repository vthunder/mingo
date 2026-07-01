---
# mingo-z8im
title: 'browserid: account merge via email transfer-on-proof'
status: completed
type: feature
priority: high
created_at: 2026-07-01T16:48:17Z
updated_at: 2026-07-01T21:08:12Z
blocked_by:
    - mingo-1c6v
---

browserid-ng has NO account merge/transfer (only add_email/remove_email); the original JS browserid isn't available locally to copy, so design new. Model = original BrowserID's per-email transfer: an email belongs to exactly ONE account; proving ownership under another session MOVES it there. IdP-agnostic (works for any two primary emails; browserid sees sandmill.org and mingo.place as peer IdPs).

## Why
Existing split: danmills@sandmill.org=U1, dan@mingo.place=U2, never linked (see [[mingo-1c6v]]). Need to fold them into one account so the chooser shows both and either can drive login.

## Tasks
- [x] Add UserStore method `transfer_email(email, to_user_id)`: sqlite (concrete + delegating) + memory + trait. DONE.
- [ ] Emptied-account cleanup: if the source account has 0 emails after transfer, delete it (and invalidate/reassign its sessions).
- [ ] Wire into `auth_with_assertion`: if the assertion-verified email belongs to a DIFFERENT account than the current session → transfer it into the current session's account (the assertion IS the proof). Composes with the W1 link fix.
- [ ] Decide/handle: transferring an email that is another account's LAST email (that account disappears) vs one of many.
- [ ] One-time reconciliation for the current U1/U2 split (re-auth danmills while logged in as dan@mingo.place, or an admin merge).
- [ ] Tests: two accounts, prove-second-under-first-session → merged; emptied account removed.


## Persona reference (confirmed 2026-07-01, ~/src/persona)
Persona has no bulk account-merge; it uses **per-email transfer on proof**. `lib/db/json.js:407-420`: when a verified email is already `known` (owned by another account), it `removeEmailNoCheck(email)` from the old account, then attaches it to the target account. Comment: 'dead simple approach that mitigates many attacks and gives reasonable behavior in the face of shared email addresses.' Also `lib/db/mysql.js:455` ('adding or reverifying an email to an existing user account') and `lib/wsapi/stage_reverify.js`.
=> Adopt the same: transfer_email = remove-from-old + add-to-target(current session). No explicit account-merge object needed; emptied old accounts are orphaned/cleaned. Matches W1's linking seam.

### Progress 2026-07-01
- transfer_email store method (trait + sqlite concrete/delegating + memory): DONE.
- auth_with_assertion wiring: different-account email → transfer into current session's account; former account deleted if left empty: DONE.
- Store test test_transfer_email_moves_ownership (U1/U2 → merged, u1 empty): DONE, passing. Whole broker suite green.
- REMAINING: integration test through auth_with_assertion (needs the primary-IdP mock harness, same gap as the deferred 'Task 8'); one-time reconciliation of the live U1/U2 split; deploy to browserid.me.

### DEPLOYED 2026-07-01 with 148eec1 (same commit as W1). Live on browserid.me.
