---
# mingo-5guy
title: 'mingo session hygiene: no TTL, /logout only clears current session, UI/cookie state uncoupled'
status: completed
type: bug
priority: normal
created_at: 2026-07-02T14:43:29Z
updated_at: 2026-07-02T14:52:32Z
---

Found while diagnosing a 'signed out but browserid still mints a cert' report (2026-07-02).

Problems in mingo-idp:
- Sessions never expire (no TTL) and accumulate: the mingo-idp DB had 5 live sessions for one account. create_session inserts; nothing deletes except /logout.
- /logout deletes only the session matching the current cookie, leaving the others valid.
- /cert_key authorizes on ANY valid mingo_session cookie (no freshness/re-proof), so a lingering session can mint a <handle>@mingo.place cert.
- mingo-web signed-out UI (localStorage mingo_email) is decoupled from the server cookie/session, so the UI can show 'sign in' while a valid session cookie persists (confusing).

## Fix
- Add a TTL to mingo sessions (created_at exists) — expire on read in account_for_session, and/or a sweep.
- /logout (or a 'sign out everywhere') option to delete all of the account's sessions.
- Consider whether /cert_key for a login-purpose cert should require a fresher proof.
- Optionally: mingo-web verifies the server session (whoami) on load so UI matches reality.

### FIXED + DEPLOYED 2026-07-02 (mingo fd8d062)
- 30-day session TTL enforced + pruned on read (account_for_session).
- delete_account_sessions(); /logout ends ALL of the account's sessions.
- Tests: session_ttl_expires_and_prunes, delete_account_sessions_clears_all (passing).
Note: the ~5 pre-existing sessions persist until read-past-TTL or the account's next sign-out (which now clears all). Not addressed here: mingo-web UI vs cookie coupling (whoami-on-load) — minor, left as follow-up.
