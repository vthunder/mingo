---
# mingo-5guy
title: 'mingo session hygiene: no TTL, /logout only clears current session, UI/cookie state uncoupled'
status: todo
type: bug
priority: normal
created_at: 2026-07-02T14:43:29Z
updated_at: 2026-07-02T14:43:29Z
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
