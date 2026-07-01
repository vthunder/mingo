---
# mingo-n153
title: 'Incomplete logout: mingo ''Sign out'' is client-only; mingo.place session + cookie persist'
status: todo
type: bug
priority: high
created_at: 2026-07-01T21:56:09Z
updated_at: 2026-07-01T21:56:09Z
---

mingo-web signOut() only does 'session.email = null; renderAuth(); toast(Signed out)'. It does NOT invalidate the mingo.place session or clear the mingo_session cookie, and mingo-idp has NO logout endpoint. It also doesn't log out of browserid. So after 'Sign out' the user still has a valid mingo session — and can silently re-mint a <handle>@mingo.place cert (cert_key is correctly session-gated, so the lingering session is the basis).

Observed 2026-07-01: fully 'logged out', typed dan@mingo.place → browserid 'log in successful' because the stale mingo_session cookie authorized /cert_key. Worsened by the /data persistence fix ([[mingo-c70r]]): the session row now survives restarts.

Not a minting-without-auth vuln (cert_key requires a session), but incomplete logout is a real security/UX bug: users can't actually sign out.

## Fix
- mingo-idp: add POST /logout — delete the session row (store) + clear the mingo_session cookie (Max-Age=0).
- mingo-idp store: add delete_session(sid).
- mingo-web signOut(): call idp /logout; optionally also POST browserid /wsapi/logout so the broker session ends too (else the chooser still shows the account). Decide how aggressive: mingo-only vs mingo+broker logout.
- Consider session expiry/TTL for mingo sessions (currently appear long-lived).

## Tests
- After /logout, require_session fails; /cert_key 401s; whoami=false.
