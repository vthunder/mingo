---
# mingo-hlka
title: Poster-enable silently fails once 5 abandoned warrant requests are pending (cap + swallowed error)
status: completed
type: bug
priority: normal
created_at: 2026-07-15T13:10:56Z
updated_at: 2026-07-15T18:49:39Z
---

Report (mobile): header "let mingo post for me" → Continue opens browserid fine. Going through New post → Post → same dialog → Continue does NOT open browserid; after that the header path stops working too. User closes all tabs and reloads between tests, so it is not client state.

## Diagnosis (corrected — the first theory, named-tab reuse, was wrong)

The breakage is **server-side, per-identity state**, which is why it survives closing all tabs and reloading — and it is NOT path-specific. "New post breaks it" is ordering coincidence: it's whichever attempt crosses the pending-request cap.

The chain:

1. Every Continue tap runs mingo-idp `/poster/enable`, which raises a **new** external warrant request at the registrar (`browserid-registrar/src/consent.rs` → `request_external`). Abandoned requests (user cancels the modal, never approves/denies on the consent page) stay `pending` for 15 min (`REQUEST_VALIDITY_SECONDS = 900`, consent.rs:38). mingo-idp's `set_poster_pending` just overwrites its stored code — nobody ever denies/cleans up the old request.
2. The registrar refuses new external requests once **5 are pending per delegator** (`MAX_PENDING_EXTERNAL = 5`, consent.rs:43) → 403 "too many pending external requests for this delegator".
3. mingo-idp `post_json` wraps any non-2xx as `AppError::BadRequest` → `/poster/enable` returns 400 to the SPA.
4. In `openPosterEnableModal` (mingo-web/app.js:815-830): `enablePoster()` throws → the catch **closes the just-opened blank consent tab** (`win.close()`) and shows only a small `Couldn't start: …` status line. On a phone this reads exactly as "tapped Continue, browserid didn't open, I'm still on mingo.place".

So during repeated testing: attempts 1–5 within a 15-min window work (each parks a pending request), attempt 6+ silently fails from EVERY entry point until requests expire.

## How to confirm

- [ ] Retry and read the modal status line after Continue — expect red "Couldn't start: /poster/enable 400 … too many pending external requests for this delegator".
- [ ] Wait 15+ min with no attempts → both header and New post paths work again (for 5 attempts).

## Root cause (final)

User tests on **Arc mobile**, whose popup blocker (a) blocks `window.open` from the modal, (b) blocks even a tapped anchor with a *named* `target` (`target="mingo-consent"` → tap does nothing), and (c) appears to keep per-TAB block state across reloads — fresh tab works, same tab stays broken even after refresh. Tap-hold → open-in-new-tab bypasses the blocker and the consent page works fine. The registrar pending-cap (above) is a real secondary landmine but wasn't the driver here.

## Fix plan (navigation-based, popup-free — dan's design)

- [x] mingo-idp: make `/poster/enable` idempotent — if an unexpired pending request exists for the account, return its verification_uri instead of raising a new one (store expires_at from the registrar's expires_in). Without this, pre-creating on dialog-open burns the 5-pending cap.
- [x] mingo-web: when the poster dialog opens (either entry point), immediately call /poster/enable; render Continue as a real `<a href=${uri}>` (disabled until uri arrives). onclick: `if (window.open(uri, "_blank", "noopener")) e.preventDefault();` — new tab where popups are allowed, anchor's default SAME-TAB navigation where blocked. Never `about:blank`+navigate, never named targets.
- [x] mingo-web: pickup after the same-tab round-trip — pollPoster dies on navigation, so on init when poster is off and a request is pending, fire one /poster/poll (or have idp /poster/status do a one-shot registrar pickup when a pending code exists, swallowing the 5s poll throttle).
- [x] mingo-web polish: stash the drafted post body in sessionStorage before the same-tab hop; restore on return.
- [x] browserid-ng consent.html: after approve/deny, show "Return to the app" via history.back() when history.length > 1, else "You can close this tab". No return_to param (avoids open-redirect validation).
- [x] mingo-web: still surface enable errors loudly (the silent "Couldn't start" swallow made this undiagnosable).
- [x] Re-test in Arc mobile: repeated attempts from both entry points, same tab, must navigate to consent every time; approve → return → poster enabled without re-tapping.

## Summary of Changes

Shipped and verified end-to-end on Arc mobile (dan, 2026-07-15). mingo faf11ee/d99ce7e: consent request raised at dialog-open (idempotent /poster/enable reusing the pending request), Continue as a real anchor with new-tab-then-same-tab fallback, pickupPoster on load/bfcache-restore, draft stash/restore, loud errors. browserid-ng d1468b8+e895629: consent-page return affordance (history.back) — plus the CSP inline-script hash update the first deploy missed (page bricked at 'Checking your session…' until e895629). Follow-up polish tracked separately.

## Still-real secondary issue (was the original theory)

The consent tab named "mingo-consent" is never closed on approval/cancel, and iOS re-targets a named window without foregrounding it. Once the cap bug is fixed, a leftover consent tab in the same session can still make a later Continue look like a no-op. Worth fixing alongside: close the tab when the poll resolves/cancel, or stop using a named target.
