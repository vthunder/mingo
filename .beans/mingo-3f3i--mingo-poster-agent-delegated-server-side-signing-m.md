---
# mingo-3f3i
title: 'mingo-poster agent: delegated server-side signing (mobile posting)'
status: draft
type: feature
priority: normal
created_at: 2026-07-14T16:52:00Z
updated_at: 2026-07-14T16:52:00Z
---

Problem: mingo's posting requires client-side per-object signing via browserid
popups (the SBO-sign grant dialog AND the /sign signer window). Mobile Safari
blocks window.open non-deterministically, so posting is unreliable on mobile.
No amount of gesture-tightening fixes it — popups are the wrong primitive here.

Solution: keep identities/pseudonyms EXACTLY as-is (external email A, or
handle@mingo.place pseudonym B). Add an opt-in "mingo-poster" AGENT that a user
can delegate to. Then mingo signs objects SERVER-SIDE on the user's behalf —
zero popups, zero per-post gestures, identical on mobile and desktop. Users who
don't opt in keep client-side signing (fine on desktop).

This is a pure SIGNING-MECHANISM change; it does NOT touch who a post is
attributed to. Pseudonymity is preserved: a handle user's posts attribute to
"mingo-poster@mingo.place acting for handle@mingo.place" — real email A never
appears.

## Why this works (machinery already exists)
- SBO implements Agent Warrants (~/src/sbo): agent cert (parent=user) +
  user-signed Auth-Warrant (aud=mingo chain, scopes, as:<user>) => object
  verifies on-chain as "agent acting for user", scoped + revocable. Tested.
- browserid implements the delegation + consent flow (browserid-ng): the
  warrant is issued via a device-authorization flow (request -> visit
  verification_uri -> approve -> poll -> pickup). The user approves on a consent
  PAGE (redirect, not a popup) where their in-origin identity key signs the
  warrant. Revocation via per-warrant status bits at browserid.me/account.

## Shape
- One shared "mingo-poster" agent identity/key (held by a mingo backend signer).
- Per user who opts in: a cert (parent=that user) + a warrant they signed once.
- mingo-web: "Let mingo post for me" -> redirect to browserid consent -> back.
- mingo backend: on submit, sign the SBO envelope with the agent key + that
  user's cert+warrant, then POST to the daemon. No browser signing.
- Works for BOTH external emails (A) and handles (B) — unlike server-side
  handle-cert signing, which can't cover external emails.

## Trust model
Server-side signing means the mingo signer can author posts attributed to a
consenting user (as "mingo-poster acting for them") until revoked. This is the
honest, scoped, revocable version of "authorize this app to post for you" — the
warrant is limited to the mingo audience + post scope, and the delegation is
on-chain-visible. Better boundary than per-post approval ("do I trust mingo"
vs "approve each post").

## Dependencies / open questions
- [ ] BLOCKED BY browserid-ng-ak1n: SBO-envelope signing method in the agent SDK
      (the one real gap — generic sign(bytes) + warrant plumbing exist, SBO
      canonical-bytes signer is design-stage).
- [ ] One shared agent email w/ per-user parent certs vs per-user agent emails
      under a shared display name (browserid store binds agent email -> single
      parent today). On-chain "acting for you" result is the same either way.
- [ ] Where the mingo backend signer lives (extend mingo-idp vs new service) and
      key custody for the shared agent key.
- [ ] Warrant scope/expiry policy (audience = mingo chain app_id; post/comment/
      vote/join scopes; renewal).
- [ ] Revocation UX surfaced in mingo (link to browserid.me/account) + handling
      a revoked/expired warrant at post time (re-consent prompt).
- [ ] Keep client-side signing as the desktop/no-delegation fallback.

## Related
- browserid-ng-ak1n (SBO agent-SDK signing — blocker)
- browserid-ng-k426 (cross-RP pseudonyms — deferred; would eventually subsume
  mingo handles but is orthogonal to this)
