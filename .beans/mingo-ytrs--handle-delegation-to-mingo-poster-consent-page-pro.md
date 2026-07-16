---
# mingo-ytrs
title: 'Handle delegation to mingo-poster: consent-page provisioning fails on mobile'
status: in-progress
type: bug
priority: normal
created_at: 2026-07-15T07:26:41Z
updated_at: 2026-07-15T23:56:46Z
---

A mingo HANDLE user (e.g. dan@mingo.place) can't enable mingo-poster: the browserid.me consent page needs the handle's identity key to sign the warrant, but it's not in that browser's keystore on a fresh device, and provisioning it there fails.

## Done so far
- Aligned public_identity to warrant the handle (mingo commit ~c5b7b96) — the delegator/owner/SPA identity now agree (was warranting the external email → 'No matching grant').
- browserid.me consent.html now tries to provision a missing primary-IdP identity in-page via a hidden /provision iframe (BrowserID.Provisioning) using /wsapi/address_info for the URL (browserid-ng 48d5ec8). Still fails on the user's mobile.

## Hypotheses to investigate
- Mobile Safari ITP blocking the mingo session cookie in the third-party mingo.place/provision iframe embedded in browserid.me (the sign-in dialog uses the same mechanism — does IT actually work for handles on mobile? verify). Storage Access API may be needed.
- Something specific to how mingo.place implements its IdP /provision (mingo-idp static provision.html/provision.js) vs what BrowserID.Provisioning expects — check the iframe postMessage protocol + that /provision mints for the current mingo session.
- Whether address_info returns type=primary + prov for mingo.place from the consent page's perspective.

## Interim mitigation (shipped)
Handles gated behind ?handles=1 in mingo-web (new users use their external email, the proven mingo-poster path). General users unaffected. Existing handle accounts still hit this bug.

## Root cause CONFIRMED (2026-07-16 investigation)

Single root cause: **a handle's signing key can only enter browserid.me's keystore via a hidden mingo.place-in-browserid.me provision iframe whose /cert_key fetch needs the mingo.place session cookie (SameSite=None) — mobile Safari ITP blocks that third-party cookie.** This is the exact third-party-IdP-iframe failure that killed the original BrowserID/Persona.

Key facts:
- All signing at browserid.me (SBO envelopes via /sign, warrants via /consent) reads keys from browserid.me's OWN IndexedDB keystore (keystore.js:7-8). So any handle that signs there must have {key,cert} deposited there.
- The ONLY deposit path is BrowserID.Provisioning.start → hidden mingo.place /provision iframe → /cert_key with credentials:include (provisioning.js:44-47, mingo-idp provision.js:29-34, routes.rs:510-524). Cross-origin cookie → ITP → 401 → nothing stored.
- Both the LOGIN grant path (dialog.js:545-579, via app.js:410 provisionEmail) and the CONSENT warrant path (consent.html:99-104) use the SAME iframe. So handle CLIENT-side signing is broken on mobile too, not just the poster warrant.
- External emails work because browserid.me is their FALLBACK IdP and mints same-origin via /wsapi/cert_key (dialog.js:227-253) — no third-party cookie.
- Constraint: keys are non-extractable CryptoKeys → a key cannot cross origins; only a cert can. Whoever holds the private key must generate it.
- No Storage Access API / CHIPS anywhere today; only mitigation is SameSite=None (insufficient under ITP).

## Candidate directions
1. mingo.place custodies handle keys & signs first-party (handles never provision into browserid.me) — cleanest, matches 'mingo is a real primary IdP', biggest lift, duplicates keystore/signer/consent.
2. Same-tab navigation provisioning — replace the hidden iframe with the proven same-tab handshake to mingo.place (browserid.me generates key → hands pubkey to mingo.place first-party → mint → return cert → store). Reuses the mingo-hlka primitive; keeps browserid.me the single signer; medium lift; wrinkle = navigating dialog/consent away and back.
3. Storage Access API + visible 'continue' iframe — smallest, but it's the exact pattern BrowserID died on; fragile on Safari.


## Fix implemented (2026-07-16) — candidate direction 2 (same-tab provisioning). NOT yet device-tested.

Replaced the ITP-dead hidden-iframe deposit with a first-party same-tab navigation handshake, scoped to the CONSENT warrant path (poster-enable). Uncommitted; both trees left for review.

mingo-idp:
- routes.rs: new GET /provision_return handler (+ validate_return_to exact-broker-origin allowlist, is_base64url state guard, sign_in_first_page). Mints handle cert (principal=handle only; external email never touched — no subordinate_to on this path) under first-party session, 302s back with cert in URL FRAGMENT.
- lib.rs: route registered. No CSP on mingo-idp (only Cache-Control) — new page runs fine.

browserid-broker:
- keystore.js: IDB bumped v1->v2, added `pending` staging store + putPending/getPending/clearPending (non-extractable CryptoKey survives the top-level hop via structured clone).
- consent.html: replaced hidden-iframe provisionPrimaryIdentity with startSameTabProvision (generate non-extractable keypair -> stash pending -> navigate top frame to IdP /provision_return) + consumePendingProvision (on return: validate state nonce, cert certifies exactly our pubkey, principal==handle, iss==IdP; then Keystore.put + resume). CSP inline-script hash updated in routes/mod.rs.

Security checks: state nonce (reject mismatch), cert in FRAGMENT not query, return_to exact-origin allowlist (rejects browserid.me.evil.com / @evil.com / fragment), pubkey+principal+iss cert binding. Pseudonymity preserved: server respond() checks warrant.delegator==request.delegator + request.user_id==session.user_id, NO session.email==delegator check — parent session signs for handle purely via keystore.

Verified: cargo test green (broker/registrar/mingo-idp), CSP hash test green, node --check on consent inline + keystore.js, curl exercise of provision_return validation (session-less->sign-in page; bad host/subdomain->403; fragment/bad-state->400).

REMAINS: real mobile-Safari device test (dan@mingo.place enabling mingo-poster end-to-end). Cert signature-over-cert not verified in-page (deferred to downstream warrant verifiers, by design). set_parent/subordinate link not recorded on this path (deferred follow-up).
