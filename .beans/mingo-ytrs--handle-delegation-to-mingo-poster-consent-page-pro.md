---
# mingo-ytrs
title: 'Handle delegation to mingo-poster: consent-page provisioning fails on mobile'
status: todo
type: bug
priority: normal
created_at: 2026-07-15T07:26:41Z
updated_at: 2026-07-15T07:26:41Z
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
