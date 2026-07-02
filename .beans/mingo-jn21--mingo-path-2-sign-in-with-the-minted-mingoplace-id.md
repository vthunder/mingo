---
# mingo-jn21
title: 'mingo Path 2: sign in with the minted @mingo.place identity (prove owner, re-issue)'
status: scrapped
type: feature
priority: high
created_at: 2026-07-01T16:48:17Z
updated_at: 2026-07-02T15:26:47Z
blocked_by:
    - mingo-z8im
    - mingo-cm8z
---

Path 1 (sign in with the owner email at its IdP -> mingo auto-provisions/refreshes the <handle>@mingo.place cert) already works. Build Path 2: let a user start login by choosing their minted <handle>@mingo.place identity.

## Flow
1. A browserid assertion for a @mingo.place email reaches mingo-idp (today `reject_own_domain` dead-ends this with 'cannot be used to sign in').
2. Instead: parse handle -> `account_id_for_handle` -> account.external_email (store.rs already has this mapping; Account{external_email, handle}).
3. Require a browserid proof of ownership of account.external_email (drive the broker to authenticate that email — redirect/assertion for the owner email).
4. Only after that proof: establish the mingo session and re-issue/refresh the <handle>@mingo.place cert (/cert_key).

## Tasks
- [ ] mingo-idp: replace the reject_own_domain dead-end at /session/from-assertion with the handle->owner-email resolution + owner-proof challenge.
- [ ] mingo-idp: after owner proof, re-issue the minted cert (reuse existing cert mint path).
- [ ] mingo-web: offer the minted identity as a login entry point and drive the owner-proof round-trip via the broker dialog (provisionEmail hint for the owner email).
- [ ] Keep the security invariant: a minted @mingo.place cert is only ever issued after a fresh owner-email proof.
- [ ] Tests: login as dan@mingo.place -> challenged for danmills@sandmill.org -> proof -> dan@mingo.place cert re-issued.
Relates to [[mingo-sux8]] (identity model) and depends on the browserid link/merge fixes for a coherent chooser.

### Progress 2026-07-01 — implemented (broker-routed, owner-hinted; per user)
- mingo-idp GET /owner_for?email=<handle>@domain → {owner_email}: resolves handle→account→external_email (routes.rs + registered in main.rs). Unknown handle → Forbidden (no enumeration). Builds.
- auth.js rewritten for Path 2: on no mingo session, resolve owner via /owner_for, open the broker dialog to authenticate that specific owner (provision_email hint), POST /session/from-assertion, then completeAuthentication → dialog re-provisions the <handle>@mingo.place cert.
- Security: cert_key already enforces the session owns the requested handle, so proving the wrong owner can't mint another's identity — the owner hint is UX, not the security boundary.

### EXPERIMENTAL / needs live validation
auth.js Case 2 opens a broker dialog from INSIDE the broker's own /auth popup (RP flow nested in IdP flow) — the part the user flagged as maybe-unsupported. Falls back to raiseAuthenticationFailure with guidance if the nested popup is blocked. Must be tested live on browserid.me + mingo.place; may need a redirect-based variant if nested popups fail.

### Deploy needed
mingo-idp → mingo.place (owner_for + auth.js). Pairs with the browserid-ng W1/W2 deploy (mingo-1c6v/z8im).


### SUPERSEDED 2026-07-01 by [[mingo-cm8z]]
The hinted-owner design here has a privacy flaw: the GET /owner_for endpoint I built is UNGATED, so anyone can map handle→owner (deanonymizes every @mingo.place identity). Replaced by browserid-native subordinate identities (mingo-cm8z): the parent↔subordinate mapping lives in the user's own browserid account (private), and browserid drives the parent auth natively (no nested RP-in-IdP).
ACTION: revert the /owner_for endpoint (routes.rs + main.rs route) and the hinted auth.js (restore simple session-check). Path 2 UX is subsumed by cm8z.

## Reasons for Scrapping
Superseded by [[mingo-cm8z]] (browserid-native subordinate identities). The hinted-owner design here required an ungated /owner_for endpoint that deanonymized every handle→owner mapping (privacy leak), and the RP-nested-in-IdP flow. cm8z replaces it: the parent mapping lives privately in the browserid account, and browserid substitutes the parent on selection — no leak, no nesting. /owner_for + hinted auth.js were reverted.
