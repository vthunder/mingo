---
# mingo-cm8z
title: 'browserid: subordinate/derived identities (parent-bound, minted-after-parent-proof)'
status: completed
type: feature
priority: high
created_at: 2026-07-01T20:38:32Z
updated_at: 2026-07-04T17:24:38Z
---

Model derived identities natively in browserid instead of leaking the mapping from mingo. A <handle>@mingo.place identity is SUBORDINATE to its parent (the external email that controls it): browserid records parent↔subordinate in the user's own account (private; no public oracle like the scrapped /owner_for), and only lets the subordinate be used after a fresh proof of the parent.

Supersedes the hinted-owner approach in [[mingo-jn21]] (that used an UNGATED GET /owner_for → deanonymized every handle→owner mapping to anyone; a real privacy leak). Also removes W3's experimental RP-nested-in-IdP flow: browserid authenticates the parent via its OWN native primary auth (opens sandmill.org), no nested broker dialog.

Depends on [[mingo-1c6v]]+[[mingo-z8im]] (account linking/merge) so parent+subordinate live in one account. Relates to [[mingo-sux8]] (identity model) and the cert-expiry work.

## Design
- Provisioning signal: mingo declares `subordinate_to: <parent_email>` when issuing the cert. browserid VALIDATES the parent is already an email in this account (mingo can't subordinate to an arbitrary address) and stores it.
- Broker store: emails.parent_email (nullable, self-referential within account) + derived flag; migration.
- Dialog UX: (1) distinct copy for derived identities; (2) selecting a subordinate auto-runs the parent's primary auth first; (3) if the parent proof/cert is expired, show parent + subordinate greyed / needs-signin.
- Integration: cert_key needs a mingo session, so after browserid proves the parent, hand mingo the parent assertion to establish it (existing /session/from-assertion).
- Enforcement stays defense-in-depth: browserid gates on fresh parent proof; mingo cert_key still checks the session owns the handle.

## Tasks
- [x] Revert [[mingo-jn21]]: /owner_for removed; auth.js restored to simple session-check.
- [x] Broker: schema v3 (emails.parent_email) + store set_parent_email/get; DEPLOYED.
- [x] Provisioning protocol: subordinate_to forwarded over private provisioning channel; recorded via /wsapi/set_parent (validated in account).
- [x] mingo-idp: /cert_key returns subordinate_to = account.external_email (private, not in cert).
- [x] Dialog: select→parent-auth (substitution) live; derived-identity copy DONE (2026-07-04); expired-parent greying WONT-DO (no cheap freshness signal; parent auth already runs on selection).
- [x] Tests: parent validated in account; mapping session-gated own-account only (401 verified); derived pairing surfaced in list_emails; substitution session-gated.


## Refinement: subordination is CONTEXTUAL (2026-07-01)
The 'select subordinate → sign in as parent' behavior applies ONLY when the RP is the subordinate's own issuing IdP (RP domain == identity issuer, e.g. logging into mingo.place with dan@mingo.place). Everywhere else the subordinate is a FIRST-CLASS identity: other RPs get a plain mingo.place assertion that reveals nothing about the parent (sandmill.org).

Rule: if RP domain == selected identity's issuer AND identity is subordinate → browserid substitutes the PARENT assertion; else deliver the identity's own assertion normally.

### Scenario 1 — signed into browserid (works)
Picking danmills OR dan for a mingo.place login → browserid (knowing the parent pointer) delivers the danmills@sandmill.org assertion → mingo.place sets session + refreshes the dan@mingo.place cert.

### Scenario 2 — signed OUT of browserid (must not leak)
Subordination metadata is account-scoped (server-side, session-gated), so signed out it's UNAVAILABLE → nothing can reveal the parent. Safe behavior falls out: mingo.place/auth with no session returns a GENERIC 'sign into browserid first' (the simple session-check; NO /owner_for). User signs into browserid via the parent (which they know) → scenario 1.

### Pitfall: do NOT cache the subordinate→parent mapping in localStorage (would leak to a signed-out attacker on a shared browser). Account-scoped only. Scenario-2 UX cost (generic 'sign in first' vs a helpful reminder) is the pseudonymity price.

### Open UX decision (scenario 2): generic 'sign in first' dead-end vs. don't surface the subordinate at all when signed out. Both non-leaking.


## Signaling decision (2026-07-01): out-of-band, not in the cert
browserid-core CertificateClaims is fixed (iss/exp/iat/public_key/principal) — no extra-claims slot. So DON'T put subordinate_to in the cert (would change the cert format globally). Instead:
- mingo /cert_key response includes `subordinate_to: <account.external_email>` (only for minted <handle>@domain certs).
- dialog forwards it to a NEW broker wsapi (e.g. /wsapi/set_parent { email, parent_email }) that sets emails.parent_email after validating BOTH belong to the current session's account.
- Cert format unchanged.

## Concrete build order
1. Broker schema: migrate_v3 adds emails.parent_email TEXT (nullable, self-ref within account); bump SCHEMA_VERSION=3. Store: set_parent/get, include parent in Email + list_emails.
2. Broker wsapi set_parent (session-gated, validates both emails ∈ account).
3. mingo-idp /cert_key: return subordinate_to = account.external_email.
4. dialog: after provisioning a subordinate, call set_parent; RP-scoped parent substitution (scenario 1) when RP domain == identity issuer; scenario-2 generic 'sign in first'.
5. Tests + live iteration.

## Prereqs status: W1 (mingo-1c6v) + W2 (mingo-z8im) DEPLOYED to browserid.me 2026-07-01 (commit 148eec1). Foundation live.


## CORRECTION (2026-07-02): parent signal must NOT be in the cert
The cert is embedded in assertions sent to EVERY RP, so a subordinate_to cert claim would leak the parent to every relying party. (Tried it, reverted.) The signal must travel a PRIVATE channel and land only in browserid's server-side account metadata:

  mingo /cert_key response (subordinate_to, private) -> mingo provision.js -> postMessage (iframe<->dialog, never sent to RPs) -> browserid dialog -> POST /wsapi/set_parent {email, parent_email} (session-gated) -> emails.parent_email

Parent email lives only in: mingo DB, mingo /cert_key response, a same-broker postMessage, browserid account row. NEVER in cert/assertion/RP.

Iframe->dialog hop options: (a) extend provisioning API registerCertificate(cert, {subordinate_to}) to forward metadata (cleanest); (b) provision.js postMessages {subordinate_to} to the dialog, which validates origin==IdP.

Cert-claim approach ABANDONED. browserid-core reverted (no cert change).

### IMPLEMENTED + DEPLOYED 2026-07-02
browserid-ng (aac90e2, app id) + mingo (39fbf0a, app mingo.place). All builds/tests green.
- browserid: schema v3 (emails.parent_email; migrated live current=2->3, DB NOT wiped — persistence holding), store set_parent_email, POST /wsapi/set_parent + GET /wsapi/parent_of (both session-gated, own-account only, 401 verified), provisioning_api.js registerCertificate(cert, metadata), provisioning.js forwards metadata, dialog handlePrimaryIdP calls set_parent, dialog handleEmailChosen substitutes parent when RP==issuer (recursion-guarded).
- mingo-idp: /cert_key returns subordinate_to = account.external_email (private, not in cert); provision.js forwards as provisioning metadata.
- Signal stays private: parent email only in mingo DB, /cert_key response to own provision page, same-broker postMessage, browserid account row. NEVER in cert/assertion/RP.

REMAINING: live validation + UX refinement (the substitution flow, chooser copy for derived identities, expired-parent greying — scenario 3 UX). Core recording + substitution paths are live to test.

### WORKING end-to-end 2026-07-02 (verified live)
Record + substitute + provision all confirmed. Two bugs found & fixed during live test:
1. mingo served a STALE copy of provisioning_api.js that dropped the metadata arg → parent never recorded (parent_email NULL). Synced (mingo abe09cd). [maintenance: mingo duplicates provisioning_api.js from the broker — keep in sync, or serve the broker's.]
2. Substitution fired during mingo's explicit provisionEmail step, swapping dan→danmills so the session showed the external email. Guarded: skip substitution when state.provisionEmail is set (browserid 258779a).
Core cm8z (private parent metadata + parent substitution on chooser-selection) is functional. Substitution correctly does NOT leak (session-gated) and does NOT fire during explicit provisioning.

### REMAINING (UX polish, deferred)
- Chooser copy for derived identities; grey-out subordinate when parent proof expired.
- Typed-email entry path doesn't substitute (only the chooser does) — see test-1 hardening.
- Consider serving the broker's provisioning_api.js instead of mingo's copy (avoid drift).

### Typed-path substitution DONE + DEPLOYED 2026-07-02 (browserid d403701)
Extracted maybeSubstituteParent() (RP==issuer, session-gated parent_of, skipped during provisionEmail); used by BOTH the chooser and the typed email-entry path. So typing a subordinate to log into its issuer also substitutes the parent.

## Chooser copy for derived identities — DONE (2026-07-04, browserid-ng, not yet deployed)
Item 1 of the deferred UX polish. Implemented in `/Users/thunder/src/browserid-ng`:
- Backend: `GET /wsapi/list_emails` now returns a `derived: [{email, parent_email}]` array (session-gated, own-account only — same privacy scope as `parent_of`; never in cert/assertion). New `DerivedIdentity` struct in routes/email.rs. Corrected the stale set_parent doc-comment ("never exposed by any read endpoint" → readable only by the owning session).
- Dialog: `state.derived` map built from the response; `populateEmailList` renders a distinct `.derived` `<li>` with a `signs in via <parent>` sub-label (added `escapeHtml` helper — the list previously interpolated raw email strings into innerHTML). New `.email-sub` CSS.
- Tests: `test_list_emails_reports_derived` (derived pairing surfaced) + existing list_emails tests assert `derived` empty for non-derived. Full browserid-broker suite green.

## Item 2 (grey-out subordinate when parent proof expired) — needs design decision
No cheap server-side parent-proof-freshness signal exists (Email has only verified_at, no per-parent proof timestamp). Deciding approach before implementing — see chat.

## Summary of Changes

Derived/subordinate identities are modeled natively in browserid with the parent-to-subordinate mapping kept private (mingo DB, /cert_key response to own provision page, same-broker postMessage, browserid account row; NEVER in a cert/assertion/RP). Core recording + RP==issuer parent substitution (chooser + typed paths) deployed to browserid.me 2026-07-02. Final UX polish landed 2026-07-04: the chooser now labels derived identities ('signs in via <parent>') via a new session-gated `derived` field on `list_emails`. Expired-parent greying was decided WONT-DO: there is no cheap server-side parent-proof-freshness signal, and selecting a subordinate already triggers the parent primary auth (interactive if stale), so greying would add an inaccurate signal for no benefit.

DEPLOYED 2026-07-04: item-1 chooser-copy committed (browserid-ng 6965fa9) and deployed to browserid.me via Dokku (sha 6965fa9 live, app running, /wsapi/list_emails 401-unauth confirmed). Note: the initial push's git client hit a local timeout mid-build but the Dokku build completed server-side and advanced the ref.
