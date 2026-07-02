---
# mingo-cm8z
title: 'browserid: subordinate/derived identities (parent-bound, minted-after-parent-proof)'
status: in-progress
type: feature
priority: high
created_at: 2026-07-01T20:38:32Z
updated_at: 2026-07-02T14:52:32Z
blocked_by:
    - mingo-z8im
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
- [ ] Revert [[mingo-jn21]]: remove GET /owner_for (routes.rs + main.rs) and the hinted auth.js; restore auth.js to the simple session-check.
- [ ] Broker: schema migration for emails.parent_email + derived flag; store methods.
- [ ] Provisioning protocol: accept + validate subordinate_to at cert issuance; record it.
- [ ] mingo-idp: declare subordinate_to (=account.external_email) when minting <handle>@mingo.place.
- [ ] Dialog: derived-identity copy, select→parent-auth, expired-parent greying.
- [ ] Tests: subordinate can't be used without fresh parent proof; parent validated ∈ account; mapping never exposed unauthenticated.


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
