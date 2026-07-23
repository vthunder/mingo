---
# mingo-3f3i
title: 'mingo-poster agent: delegated server-side signing (mobile posting)'
status: completed
type: feature
priority: normal
created_at: 2026-07-14T16:52:00Z
updated_at: 2026-07-23T12:43:26Z
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

## Design locked (with Dan)

- Cross-issuer warrants: relax same-issuer so ANY email can warrant
  mingo-poster@mingo.place. Foundation tracked in browserid-ng bean
  'Cross-issuer agent warrants'. Single-parent binding unchanged (per-user
  in-process certs).
- Second DNSSEC proof: support both inline + on-chain; mingo uses on-chain
  (/sys/dnssec/<issuer> refreshed for both agent + delegator issuers).
- Attribution: user warrants mingo-poster with as:<user>, on-chain visible.
- Delegation UX: mingo.place -> browserid.me/account, sign a WARRANT ONLY (no
  agent creation); mingo-poster appears under a separate 'external agents'
  list; revoke there. The warrant request carries a DELEGATOR HINT (mingo knows
  which identity the user should sign as) so the consent page pre-selects it.
- Service identity: mingo mints/refreshes mingo-poster@mingo.place headlessly
  in-process (owns mingo.place IdP key); per-user certs parent=<user>.

## Sequencing
1. sbo-core two-issuer warrant verification + tests + spec (foundation).
2. Daemon: resolve delegator issuer proof (inline | on-chain).
3. Registrar: third-party warrant-request entry point (+ delegator hint).
4. Account UI: external-agents list.
5. mingo backend signer + mingo-web delegation redirect + submit-unsigned.

## Registrar consent — implementation plan (design confirmed with Dan)

Unify into the EXISTING /warrant/request (not a separate endpoint), branching on
request contents. Both modes keep the 'request signed by the agent' principle.

- Own-agent mode (today): RequestBundle U_cert~P_cert~R, gated by a registered
  provisioning cert; agent_email = <name>@<user-domain>.
- External mode (new): body carries agent_cert ~ R, where R is signed by the
  AGENT IDENTITY key (verified under agent_cert.public_key()); agent_email = the
  agent cert's email (mingo-poster@mingo.place); delegator = a NEW claim in the
  request (the hint mingo passes; the identity the user signs as). No
  provisioning-cert gate.

browserid-core change: add `delegator: Option<String>` to
ProvisioningRequestClaims + a warrant_external() constructor (Action::Warrant,
signed by agent key) + a verify path for the agent_cert~R bundle
(agent_cert.is_agent(), R.verify(agent_cert.public_key()), delegator present).

Anti-spam (signing alone is insufficient — Dan):
1. Redirect-tied: mingo creates the request, gets a code, redirects the user to
   verification_uri_complete (/consent/<code>). No browsable pending inbox for
   external requests — unsolicited ones are never surfaced, just expire.
2. Per-delegator rate-limit on pending external requests.

Consent UI (account.html): 'external services' section shows GRANTED warrants
(revocable via existing /wsapi/revoke_warrant), NOT a pending inbox.

respond(): confirm it only does binding checks (audience/agent/delegator vs the
pending record) + stores; relax only if it cryptographically re-enforces
same-issuer.

Sequence: (1) browserid-core external request type + tests; (2) registrar
/warrant/request external branch + store + rate-limit; (3) consent page +
account 'external services' UI; (4) mingo backend signer + mingo-web redirect.


## Implementation plan (confirmed 2026-07-14, browserid-ng side shipped)

browserid-ng external-warrant support is MERGED + DEPLOYED (browserid.me): POST /warrant/request
accepts a 2-part `agent_cert~R` bundle, verifies it against the agent's foreign issuer key
(DNSSEC-discovered), routes the delegator hint to the local account, and parks a redirect-tied
`/consent/<code>` row. So mingo is now unblocked to build the requester + signer side.

### Confirmed attribution (from sbo-core authorize.rs)
Post attributed to the USER (pseudonym preserved) via an on-behalf warrant: the warrant the user
signs at consent MUST carry `as:<user-email>` + at least one `path:` scope → `warrant_effective_email`
returns the delegator (the user). Audience must identify the mingo db (`sbo+raw://avail:turing:506/`
bare, per deploy/sbo-daemon; `audience_identifies_db` accepts the bare authority across regenesis).

### SBO agent-write shape (from sbo-core tests/agent_write.rs)
Message signed by the shared mingo-poster agent key, with `auth_cert` = per-user agent cert
(agent=mingo-poster@mingo.place, parent=<user>, minted in-process by mingo IdP key),
`auth_warrant` = the user-signed warrant JWS (from /warrant/poll), `auth_evidence` = on-chain
`/sys/dnssec/` ref (mingo posts /sys/dnssec for BOTH mingo.place and the user's issuer). owner =
the user's email (object lives in the user's namespace; effective author resolved from warrant).

### Dependency bumps needed
- mingo-idp/Cargo.toml: browserid-core rev a39b5ea → (>= e572cda, the merged external-warrant work)
  for ProvisioningRequest::warrant_external + ExternalWarrantRequest. Non-breaking (additive;
  create_agent signature unchanged).
- mingo-idp: ADD sbo-core dep (rev 3a6f959, matching deployed daemon) for Message/wire assembly +
  authorize/attribution helpers. (mingo-idp currently has no sbo-core dep.)

### Pieces (in dependency order)
1. Config: shared mingo-poster agent key (MINGO_POSTER_KEY_* mirroring load_or_generate_keypair).
2. poster.rs (mingo-idp): pure, unit-testable —
   - mint_poster_cert(user_email) -> Certificate (create_agent, parent=user, mingo IdP key)
   - external_warrant_request(user_email, grants) -> `agent_cert~R` string (warrant_external, signed
     by the poster agent key)
   - assemble_agent_write(user_email, warrant_jws, spec) -> wire bytes (Message + auth_cert/warrant/
     evidence, signed by agent key)
3. store.rs: `poster_warrants` table (account_id/user_email → warrant JWS + aud + scopes + exp).
4. Endpoints (routes): POST /poster/enable (session-gated) → build external request, POST to
   browser id.me/warrant/request, return verification_uri for redirect; POST /poster/poll (or
   server-side poll loop) → /warrant/poll, store warrant; GET /poster/status; POST /poster/submit
   (session-gated) → look up warrant, mint/refresh cert, assemble wire, POST daemon /v1/submit.
5. On-chain /sys/dnssec refresh for mingo.place + each delegator issuer (auth_evidence source).
6. mingo-web app.js: "Let mingo post for me" toggle → /poster/enable redirect; when enabled, route
   writeContent to /poster/submit instead of signEnvelope+submitWire. Keep client path as fallback.

### Open/verify during impl
- Daemon owner-vs-effective-email check: confirm owner=<user> is accepted for an on-behalf agent write.
- auth_evidence format the deployed daemon expects for the second (delegator) issuer proof (on-chain
  /sys/dnssec ref vs inline) — align with sbo-core attribution.rs daemon-resolved path.


## Progress (2026-07-15) — signer core landed on branch feat/mingo-poster-signer

DONE (commit a318055, tested, on branch — NOT deployed):
- [x] Dependency bumps: mingo-idp browserid-core → e572cda; workspace sbo-core → 3a6f959
      (daemon rev). Two browserid-core versions coexist safely (signer crosses the sbo
      boundary only as encoded strings). mingo-app auth_warrant field fixes.
- [x] Config: shared mingo-poster key (MINGO_POSTER_SECRET/_KEY_JSON/_KEY_FILE) +
      MINGO_SBO_DB_AUDIENCE + MINGO_DAEMON_URL; AppState.poster_key loaded at boot.
- [x] poster.rs signer core (pure, unit-tested): mint_poster_cert, external_warrant_request,
      default_scopes (as:<user> → effective author = user), assemble_agent_write.

REMAINING (next increment — needs live-daemon verification):
- [ ] store.rs: poster_warrants table (account → warrant JWS + aud + scopes + exp).
- [ ] Endpoints: POST /poster/enable (session) → build external request, POST browserid.me
      /warrant/request, return verification_uri for redirect; poll /warrant/poll → store warrant;
      GET /poster/status; POST /poster/submit → assemble wire, POST daemon /v1/submit.
- [ ] auth_evidence: post/refresh on-chain /sys/dnssec for mingo.place AND each delegator issuer.
- [ ] mingo-web app.js: "Let mingo post for me" toggle → /poster/enable redirect; route
      writeContent → /poster/submit when enabled (keep client-signed path as fallback).
- [ ] VERIFY against live daemon: owner=<user> accepted for on-behalf agent write; exact
      auth_evidence format the deployed daemon expects for the delegator-issuer proof.


## Endpoints + web toggle landed (2026-07-15, commit 1e3dc3e on feat/mingo-poster-signer)

DONE (tested; branch not deployed):
- [x] store.rs: poster_warrants + poster_pending tables (CREATE IF NOT EXISTS — no migration step) + round-trip test.
- [x] Endpoints (session-gated, same-origin): POST /poster/enable (mint cert → external warrant request → browserid.me/warrant/request → verification_uri), POST /poster/poll (store approved warrant), GET /poster/status, POST /poster/disable, POST /poster/submit (assemble agent write → daemon /v1/submit). 4 HTTP smoke tests.
- [x] mingo-web app.js: "📱 let mingo post for me" toggle (tap-through approve link, no window.open; background poll), writeContent routes email-rooted writes → /poster/submit when enabled, client-signed path kept as fallback.

STILL TO VERIFY LIVE (before rollout — deploy mingo to test):
- [ ] Daemon accepts owner=<user> for an on-behalf (as:) agent write (I set owner=user; if the
      daemon wants owner=agent, adjust assemble_agent_write's owner + the submit handler).
- [x] /sys/dnssec freshness — DONE server-side (commit eaafd41). /poster/submit refreshes BOTH the
      agent issuer (mingo.place) and the delegator issuer (from the warrant's parent-cert iss) before
      assembling: GET /v1/dnssec, and on stale submit a key-rooted set_dnssec write with a throwaway
      key. Mirrors the client's ensureDnssecFresh.
- [ ] Deploy config: set MINGO_POSTER_SECRET (or _KEY_JSON/_KEY_FILE) on the mingo dokku app.
- [ ] Handle-identity delegation depends on the handle's identity key being available in the
      browserid.me consent-page keystore (external-email delegation works cleanly; handle may need the
      user to have that identity active at browserid.me first).


## Deploy note (2026-07-14): single browserid-core version required
First mingo deploy failed: cargo-chef 0.1.77 panics cooking a recipe with TWO
versions of the same git package (mingo-idp on browserid-core e572cda + sbo-core
pulling 4fdfa86). Fixed by bumping sbo-core's browserid-core pin to e572cda
(new sbo rev 6f049c0, additive/no-logic-change) so everything resolves to ONE
browserid-core. mingo now on sbo-core 6f049c0. Daemon stays at 3a6f959 (its
sbo-core library logic is identical, so wire-compatible; e572cda agent certs are
a superset-compatible descendant of 4fdfa86 the daemon verifies against).


## Deploy fix #2 (2026-07-14): rocksdb/libclang out of the mingo build
The real deploy blocker (masked under the cargo-chef panic): adding sbo-core to
mingo-idp pulled rocksdb → librocksdb-sys → bindgen → libclang, which the mingo
builder image lacks (and would cold-compile rocksdb on the disk-constrained
on-host build). Fix: sbo-core a92886c gates its rocksdb-backed state store
(state::db + indexer) behind a default-on `storage` feature; mingo disables it
workspace-wide (default-features=false on the root sbo-core dep) since neither
mingo-idp nor mingo-app uses the state store. Workspace tree now rocksdb-free.
mingo on sbo-core a92886c. Daemon still 3a6f959 (unaffected).

## Superseded + SHIPPED via the holder model (2026-07-23 reconciliation)
The user-facing goal — opt-in server-side (popup-free, mobile-reliable) posting — SHIPPED, but via the holder-authorization model, NOT the as:-warrant/cross-issuer design detailed above. Under the holder model the poster is an **as-you service** (owner==user, no as: scope, no separate mingo-poster@ identity; isolation via a broker-assigned holder in the user's 'services' namespace). Implemented in mingo-idp/src/poster.rs (main 58ed2ea + fixes 1a03483/4cf300d/b4e5ca3), deployed, and live-confirmed by Dan 2026-07-22 (mingo posted on his behalf). The as:-approach branch feat/mingo-poster-signer (fully contained in main, 0 unique commits) was deleted. Tracking + remaining polish live on browserid-ng-3b8m (human re-test) and browserid-ng-p5i0 (cold-start bootstrap).
