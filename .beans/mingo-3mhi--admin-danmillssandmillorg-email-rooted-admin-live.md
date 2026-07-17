---
# mingo-3mhi
title: 'Admin -> danmills@sandmill.org: email-rooted admin, live (no regenesis)'
status: todo
type: feature
priority: high
created_at: 2026-07-17T11:37:01Z
updated_at: 2026-07-17T12:07:54Z
blocked_by:
    - mingo-1pxk
---

Root mingo admin in an EXTERNAL browserid identity (danmills@sandmill.org) instead of the baked sys key, so there is no admin key to manage. Trust deliberately placed in sandmill.org (dan-controlled) + the pinned browserid.me broker; sandmill.org-can-impersonate-sys is accepted. Avoids the mingo-d7bi privesc BY DESIGN: that was sys@mingo.place (mingo-idp's OWN domain, forgeable); sandmill.org is external, mingo-idp cannot mint it.

## Mechanism: M2 (direct email in policy) — verified 2026-07-17

`roles.admin = ["danmills@sandmill.org"]` in /sys/policies/root (Identity::Name is an untagged BARE STRING, not `{name:…}` — a `{name:…}` object is rejected by the daemon: "data did not match any variant of untagged enum Identity"; found live 2026-07-17).
- Policy role matching (evaluate.rs identity_matches) is a pure canonicalized STRING COMPARE against the pre-resolved actor; it NEVER resolves through /sys/names. `canonical_name_ref` leaves a foreign @-email verbatim, so it matches an actor whose attributed email is danmills@sandmill.org (resolve_creator -> attributed_email via sandmill.org DNSSEC + broker). Unforgeable by mingo-idp (foreign domain).
- The user's original idea (M1: keep role = "sys", re-point /sys/names/sys -> danmills) DOES NOT WORK: role matching ignores name records; `canonical_name_ref("sys","mingo.place") = "sys@mingo.place" != "danmills@sandmill.org"`. /sys/names resolution is only used for OWNER auth + attestation subjects, not roles. So the change must be a POLICY edit, not a name-record edit.

## No regenesis needed — verified

The current sys key holds admin-by-key -> `govern` on /** (genesis.rs:438), so it can UPDATE /sys/policies/root IN PLACE (require_govern is satisfied by the sys key via the Identity::Key admin member). Live sys-signed policy write; no chain re-anchoring.

## Safe migration sequence (avoid admin lockout)

Do NOT swap sys-key -> danmills in one step: if danmills can't yet authenticate (no sandmill.org evidence on-chain), you'd brick admin (only regenesis recovers). Instead:
1. PREREQ (user + chain): sandmill.org _browserid record + DNSSEC; danmills@sandmill.org verified at browserid.me; on-chain /sys/dnssec/sandmill.org evidence submitted (see the sandmill-evidence bean). Sign as sys.
2. DUAL-ADMIN: sys-signed policy update -> `roles.admin = [{key: sys_pubkey}, {name: "danmills@sandmill.org"}]`. Both are admin. No lockout risk.
3. VERIFY: perform a real admin op attributed to danmills@sandmill.org (e.g. a no-op policy touch, or appoint-moderator) and confirm it's accepted as admin. (live-test can carry a scenario.)
4. CUTOVER: sys-signed policy update -> `roles.admin = [{name: "danmills@sandmill.org"}]` only. Sys key is no longer admin. Keep it backed up as historical, but note: after this, admin recovery if danmills breaks = sandmill.org DNS recovery, else regenesis (accepted).

## Todos
- [x] `mingo set-root-admin` subcommand built (58ffa8c) + bare-string identity fix (8e5f1b0), used live for step 2.
- [x] PREREQ: sandmill.org evidence on-chain — DONE (/sys/dnssec/sandmill.org live).
- [x] Step 2: dual-admin update LIVE + verified — roles.admin = [{key:sys}, "danmills@sandmill.org"] at block 3626010, 6 grants/2 restrictions preserved. (Exposed + fixed a bug: Identity::Name is a bare string, not {name:…}.)
- [ ] Step 3: verify danmills admin op end-to-end
- [ ] Step 4: cutover to danmills-only admin
- [ ] Update GENESIS.md to record email-rooted admin

## Depends on / relates
- browserid-ng-wmgb (CLI-auth `mingo login`) — the ergonomic way for danmills to act as admin long-term (warrant as: danmills@sandmill.org). NOT strictly required for the migration (a direct danmills cert from browserid.me also works), but the intended day-to-day path.
- Checkpointer-to-email followup (separate bean).
