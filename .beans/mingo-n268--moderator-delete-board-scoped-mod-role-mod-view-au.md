---
# mingo-n268
title: 'Moderator delete: board-scoped mod role, mod view, audit attestations'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T21:22:25Z
updated_at: 2026-07-17T06:43:18Z
parent: mingo-6phv
blocked_by:
    - mingo-gj9r
    - mingo-3go6
---

Phase 2 of moderation (mingo-6phv): moderator-role delete grants in community policies, mod view UI, grant/revoke moderator attestations, mod:remove audit trail.

## Scope

Moderators delete others' content in their board. Moderator = board-scoped `role:moderator` attestation issued by the board creator/issuer — hence blocked by user-created boards (mingo-gj9r). Decision (dan, 2026-07-16): do NOT build moderator issuance for the three genesis boards; they'll be removed at regenesis once user-created boards land.

## Policy amendment (smaller than feared — verified 2026-07-16)

- The community policy object at `/communities/<board>/` is sys-OWNED, and owners can always update their objects — so adding the moderator grant is a sys-signed UPDATE of that one object, NOT a root-policy change. Much lower risk than the gj9r root-policy op.
- Grant shape: `{to: {role: "moderator"}, can: ["delete"], on: "/communities/<board>/spaces/**"}` with the role bound to `{attested: {type: "role:moderator", by: "<board issuer>"}}`. All machinery exists in sbo (`policy/types.rs:41-68`, `evaluate.rs:323-366`, live test at `evaluate.rs:505`) — zero new sbo code.
- Gotchas: (1) `delete` must be listed explicitly — `post` = create+update, never delete; (2) the community policy SHADOWS the root (no merge) — restate every grant the subtree still needs; (3) always scope the role with `by:<issuer>` — an unscoped attested check does a full column-family scan at validation time; (4) give moderator attestations an `expires` — deletion of an attestation is head-state-only and invisible to historical readers.

## Todos

- [ ] Community policy grant: moderator-role delete (sys-signed update of the community policy object; supervised op)
- [ ] Moderator attestation issuance UI: grant/revoke `role:moderator` (board creator only; reuse the `vouchFor` attestation-authoring path, `mingo-web/app.js:695-720`)
- [x] Delete affordance for moderators on any item in their board (kebab "Delete (moderator)" + comment "remove" link; envelope signs as the moderator, authorized by the board's moderator-role policy grant, NOT owner spoofing)
- [x] Mod view per board: recent items + delete (route #/c/<board>/mod, moderator-only, reachable via a "Moderate" link in the board header shown only to mods)
- [ ] `mod:remove` companion attestation naming the deleted object (audit trail per SBO Community Spec:163) — decided in v1 (dan, 2026-07-16)


## Summary of Changes (2026-07-17, UI phase — mingo-web)

Built the moderator-delete UI in `mingo-web/app.js` (+ styles in `mingo-web/style.css`). Server-side (`mingo-idp`) needed NO changes — the delete envelope is already correct.

**Moderator detection** — `moderatedBoards()` resolves, in one `attestation.v1` read, the set of board ids the session user moderates: an in-force (`expires` in the future) `role:moderator:<id>` whose AUTHENTICATED issuer (on-chain `owner_ref`, not the self-declared `value.issuer`) equals the community's `issuer` (from the `community.v1` descriptor via `window.__comms`). This mirrors the daemon's `{attested: {type:"role:moderator:<id>", by:<issuer>}}` grant, so the affordance lines up with what will actually authorize. Cached per navigation (`_modBoards`, reset in `route()`); each view refreshes the render-scoped `currentMods` set before building HTML so the sync card/comment renderers can consult it via `isMod()`/`canModDelete()`.

**Corrected delete envelope (the key subtlety)** — verified by code-trace against `sbo-daemon/src/validate.rs`: for `Action::Delete`, `validate_message` SKIPS the L2 owner-attribution gate (transfer/delete exempt) and `validate_delete`→`validate_transfer` resolves the real owner from STORED state (`get_object(path,id)`), tries the owner fast-path (`l2_authorize` against the stored owner — fails for a moderator), then falls to `check_policy(Delete)`, which authorizes the moderator via the moderator-role grant (actor = `resolve_creator` = the signer'\''s attributed email, independent of the `Owner` header). So `Owner` is IGNORED for delete authz. Crucially, the broker signer (`browserid-broker/.../sbo-sign.js`) REQUIRES `spec.owner === signing identity`, so an ownerless delete is impossible — and the existing `deleteContent`→`writeContent` sets `Owner = session.email = the moderator`, which is the SIGNER, NOT the object'\''s real author. That does not spoof the owner, so `deleteContent` needed no change; the moderator path reuses it as-is.

**Affordances** — `cardMenu` (posts, all feeds/thread) shows "Delete (moderator)" and `deleteLink` (comment meta) shows "remove" on any non-owned item in a board the user moderates; both flag `data-moddelete`. `wireDeleteButtons` passes the flag to `beginDelete(uri, asMod)`, which uses moderator copy ("Remove this as a moderator? Everyone loses it.") via the same inline-confirm pattern.

**Per-board mod view** — `viewModerate(commId)` at `#/c/<board>/mod`: guarded to moderators, lists recent posts+comments (newest first) each with a remove control, reachable via a "Moderate" link in the board header shown only to mods. Live-polls like other views.

Verification: `node --check mingo-web/app.js` and `cargo build -p mingo-idp` both pass. End-to-end moderator delete awaits the regenesis (mingo-qjkf) that lands the `community_policy_open` moderator grant live; authorization verified by code-trace against `validate.rs`/`evaluate.rs` in the meantime.

**Remaining (NOT built tonight, left unchecked):**
- Community policy grant (moderator-role delete): part of the regenesis (mingo-qjkf), landing separately — `community_policy_open` in `mingo-app/src/genesis.rs` already carries it.
- Moderator attestation issuance UI (grant/revoke `role:moderator`): OUT OF SCOPE — needs board-creator identity / user-created boards (mingo-gj9r).
- `mod:remove` audit-trail companion attestation: not in this UI phase'\''s scope.

## Appointment path added (2026-07-17)

`mingo appoint-moderator <commId> <subject>` CLI subcommand (commit 9ec9336): mints a `<commId>@mingo.place` issuer cert via mingo-idp /admin/provision, assembles an attestation.v1 (Owner=issuer, type=role:moderator:<commId>, subject) at /u/<issuer>/attestations/<subject>/, submits to the daemon. Dry-run by default; --execute to write. This is the "set the attestation from sys" mechanism (sbo CLI cannot — it attaches no attribution cert for an email issuer). With this, moderator-delete is end-to-end appointable+exercisable on the live chain.

Still open: grant/revoke moderator UI in the SPA (board-creator-only; awaits user-created boards mingo-gj9r for the general case — for genesis boards, appointment is via this CLI).
