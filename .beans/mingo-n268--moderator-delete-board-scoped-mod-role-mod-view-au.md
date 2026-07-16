---
# mingo-n268
title: 'Moderator delete: board-scoped mod role, mod view, audit attestations'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T21:22:25Z
updated_at: 2026-07-16T21:23:26Z
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
- [ ] Delete affordance for moderators on any item in their board (UI differs from author-delete — likely surfaced in mod view)
- [ ] Mod view per board: recent items + delete — decided in v1 (dan, 2026-07-16)
- [ ] `mod:remove` companion attestation naming the deleted object (audit trail per SBO Community Spec:163) — decided in v1 (dan, 2026-07-16)
