---
# mingo-gj9r
title: User-created boards
status: todo
type: feature
priority: normal
created_at: 2026-07-16T00:25:52Z
updated_at: 2026-07-16T21:23:44Z
parent: mingo-y9gb
---

Let users create their own community/board that others can discover and join, instead of only the three genesis communities (cooks/woodworking/homelab).

## Design notes (verify against current policy at build time)
- Today communities are created only by the sys key in genesis (a community.v1 descriptor + a community-root policy.v2 + a spaces/general/_config collection, per mingo-app/src/genesis.rs). The hub root policy grants community creation to the admin (sys) role on /**.
- For user creation we need a policy path that lets a signed-in identity create /communities/<id>/ objects they own. Options to weigh: (a) a delegated/among grant in the hub root policy allowing any member to create under /communities/<newid>/ where they become the community issuer/owner; (b) an IdP-mediated create (mingo-idp mints the community objects on the user's behalf, like it does for other server-side writes) so policy stays tight; (c) sys-key-signed creation via an admin endpoint (simplest, least sovereign).
- The creator should become the community's issuer (attestation authority) + first moderator (ties into the moderation bean). Membership stays self-issued (membership:<id>) as today.
- Need: id/name uniqueness + collision handling, a create-board UI (name, description, open/closed), and the new board appearing in the sidebar discovery list.
- Open question: closed/invite-only boards vs open (self-join). Start with open self-join to match current model.

## Autonomous-run note (2026-07-16) — deferred, needs you
Skipped in the overnight run: user-created boards requires giving non-sys identities authority to create /communities/<id>/** + write a governing policy, which under the current genesis means UPDATING THE HUB ROOT POLICY at /sys/policies/root (sys-signed). That is a root-policy change on the live chain — too risky to do unsupervised, and it is the crux design decision (which grant shape: members-create-anywhere-they-own vs IdP-mediated create vs a dedicated create-authority key). Recommend: decide the mechanism together, then a supervised sys-key op. sys key is at ~/secure-backup/mingo-sys.key.

## Decision (dan, 2026-07-16)

Once user-created boards land, remove the three genesis communities (cooks/woodworking/homelab) from genesis and re-genesis to clean up. So: no need to retrofit issuer/moderator machinery onto the genesis boards — moderation (mingo-n268) targets user-created boards only, and this bean blocks it.
