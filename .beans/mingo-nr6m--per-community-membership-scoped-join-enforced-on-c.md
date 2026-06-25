---
# mingo-nr6m
title: Per-community membership (scoped join, enforced on-chain)
status: completed
type: feature
priority: normal
created_at: 2026-06-25T21:57:08Z
updated_at: 2026-06-25T22:13:18Z
---

Today open communities use a single self-issued 'membership' attestation that grants posting to ALL open communities (root policy role member = {attested:{type:membership}}, grant post on /spaces/**). Users expect to join each community separately. Make membership community-scoped and enforced on-chain, with the SPA showing Join per community.

Design pending investigation of: (a) whether the policy engine's attested role matcher can constrain on attestation value/subject/path or only type; (b) per-community policy resolution at /communities/<id>/; (c) current seeding of community descriptors + policies.

Likely workstreams:
- [ ] Scope the membership attestation per community (path or value carries community id)
- [ ] Per-community policy granting post only to that community's members (or extend root policy matcher)
- [ ] Re-seed existing communities with scoped policies
- [ ] SPA: joinHub(commId) issues scoped membership; hasMembership(commId) checks it; per-community Join button
- [ ] Tests (daemon authz: member of A cannot post to B)
- [ ] Deploy

## Decision (2026-06-26)

On-chain policy update to live app 506 (non-destructive, keeps posts; users re-join) AND update presets so a fresh genesis uses the same per-community model.

Approach: community-scoped membership TYPE (membership:<commId>) — no policy-engine change (matcher already filters on type; ':' already used by role:moderator attestations). Per-community policy member role = {attested:{type:'membership:<id>'}}; remove the hub root policy's global membership grant.

- [x] presets.rs: scoped open community policy + use in mingo_genesis loop; dropped global membership grant in hub root policy
- [x] SPA: joinHub(commId) issues membership:<commId>; hasMembership(commId) checks it; viewCommunity passes commId
- [x] Migration: superseded cooks/homelab/woodworking policies on app 506 via sbo domain open-community + /v1/submit (sys key); all confirmed on-chain
- [x] Test: community_scoped_membership_does_not_cross_communities (member of A cannot post to B)
- [x] Deployed SPA + ran migration

## Summary of Changes

Membership is now per-community, enforced on-chain. Mechanism: community-scoped attestation type membership:<commId> (no policy-engine change — matcher already filters on type, as role:moderator does).

Code: presets::community_policy_open requires membership:<id>; mingo_genesis uses it and drops the hub root policy global membership grant (the old cross-community bypass). SPA joinHub/hasMembership scoped per community. New daemon test proves cross-community denial.

Migration (live app 506, non-destructive): generated superseding policy objects with sbo domain open-community signed by the sys key (local default keyring = /sys/names/sys) and POSTed to da.sandmill.org/v1/submit. All three community policies (cooks, homelab, woodworking) confirmed on-chain serving membership:<id>. Existing posts/comments/votes preserved; users with the old global membership must re-join each community (expected). SPA deployed.

Commit 4c99b1b.
