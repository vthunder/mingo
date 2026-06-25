---
# mingo-nr6m
title: Per-community membership (scoped join, enforced on-chain)
status: in-progress
type: feature
priority: normal
created_at: 2026-06-25T21:57:08Z
updated_at: 2026-06-25T22:03:43Z
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

- [ ] presets.rs: scoped open community policy + use in mingo_genesis loop; drop global membership grant in hub root policy
- [ ] SPA: joinHub(commId) issues type membership:<commId> (id membership-<commId>); hasMembership(commId) checks it; viewCommunity passes commId
- [ ] Migration: write superseding per-community policy objects (+ root) to app 506 signed by sys key
- [ ] Tests: member of A cannot post to B
- [ ] Deploy SPA + run migration
