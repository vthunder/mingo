---
# mingo-w41d
title: Email-rooted /sys/names identity self-loops in primary domain -> owner Unresolved (can't pin key)
status: completed
type: bug
priority: high
created_at: 2026-07-07T20:35:07Z
updated_at: 2026-07-07T21:56:56Z
parent: mingo-sux8
blocking:
    - mingo-hqp2
---

Found 2026-07-07 during the mingo-hqp2 attestor e2e test. An email-rooted `identity.email.v1` record at `/sys/names/<handle>` in the PRIMARY domain resolves in a self-loop, so the identity can never authorize its own subsequent writes via a pinned key.

## Trace (sbo-core resolve.rs resolve_controller)
Record: /sys/names/attestor, identity.email.v1, owner_ref="attestor@mingo.place" (confirmed on-chain).
- resolve("attestor@mingo.place"): has '@', primary_domain=mingo.place, local="attestor", lookup("attestor") is_some -> current="attestor".
- resolve("attestor"): local name -> lookup -> name_lookup returns EmailRooted(owner_ref="attestor@mingo.place") (validate.rs:95-98) -> current="attestor@mingo.place".
- back to email -> local "attestor" already visited -> CYCLE -> Controller::Unresolved.
Result: attestation writes to /u/attestor@mingo.place/** fail L2 with `attr:✗ (owner 'attestor@mingo.place' could not be resolved)`.

## Why it matters (beyond the attestor)
Any email-rooted identity whose /sys/names/<local> record exists in its own primary domain has this loop. Such an identity can only authorize writes via per-write BROWSERID attribution (Auth-Cert+Auth-Evidence), never via a resolved pinned key — because the sovereignty record (meant to be "the on-chain control policy that wins over browserid") points back to the email instead of to a key. name_lookup: identity.v1 -> KeyRooted(pubkey from JWT); identity.email.v1 -> EmailRooted(owner_ref) -> loops.

## Options (identity-model decision — relates to mingo-sux8)
- A. The sovereignty record for an email identity should be KEY-ROOTED (or identity.email.v1's owner_ref / name_lookup should yield the controlling pubkey from the cert), so resolve returns Controller::Key. This is the "sovereignty upgrade" actually pinning the key. Cleanest; makes email identities' writes work without per-write browserid.
- B. Provision the attestor as a KEY-ROOTED identity.v1 at /sys/names/<handle>, with the claim write carrying Auth-Cert+Auth-Evidence to pass the primary-domain name gate (validate.rs:714). Aligns with owner's "key-rooted via /sys/names with pubkey" model. Needs a preset/flow: identity.v1 + attribution headers. (Note: /sys/names/attestor is now burned by the Unresolvable email record; would need a fresh handle + fresh cert.)
- C. build_attestation_wire embeds Auth-Cert+Auth-Evidence per write (Controller::Email path). Only works if NO /sys/names record exists for the handle (else the loop makes it Unresolved, not Email). Heavy: attestor holds a 24h-expiring cert + captures DNSSEC per write.

Recommend A (fix the sovereignty-record key pinning) as the correct general fix; B as the pragmatic unblock for the attestor test.

Blocks mingo-hqp2 e2e (attestations post but fail authorization). Relates to mingo-blpo, mingo-sux8.
