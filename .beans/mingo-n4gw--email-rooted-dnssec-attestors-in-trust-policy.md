---
# mingo-n4gw
title: Email-rooted (DNSSEC) attestors in trust policy
status: todo
type: task
priority: normal
created_at: 2026-07-06T20:40:23Z
updated_at: 2026-07-06T20:40:27Z
parent: mingo-o5t1
blocked_by:
    - mingo-8gau
---

Follow-up to mingo-8gau (trustless fast-sync verifier). The baseline verifier pins attestor identities by ed25519 PUBLIC KEY in [trust].attestors, because on-chain /sys/names state is untrusted during fast-sync. This bean adds the alternative: attestors identified by EMAIL, verified trustlessly via the existing DNSSEC-rooted browserid/persona machinery.

## Why this is possible without new pinned keys
Email identities root in the DNSSEC chain (a public trust anchor), not a per-IdP pinned key. The daemon already has the machinery to verify DNSSEC-rooted email attribution (see [[dnssec-self-authorizing-writes]] and the browserid/persona attribution path in validate.rs). So an email attestor can be authenticated trustlessly given only the DNSSEC root already in config — no per-attestor or per-IdP key pinning.

## Scope
- Accept `[trust].attestors` entries of the form `email:alice@example.com` (alongside `ed25519:<hex>`).
- During the P3 promotion hook, for an attestation message, verify the signer's email attribution chain terminates at the claimed email rooted in DNSSEC (fully, offline/independently — not via untrusted on-chain names), then match the resolved email against the pinned email attestor.
- Tests: valid email-rooted attestor promotes; broken/forged attribution chain does not; fallback-IdP path.

## Blocked by
mingo-8gau (needs the provisional-anchor + promotion-hook framework first).
