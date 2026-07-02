---
# mingo-ca71
title: roles.admin bare-name never matches sys@mingo.place under enforcement
status: completed
type: bug
priority: high
created_at: 2026-07-02T19:39:00Z
updated_at: 2026-07-02T21:38:38Z
---

The mingo genesis root policy sets `roles: {admin: ["sys"]}` (bare name). Policy actors for name-claimed identities canonicalize to `name@domain` (sbo validate.rs resolve_creator ~284), and role membership matches via a direct string compare (`name == actor.as_str()`, sbo evaluate.rs:315, reached through Identity::Role at :326). So member "sys" never equals the signer "sys@mingo.place" — the admin grant `{to:{role:admin},can:[post,transfer,delete],on:/**}` matches NOTHING under enforcement. sys-level moderation/transfer/delete is silently non-functional.

Discovered while activating on-chain checkpoints: the analogous `to:"checkpointer"` grant was policy-denied the same way (fixed by matching on pubkey instead). roles.admin was left as-is (out of scope) in the B=3562782 regenesis.

## Fix options
- Change roles.admin to the qualified form: `["sys@mingo.place"]` (or `[{key: ed25519:564aafe4…}]`, most robust). Requires a regenesis (root policy is genesis).
- Add genesis test asserting an admin (sys) write to a policy-protected path is Valid under enforcement, to prevent regression.

## Verify first
Empirically confirm sys admin is currently denied under enforcement (submit a sys-signed transfer/delete on the live chain, expect policy:✗) before regenesising, in case sys resolves differently than assumed.

## Empirically confirmed (2026-07-02)
Live daemon logs, B=3562782 genesis:
- `Indexed name claim: sys -> ed25519:564aafe4…` (the /sys/names/sys record DOES exist)
- `Post /sys/trust/brokers by sys@mingo.place → applied` — sys's policy actor canonicalizes to **sys@mingo.place**, NOT bare `sys`.

So the /sys/names/sys record is the *cause*: validate.rs:284 turns a name claim into `name@domain` (deliberate — 'a local name IS the identity name@domain'). The grant's literal compare `"sys" == "sys@mingo.place"` fails. (Note: the very first genesis write that *creates* /sys/names/sys logs actor `sys` because the claim isn't indexed yet; every write after is `sys@mingo.place`.) Confirmed real. Fix: roles.admin = ["sys@mingo.place"] (or {key: ed25519:564aafe4…}).

## RE-SCOPED to spec-compliant engine fix (option A, 2026-07-02)

Root cause is the policy ENGINE, not the genesis data. Per SBO Policy Specification.md ~line 175: a requester matches when its signer RESOLVES to the identity; a name and the email that controls it resolve to the same controller — 'a policy MAY grant to either.' So roles.admin:["sys"] is spec-VALID.

But identity_matches (sbo-core/src/policy/evaluate.rs:315) does literal name == actor.as_str(); the actor is canonicalized to email form (validate.rs resolve_creator:284) while the grant's ref is never resolved. So bare-name grants never match; email grants match only by string coincidence.

FIX (A): in identity_matches (Identity::Name + Role member paths), resolve BOTH the grant ref and the signer to a common controller (resolve name via /sys/names/<name> to its key, and/or canonicalize name<->name@domain via primary_domain) and compare controllers. Bare sys, sys@mingo.place, and {key:564aafe4} must all match the same signer. The checkpointer key-form grant stays correct. Lives in sbo (sbo-core), not mingo.

TESTS: identity_matches matches all three forms for one signer; a sys-signed write to a policy-protected path is Valid via the admin role under enforcement.

## Deployed 2026-07-02
Merged fix/policy-resolution-based-identity-matching to sbo main (01e3da5); bumped daemon SBO_REV → 01e3da5 (deploy 5bebca5). Live daemon healthy: genesis verified, checkpoints still publishing (block 3563142), no policy/panic regressions. Bare-name/email/key grants now resolve to a common controller per spec; roles.admin:["sys"] active under enforcement WITHOUT a regenesis (grant was already on-chain). sbo-core 164 tests + 8 new pass.
