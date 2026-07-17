---
# mingo-2nra
title: Bump mingo sbo-core pin a92886c -> b6ac8ba to match the deployed daemon
status: todo
type: task
created_at: 2026-07-17T11:46:48Z
updated_at: 2026-07-17T11:46:48Z
---

mingo/Cargo.toml pins `sbo-core = { rev = "a92886c" }`, but the deployed daemon (deploy/sbo-daemon/Dockerfile SBO_REV) now runs b6ac8ba (P1 govern + P2-P4 pinning/constraints + the /u/ attested-lookup fix, sbo-4tka). So mingo-app/mingo-idp compile against a STALE sbo-core that predates `govern` and the policy.v2 pin/descendant_constraint fields.

## Symptom
`genesis::tests::root_policy_grants_admin_role_transfer_and_delete` fails: mingo genesis writes a `govern` grant into the policy JSON, but sbo-core@a92886c can't parse the `govern` ActionType variant on round-trip. (Confirmed pre-existing on a clean tree, not from set-root-admin.)

## Why it's currently low-impact
Genesis GENERATION works (writes JSON strings; the b6ac8ba daemon parses them — v5 regenesis validated live). set-root-admin mutates raw serde_json (not sbo-core types), so it round-trips `govern` fine. The drift only bites code that PARSES govern/P2-P4 policies via sbo-core types in mingo.

## Fix
Bump Cargo.toml sbo-core rev a92886c -> b6ac8ba (or current sbo main). Rebuild mingo-app + mingo-idp; fix any ripples from the sbo-core type changes (ActionType::Govern, Policy.pin/descendant_constraint, PolicyEntry CF format, snapshot format). Re-run tests. Keep the daemon SBO_REV and this pin in lockstep going forward (they're supposed to match — the Dockerfile comment even says so).
