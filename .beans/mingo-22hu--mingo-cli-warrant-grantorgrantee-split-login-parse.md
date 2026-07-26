---
# mingo-22hu
title: 'mingo CLI: warrant grantor/grantee split (login parse failure)'
status: completed
type: bug
priority: high
created_at: 2026-07-25T22:38:40Z
updated_at: 2026-07-26T19:12:13Z
---

`mingo login` failed because mingo-app was pinned to browserid-ng rev fa21c8e, whose `Warrant` still had a single `identifier` claim. The current broker (browserid.me) issues grantor/grantee warrants (browserid-ng-8v6c: a named agent is provisioned ON BEHALF of its approver, so grantor != grantee).

## Done (uncommitted)

- Bumped both mingo-app and mingo-idp to browserid-ng rev 4fce152 (current main). mingo-idp was on 5ffe436, which is already grantor/grantee — core/agent are unchanged between the two, so the idp is a comment-only change.
- mingo-app/src/device_login.rs: added `StoredGrant::grantor()`/`grantee()` and `StoredDeviceLogin::grantor_for(audience)`, parsing the stored warrant with `browserid_core::device::Warrant` rather than hand-rolling claims. `whoami` now shows 'as X' vs 'as X, on behalf of Y' per grant.
- mingo-app/src/login.rs: `post` takes the object owner from the warrant grantor (was `agent.email()`, which is now the GRANTEE), and the attribution read-back compares against the grantor. Login report flags on-behalf grants.
- Tests: as-you and on-behalf coverage in both modules (`on_behalf_envelope_attributes_to_the_grantor`, `on_behalf_grant_attributes_to_the_grantor`).

## Notes

- The daemon (sbo, SBO_REV ae1a998) pins browserid-core 2582555 — the commit that INTRODUCED the split; device.rs is unchanged since, so the daemon needs no bump.
- mingo-web/app.js was already grantor/grantee aware (receipt provenance).

## Summary of Changes

Shipped together with the agent-flows-v2 rollout (browserid-ng eywc/t1jp): revs bumped again 4fce152 → ac7b93e (both crates, both Cargo.tomls). The grantor/grantee parse fixes described above are unchanged; on top of them login.rs now passes the new request_provision args (message shown quoted on the broker's permission card; no grantor pin — the CLI leaves the on-behalf choice to the human's dropdown), surfaces grants_denied legibly when the human approves the identity but declines the permission, and the module doc describes the v2 two-step approval. poster.rs sends a message with its delegated request. Workspace tests green (69).
