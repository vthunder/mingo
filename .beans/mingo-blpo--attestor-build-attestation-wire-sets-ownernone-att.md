---
# mingo-blpo
title: attestor build_attestation_wire sets owner:None -> attestations fail /u/$owner authorization
status: completed
type: bug
priority: high
created_at: 2026-07-06T21:45:11Z
updated_at: 2026-07-07T21:56:56Z
parent: mingo-o5t1
blocking:
    - mingo-hqp2
---

Discovered 2026-07-06 via the mingo-hqp2 e2e test (first real attempt to run the attestor). The producer `build_attestation_wire` (sbo-daemon/src/main.rs:914) sets `owner: None` on the `checkpoint-attestation.v1` message, path `/u/<attestor>/attestations/checkpoints/`.

## Why it can never authorize
Authorization for `/u/<X>/**` relies on the genesis grant `{to:"owner", can:["*"], on:"/u/$owner/**"}`. For a CREATE, `validate_post` calls `check_policy(..., ActionType::Create, None, ...)` (validate.rs:650) and `$owner` = the message's DECLARED `Owner` header (validate.rs:1051; "literal, never path-derived"). With `owner: None`, `$owner` is UNDEFINED → the `/u/$owner/**` grant cannot substitute/match → write REJECTED (fails closed). Confirmed empirically: attestor ran, `attestations[]` stayed empty on chain.

(Note: the ATTRIBUTION gate at validate.rs:496 uses `effective_owner_ref` which falls back Owner→Creator→signing_key, so the signer-speaks-for-self check passes on the full key — but the POLICY $owner substitution does NOT use that fallback, so the path grant still fails. Two different owner derivations.)

Never caught because attest has only ever been deployed OFF (see mingo-hqp2 "attest OFF, backward-compatible").

## Fix (depends on identity-model decision — see below)
`build_attestation_wire` must set `owner: Some(<attestor-identity>)` where the identity resolves to a controller the attestor key speaks for. Two shapes:
- KEY-ROOTED: owner = "ed25519:<fullkey>" (or a key-rooted registered name), path `/u/ed25519:<fullkey>/…`. Works but is the "key as /u/ namespace" pattern flagged as undesirable.
- EMAIL/NAME-ROOTED (preferred): owner = "attestor@<domain>", requires the key be attributed to that email (browserid/DNSSEC IdP flow) or a key-rooted name. In the mingo PRIMARY domain a bare name canonicalizes to email-rooted and self-signed identity.v1 registration is REJECTED (needs attribution) — so an email-rooted attestor needs the IdP flow.

Also set `attestor` config to match, and the `attestor`/manifest `AttestationView` derivation should reflect the resolved controller.

## Blocks
mingo-hqp2 e2e test (can't produce a valid attestation until this is fixed).

## Status 2026-07-07: code fixed, blocked on identity provisioning
build_attestation_wire fixed (owner = attestor identity) on sbo branch fix/attestor-owner-and-evidence (06d35da), compiles. Also committed the sync.rs signature-rooted evidence fix (mingo-8gau) there. NOT deployed — needs a provisioned attestor identity to test.

Provisioning attestor@mingo.place requires the mingo IdP: email attribution is BrowserID+DNSSEC (no offline domain shortcut), and the IdP issues certs only to an authenticated ACCOUNT owning the handle (mingo-idp routes.rs require_session + account_id_for_handle). So need: register IdP account -> claim handle 'attestor' -> sbo id create --email (writes identity.email.v1 w/ attribution) -> once on-chain, attestor key authorizes via pinned-key resolution (no per-write browserid). Awaiting owner decision on provisioning path.

## Attestor identity provisioned 2026-07-07
attestor@mingo.place now on-chain (identity.email.v1, /sys/names/attestor). Attestor daemon reconfigured attestor="attestor@mingo.place", running full independent replay on the fixed binary (owner=Some(attestor)). Awaiting catch-up -> first attestation to confirm the /u/$owner authorization fix works end-to-end.
