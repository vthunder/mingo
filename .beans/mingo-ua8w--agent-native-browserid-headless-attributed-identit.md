---
# mingo-ua8w
title: Use agent-native browserid for the SBO attestor + service agents (followup)
status: completed
type: task
priority: high
created_at: 2026-07-08T00:04:32Z
updated_at: 2026-07-09T23:40:56Z
parent: mingo-sux8
---

Once agent-native browserid ships (browserid-ng bean
`browserid-ng-l8lw`: headless, API-key-gated, attributed identity issuance at
`agents.browserid.me`), wire mingo/SBO to use it — so the checkpoint attestor and
similar service agents mint a key-rooted identity and sign on-chain writes directly,
retiring the hard provisioning path (`mingo-hqp2` / `mingo-acmx`).

Deferred until browserid-ng ships; will likely need mingo-side adjustments.

## Anticipated work

- [ ] Provision the checkpoint attestor's identity via the new `agents.browserid.me`
      REST flow (own keypair → cert), replacing the local-IdP / admin-token hard path
- [ ] **Support non-`mingo.place` domain identities on-chain** — these agents will be
      `@agents.browserid.me`, not `@mingo.place`; `/sys/names` claim + resolver /
      controller logic must accept a foreign-domain browserid identity
- [ ] Let the attestor (and similar) sign writes with its cert-bound key
      (`Controller::Key`) — no per-write cert dance
- [ ] Optional: record parent attribution on-chain (mingo is an RP we control and can
      make delegation-aware — plain login to the world, attributable on the ledger)
- [ ] Retire `docs/notes/browserid-for-agents-handoff.md` (the worked hard-path)

## Guardrail

Honor `sbo-4arq` ("a bare key is not an identity") — it's the API-key + attribution +
quota upstream that makes these identities, not bare keys.

See `browserid-ng` bean `browserid-ng-l8lw` for the full design.

## Concrete plan (2026-07-09)

Upstream shipped: browserid-ng l8lw is complete (REST spec at browserid-ng/docs/specs/agent-provisioning-and-grant-api.md, `browserid-agent` + `browserid-rp` crates, broker deployed to browserid.me with AGENT_PROVISIONING=1).

Full plan: **docs/plans/2026-07-09-agent-native-attestor-plan.md**. Recommendation: mingo-idp implements the provisioning spec itself (attestor = `<name>@mingo.place`, existing on-chain machinery unchanged) rather than blocking on foreign-domain (@browserid.me) identity support, which moves to Phase 4 / its own bean.

- [x] Phase 1 (v2 delegation chain): mingo-idp is a target IdP — /provision/{mint,list,revoke} verify the U_cert~P_cert~R chain against our own key + a broker endorsement (discovered via browser well-known, cached). api_keys dropped; key mgmt is broker-only. Namespace/quota/reserved-names/revoke kept. Conformance e2e green (4 tests). browserid-core pinned to 480a4be.
- [x] Phase 1: conformance test — browserid-agent SDK e2e against mingo-idp (5 tests: full flow incl. persist/revoke, name rules + cross-namespace collisions, quota + auth rejections + visibility rule, disabled/CSRF gates, rotated-keypair re-mint verifying against the IdP key)
- [x] Phase 2 (v2): `sbo id provision-agent` consumes an agent credential file (SBO_AGENT_CREDENTIAL, made at browserid.me/agents): signs a mint request for the keyring key → broker /provision/endorse → IdP /provision/mint → key-rooted claim. Credential parse + wiring done; on-chain claim step unchanged.
- [x] Phase 2 (revised): entrypoint writes /data/attest-key.json from SBO_ATTEST_KEY (mirrors checkpointer); boot-time provisioning would be circular (the claim submits via the daemon), so the one-time provision-agent claim is an operator runbook step — documented in deploy/sbo-daemon/config.toml
- [x] Phase 3: go live co-located on da.sandmill.org (mingo-02ta option a), verify attestation flow + fast-sync backer counting
- [x] Phase 4 split into its own epic → **mingo-2rbx** (foreign-domain identities on-chain, n4gw trust-policy identities, on-chain parent attribution, retire the handoff note)

## v2 rework (delegation chain, 2026-07-09)

The v1 bearer bidk_ implementation is SUPERSEDED by browserid-ng's delegation-chain redesign (bean browserid-ng-tdxf, spec v0.2). mingo-idp becomes a target IdP that verifies dual-signed provisioning requests + a browser-endorsement from browserid.me; sbo provision-agent consumes a credential file. Key management is centralized at browserid.me (no per-IdP api_keys).

## External-email on-chain attribution — fix (2026-07-10)

A fallback-certified email (e.g. vthunder@gmail.com, cert issuer = broker) failed to post/join on-chain: its `/sys/dnssec/<broker>` proof write was routed through the broker signer, which requires an Owner and rightly refuses to sign an unowned write as the user.

Fix (mingo-web app.js, commit 6b9c331): a `/sys/dnssec` proof is self-authorizing — daemon policy grants create/update on `/sys/dnssec/**` to anyone, and the proof attests its own domain. So sign key-rooted writes LOCALLY with a throwaway ephemeral Ed25519 key (WebCrypto) instead of the broker signer; effective owner = that key, authorized by policy + proof. The email-rooted content write (the join/post) still uses the broker signer with the user's cert. Generalizes to any primary domain (no seeding). Deployed to mingo.place; awaiting retest of joining a group as vthunder@gmail.com.

## Phase 3 verified (2026-07-09)

Checkpoint attestor live end-to-end on da.sandmill.org:
- attestor2@mingo.place claimed key-rooted on-chain (/sys/names/attestor2, owner ed25519:a7cfa800…) — the claim is a ONE-TIME cert-authorized write; frequent attestations then ride the key (plain signature, no per-write cert/evidence, no runtime cert-refresh dependency).
- Producing checkpoint-attestation.v1 under /u/attestor2/attestations/checkpoints/, keeping up with sys-checkpointer within ~3 blocks (all 4 latest checkpoints attested).
- Manifest (/v1/sync-points) serves 62 checkpoints + 102 attestations as backers.
- **Backer counting proven** via real bootstrap_with_policy fast-sync (sbo-daemon examples/fastsync_backers.rs): threshold-2 {sys-checkpointer, attestor2} → RootTrust::Attested{backers:2}, 188 objects loaded at block 3593474; negative control (attestor2→unknown key) correctly rejected. Count is real, not rubber-stamped.

Remaining: Phase 4 (foreign-domain @browserid.me identities on-chain, n4gw trust-policy identities, on-chain parent attribution, retire handoff note) — separate track.

## Summary of Changes

Agent-native browserid wired into mingo/SBO and validated end-to-end. Delivered: mingo-idp as a target IdP implementing the v0.3 delegation-chain provisioning spec (dual-signed request + broker endorsement; api_keys dropped); `sbo id provision-agent` consuming an agent credential file; the checkpoint attestor (attestor2@mingo.place) minted agent-native, claimed key-rooted on-chain, and **Phase 3 verified live** (produce checkpoint-attestation.v1 → serve in manifest → fast-sync counts 2 distinct backers at threshold 2; negative control rejected). Also shipped along the way: external-email identities (post as your real email or a @mingo.place handle) with broker-certified on-chain attribution working (root-caused a stale browserid.me DNS _browserid key + a first-creator /sys/dnssec resolution flaw; DNS fixed, stopgap proof written).

Remaining work split off: Phase 4 federation (mingo-2rbx, draft — needs design). Related follow-ups: mingo-jyzt (multi-creator resolution spec), mingo-d0cd (external-email sovereignty upgrade).
