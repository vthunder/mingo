---
# mingo-ua8w
title: Use agent-native browserid for the SBO attestor + service agents (followup)
status: in-progress
type: task
priority: high
created_at: 2026-07-08T00:04:32Z
updated_at: 2026-07-09T07:48:44Z
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

- [x] Phase 1: mingo-idp implements spec §4 — api_keys + agent_identities tables (one namespace with human handles, sys/sys-* reserved for agents too), /agent/* routes with the spec status contract, session+CSRF-gated /agent_keys minting, quota (MINGO_AGENT_PROVISIONING / MINGO_AGENT_QUOTA); /admin/provision marked deprecated as the agent path
- [x] Phase 1: conformance test — browserid-agent SDK e2e against mingo-idp (5 tests: full flow incl. persist/revoke, name rules + cross-namespace collisions, quota + auth rejections + visibility rule, disabled/CSRF gates, rotated-keypair re-mint verifying against the IdP key)
- [x] Phase 2: `sbo id provision-agent <name> [uri]` one-shot (sbo repo, branch fix/attestor-owner-and-evidence b68fefd): REST-mints the cert for the KEYRING key (one custody system — deviation from the plan's SDK-generated-key idea, deliberately), captures DNSSEC evidence, claims key-rooted, idempotent; smoke-tested end-to-end against a local agent-enabled mingo-idp
- [x] Phase 2 (revised): entrypoint writes /data/attest-key.json from SBO_ATTEST_KEY (mirrors checkpointer); boot-time provisioning would be circular (the claim submits via the daemon), so the one-time provision-agent claim is an operator runbook step — documented in deploy/sbo-daemon/config.toml
- [ ] Phase 3: go live co-located on da.sandmill.org (mingo-02ta option a), verify attestation flow + fast-sync backer counting
- [ ] Phase 4 (split to separate beans when reached): foreign-domain identities on-chain, n4gw trust-policy identities, on-chain parent attribution, retire the handoff note
