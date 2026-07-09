---
# mingo-02ta
title: Enable a live checkpoint attestor (T2-attest end-to-end in prod)
status: in-progress
type: task
priority: normal
created_at: 2026-07-04T20:59:04Z
updated_at: 2026-07-09T15:19:00Z
---

The attestation code (produce/serve/consume + unified client) is deployed to da.sandmill.org with [attest] OFF, so no checkpoint-attestation.v1 objects actually flow yet. The default client {sys-checkpointer, threshold 1} needs none, but a real web-of-trust demo needs at least one DISTINCT attestor identity.

## Decision needed
- (a) Co-located attestor on da.sandmill.org with its own key + identity — validates the produce→serve→consume pipeline live; NOT operationally independent (correlated failure).
- (b) A named attestor identity (needs a regenesis to add /sys/names/<attestor> + confirm /u/<attestor>/ owner grant resolves).
- (c) A genuinely independent full-replay attestor node (real infra; strongest).

## Blockers / notes
- Attestor MUST be a distinct identity from sys-checkpointer (a checkpoint already counts as sys-checkpointer's own claim; self-attestation dedupes to the same backer).
- Writing /u/<attestor>/attestations/checkpoints/ needs the attestor's resolved controller == the /u/ path segment (owner grant /u/\$owner/**). Verify this resolves for a key-form vs named identity before enabling.
- entrypoint.sh would write the attest key from an env var (SBO_ATTEST_KEY), like the checkpointer.
- Config stub already in deploy/sbo-daemon/config.toml ([attest], commented).

Parent: mingo-hqp2 (checkpoint attestations).

## Go-live in progress (2026-07-09, via agent-native provisioning)

Chose option (a) co-located attestor on da.sandmill.org with its own distinct identity — provisioned the agent-native way (ua8w / delegation chain), not the old hard path:

- Identity: **attestor2@mingo.place**, minted via browserid.me endorse → mingo.place /provision/mint (delegated from dan@mingo.place), key ed25519:a7cfa800… (DISTINCT from sys-checkpointer 937fc1e8…).
- On-chain: /sys/names/attestor2 claimed **key-rooted** at block **3592043** (owner_ref = the attestor2 key, creator attestor2@mingo.place). Verified via da /v1/object.
- Daemon: SBO_ATTEST_KEY set on the sbo-daemon dokku app; [attest] enabled (attestor="attestor2") in deploy/sbo-daemon/config.toml; entrypoint writes /data/attest-key.json. Daemon redeploying via GHA.

Remaining: confirm checkpoint-attestation.v1 objects flow under /u/attestor2/attestations/checkpoints/, and that a threshold-2 client {sys-checkpointer, attestor2} counts two distinct backers.
