---
# mingo-02ta
title: Enable a live checkpoint attestor (T2-attest end-to-end in prod)
status: completed
type: task
priority: normal
created_at: 2026-07-04T20:59:04Z
updated_at: 2026-07-09T15:52:01Z
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

## Bug found + fixed during go-live (2026-07-09)

The daemon came up with [attest] on and IS posting checkpoint-attestation.v1, BUT every attestation WRITE was policy-denied on sync: 'Policy denied Create on /u/attestor2/attestations/checkpoints/ … No matching grant'.

Root cause: the deployed daemon was pinned to SBO_REV=5855e992, which PREDATES the attestation-owner fix (sbo 06d35da). Without it, build_attestation_wire sets owner:None → $owner unbound → the root-policy grant {can:*, on:/u/$owner/**, to:owner} can't match. (The identity itself is fine — /sys/names/attestor2 resolves key-rooted to the attest key; l2 ownership would authorize once $owner is bound.)

Fix: bumped deploy/sbo-daemon/Dockerfile SBO_REV → 1f45b9a (fix/attestor-owner-and-evidence HEAD: owner fix 06d35da + checkpoint-height fix ab37d55 + credential-based provision-agent). Pushed → daemon rebuilding. Verifying attestations apply after redeploy.

## LIVE (2026-07-09) ✓

After the SBO_REV bump (daemon rebuilt at 1f45b9a with the owner fix), attestation writes flip to sig:✓ state:✓ applied. Confirmed on-chain: checkpoint-attestation.v1 objects at /u/attestor2/attestations/checkpoints/block-* (creator attestor2@mingo.place, owner_ref attestor2), flowing continuously as the daemon reproduces each checkpoint.

The live checkpoint attestor is DONE. Remaining (minor, separate): verify a threshold-2 fast-sync client {sys-checkpointer, attestor2} counts two distinct backers end-to-end.

Note: the daemon now runs feature-branch commit 1f45b9a; folding fix/attestor-owner-and-evidence into main + realigning SBO_REV is the follow-up (bean n022).
