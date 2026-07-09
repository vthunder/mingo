---
# mingo-hqp2
title: T2.5 checkpoint attestations (web-of-trust checkpoint trust)
status: completed
type: task
priority: normal
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-07T21:56:56Z
parent: mingo-o5t1
blocked_by:
    - mingo-lsjh
---

checkpoint-attestation.v1; /u/<attestor>/attestations/checkpoints/block-<h>; produce (replay-verify->post); surface in manifest; client threshold logic.


## Implementation plan — unified checkpoint attestations (2026-07-04)

### Design of record: the unified model
A client's trust is a local policy over signed `(block, state_root)` claims: `{ attestors: [id…], threshold: N }`. Both the sys `checkpoint.v1` and a peer `checkpoint-attestation.v1` are the SAME shape of evidence — a signed `(h,root)` claim. Today's `OnChainCheckpoint` ≡ `{attestors:[sys], threshold:1}`. Web-of-trust just changes the set/threshold. `sys` is not privileged in the protocol; it's a default attestor.

### Async / lagged timeline (settled)
Attestations are posted AFTER the checkpoint, at later heights (attestor watches `/sys/checkpoints/`, verifies a PAST block via its own recorded `get_state_root_at_block(h)`, then posts). So a fast-syncing client:
- anchors provisionally at snapshot@t0, tail-replays forward, and ACCRUES trusted `(h,root)` claims as it walks (tail-replay IS the walk);
- confirms once ≥threshold trusted claims agree on the t0 root.
Default client strategy: pick the freshest checkpoint whose threshold is ALREADY met (no waiting); fall to walk-and-wait only for tip-freshness beyond what's attested. Liveness fallback: walk forward up to N blocks / T secs; if unmet → older attested checkpoint, or degrade to sys-only, or report "trust not established" (never loop forever).

### Feasibility confirmed (sbo code)
- checkpoint.v1 built/signed/published: main.rs build_checkpoint_wire + checkpoint_if_due; state_root is bare hex.
- Per-block roots recorded during sync (sync.rs record_state_root) → get_state_root_at_block(h) enables independent verification of a past checkpoint.
- Manifest SyncPointsView.checkpoints populated in main.rs sync_points(); `attestations` array is specced but not yet in the struct.
- Bootstrap trust: bootstrap.rs RootTrust {OnChainCheckpoint, ServingNode}; picks checkpoint at snapshot height.
- Genesis policy already grants {to:"owner", can:["*"], on:"/u/$owner/**"} → attestor can write /u/<attestor>/attestations/checkpoints/ with NO genesis-policy change.

### Work items
1. **Spec** (sbo specs/SBO State Commitment Specification.md): add the unified framing (authority sig = degenerate threshold-1 case), the async walk-forward client loop, freshest-attested selection + liveness fallback. Reconcile the attestation object schema fields with the impl.
2. **sbo schema** (sbo-core): register/validate `checkpoint-attestation.v1` content schema.
3. **sbo producer** (sbo-daemon): `[attest]` config {enabled, key_file, attestor id, cadence}; `attest_if_due()` in the sync loop — for each on-chain checkpoint at h ≤ head not yet self-attested, compare get_state_root_at_block(h) to checkpoint.state_root; on match build+submit checkpoint-attestation.v1; on mismatch log divergence, never attest; skip if root(h) not recorded.
4. **sbo manifest**: add `attestations: Vec<AttestationView>` to SyncPointsView; populate from /u/*/attestations/checkpoints/ (bounded).
5. **sbo client** (bootstrap.rs): TrustPolicy {attestors, threshold}; RootTrust::Attested{n}; accept a root once ≥threshold trusted claims agree; keep sys as default attestor so existing behavior is threshold-1.
6. **Tests**: producer verify/attest+mismatch-skip; client threshold accept/reject; manifest surfacing.
7. **Deploy**: attestor identity/key setup; regenesis if needed; redeploy sbo-daemon to da.sandmill.org; bump mingo sbo pin.

## Built + committed (2026-07-04)
sbo f4c6e69 (pushed origin/main): unified attestation model — core schema validation, daemon [attest] producer, manifest attestations field, client TrustPolicy+evaluate_trust+bootstrap_with_policy, spec v0.4. Full sbo workspace green; new unit tests for evaluate_trust (threshold/agreement/untrusted) + schema. mingo sbo pin + SBO_REV bumped to f4c6e69; mingo-app builds + tests green.
Deploying daemon (attest OFF — backward-compatible, no genesis change): manifest gains attestations:[]; client default {sys-checkpointer,1} == legacy OnChainCheckpoint.
- [x] Deployed to da.sandmill.org (402d501); /v1/sync-points now serves attestations:[] (head 3571304, 8 checkpoints). Unified client + manifest field LIVE, backward-compatible.
- [x] FOLLOW-UP tracked as mingo-02ta: enable a live attestor (needs identity/regenesis decision).

## BLOCKER (2026-07-06): as-built is trust-the-serving-node, NOT trustless — do not close on plumbing test alone

Code trace (sbo bootstrap.rs):
- `verify_and_load` performs ONE check: `compute_snapshot_root(objects) == trusted_root` — i.e. the snapshot is internally consistent with a root the SERVING NODE supplied.
- `trusted_root` comes from `manifest.checkpoints[].state_root` (unsigned `CheckpointView`); `manifest.attestations[]` is unsigned `AttestationView`. Both are HTTP JSON from the serving node.
- Bootstrap NEVER verifies: the checkpoint's `sys-checkpointer` signature, the attestation's attestor signature, or that the attestor key is the registered controller of its `name@domain`.
- => `evaluate_trust`/`TrustPolicy{threshold}` counts backers over UNAUTHENTICATED hints. A malicious serving node can serve fake root R' + fake checkpoint(R') + fake attestations(R') + a snapshot hashing to R', and the client accepts `Attested{2}`.

Why the manifest can't be the verification (timeline):
- checkpoint for h=0 is published; sys attestation lands ~h+1; attestor observes /sys/checkpoints, reproduces root, posts its attestation at h+n.
- The SIGNED attestation object only exists on-chain at h+n. The only trustless source is the DA chain (Avail consensus is the trust anchor).
- Trustless verification therefore REQUIRES: bootstrap snapshot@h=0 provisionally -> walk forward replaying from Avail DA -> at h+n observe + verify the signed checkpoint & attestation objects (sigs + signer∈policy + agree on R) -> only THEN promote anchor to trusted. This walk-forward gate is UNIMPLEMENTED (bootstrap declares Attested{} before replaying any block).

Decision: split trustless verification into its own bean (blocks this one's test). hqp2 as-built = wiring only (produce/serve/consume + threshold arithmetic). Do NOT run the e2e test or close hqp2 until the trustless walk-forward verifier lands.

## e2e test status (2026-07-06): BLOCKED on producer bug
Ran a real local attestor (full independent replay) + drafted a threshold-2 local client against the prod chain. The test surfaced two real bugs BEFORE any attestation could land: (1) mingo-blpo — build_attestation_wire owner:None → attestations fail /u/$owner authorization (never caught: attest always deployed OFF); (2) mingo-8gau client trust-evidence was L2-gated → a fast-synced client would hang gated (FIXED: signature-rooted evidence). Also: fast-synced nodes can't attest (mingo-u1be) and hit a snapshot policy-completeness gap. e2e test resumes once mingo-blpo lands (needs identity-model decision: key-rooted vs email-rooted /u/ owner).

## E2E TEST PASSED (2026-07-07)
Full trustless fast-sync attestation loop validated end-to-end against the PRODUCTION chain:
- Attestor: independent full replay from genesis, key-rooted identity /sys/names/attestorsvc (owner_ref=attestor key), posts checkpoint-attestation.v1 that AUTHORIZE + land on-chain (own-writes applied 21+, rejected 0), indexed into /v1/sync-points attestations[].
- Client HAPPY PATH (threshold-2, pinned sys-checkpointer + attestor keys): bootstrap -> provisional anchor 3584343, reads GATED (503) -> walk-forward observes 2 distinct pinned-key claims agreeing on anchor root -> 'trust ESTABLISHED: 2 pinned attestors verified anchor block 3584343' -> gate lifted, reads 200, pending_trust.json deleted.
- Client NEGATIVE PATH (threshold-2, sys + BOGUS key): fast-forwards to checkpoint, replays forward (head 3584597), only 1/2 backers -> stays GATED, reads 503 'trust not yet established (1/2)'. Confirms it does NOT accept state until agreement.

Bugs found+fixed along the way: mingo-8gau (signature-rooted evidence), mingo-blpo (attestation owner), attest floor-lookup (get_state_root_at_or_before), mingo-w41d (email self-loop). Feature validated; DEPLOY pending (see follow-up).
