---
# mingo-8gau
title: 'Trustless fast-sync verifier: verify signed checkpoint+attestation objects on-chain (not manifest)'
status: completed
type: task
priority: high
created_at: 2026-07-06T16:35:26Z
updated_at: 2026-07-07T21:56:56Z
parent: mingo-o5t1
blocking:
    - mingo-hqp2
---

The fast-sync client currently establishes trust from the serving node's UNSIGNED manifest (checkpoints[]/attestations[]) and only checks that the downloaded snapshot hashes to the node-supplied root (verify_and_load). It never verifies signatures on the checkpoint or attestation objects, so today's fast-sync is trust-the-serving-node, not trustless — a malicious node can serve a fabricated root + matching fake checkpoint/attestations + snapshot. This defeats the entire point of the "fast TRUSTLESS sync" epic and the web-of-trust threshold model (mingo-hqp2).

## What trustless verification requires
A signed checkpoint-attestation.v1 for height h only lands on-chain LATER (at h+n, after the attestor observes /sys/checkpoints and reproduces the root). The only trustless source of those signed objects is the DA chain itself (Avail consensus = trust anchor). So the client must:

1. Bootstrap the snapshot at h PROVISIONALLY: load objects, compute root R (as today), but mark the anchor UNTRUSTED.
2. Walk forward from h+1 replaying blocks directly from Avail DA (normal sync path already validates object sigs/authorization).
3. As it walks, collect the SIGNED checkpoint(h,R) and checkpoint-attestation.v1(h,R) objects; for each, verify: signature valid, signer resolves to a policy-trusted attestor identity (name@domain controller check / {key:...}), and it agrees on R at h.
4. PROMOTE the anchor from provisional to trusted only once >= threshold distinct trusted attestors have been observed+verified on-chain agreeing on R. Until then, state read from the snapshot must not be surfaced as trusted.

## Design decisions to settle
- Reaching tip WITHOUT observing >= threshold attestations for the anchor: (a) keep replaying/polling + wait, (b) error, (c) restart at an older checkpoint that already has its attestations on-chain below tip. (Older-checkpoint restart is cheapest to make trustless because its attestations are already in-chain by tip; the walk from older h to its h+n is bounded and past.)
- Whether the manifest stays as a DISCOVERY hint (pick candidate height/snapshot) with the on-chain walk as the ACTUAL verification — recommended: manifest = untrusted hint, chain = verification.
- Signer identity resolution offline: client must map attestor name@domain -> controlling key from on-chain /sys/names state (which it is rebuilding) to authenticate attestation signatures.

## Scope boundary
- This bean: the trustless client-side verifier (provisional anchor + walk-forward attestation verification + promotion gate + unmet-threshold strategy). Blocks the mingo-hqp2 e2e test.
- Related but separate: mingo-ikvs RootTrust::Proven (a zk proof discharges the claim outright) short-circuits this same gate; keep the trust-promotion API shaped so Proven and Attested plug into one decision point.

## Tasks
- [x] Make bootstrap anchor provisional (do not return Attested/OnChainCheckpoint from unsigned manifest data).
- [x] Verify signed checkpoint.v1 + checkpoint-attestation.v1 objects during walk-forward (KEY-PINNED: match raw wire signing_key vs config keys; NOT /sys/names).
- [x] Promotion gate: surface trusted state only at >= threshold verified distinct attestors.
- [x] Decide + implement unmet-threshold-at-tip strategy (keep-waiting-gated; timeout_blocks stops sync, reads stay refused; older-restart deferred).
- [x] Unit tests incl. adversarial (unpinned key, wrong-root, wrong-block, dedup, real message->claim). [ ] LIVE e2e promotion deferred to mingo-hqp2 (needs live attestor mingo-02ta).


## Implementation plan (2026-07-06) — key-pinned trustless verification

### Core correction (why this is NOT a signature-writing exercise, and why identities are key-pinned)
- Normal sync ALREADY verifies every object: process_block -> validate_message -> verify_message (ed25519 sig, sbo-core message/validate.rs:8) + l2_authorize (validate.rs:497). The daemon replays blocks from Avail DA directly (its own RPC), not from the serving node. So the walk-forward is already trustless w.r.t. the serving node.
- The gap is SEQUENCING: bootstrap declares trust from the UNSIGNED manifest and `start` serves snapshot state immediately, before the walk-forward reaches/validates the on-chain attestations.
- Identities MUST be pinned by PUBLIC KEY in config, never by name: name/owner resolution runs through on-chain /sys/names, which during fast-sync came from the untrusted snapshot (circular). The only non-circular anchor is the wire message's signing_key verified by verify_message (pure crypto, no on-chain dependency).
- Constraint that dictates the hook point: StoredObject (sbo-core state/objects.rs:9-43) persists NO signature/signing_key (only owner/creator/object_hash). So the signer key cannot be recovered from the StateDb after the fact — it must be captured while replaying the raw wire Message in process_block (which already holds signing_key+signature and already calls verify_message).

### P0 — [trust] config section (config.rs; TOML, loaded via Config::load config.rs:231)
- Add `#[serde(default)] pub trust: TrustConfig` to Config (config.rs:8). Fields: `threshold: usize`, `attestors: Vec<String>` (pinned "ed25519:<hex>" public keys). Default {[checkpointer key], 1} = backward-compatible with today's OnChainCheckpoint.
- TrustPolicy.attestors (bootstrap.rs:31) changes from name strings to pinned public keys. SYS_AUTHORITY stops being a name const ("sys-checkpointer") and becomes the pinned checkpointer key (genesis: sys-checkpointer=ed25519:937fc1e8...).
- Commands::Bootstrap (main.rs:1057) calls bootstrap_with_policy with the configured policy, not the hardcoded default.

### P1 — provisional anchor (manifest demoted to a hint)
- bootstrap_with_policy (bootstrap.rs:163): use manifest ONLY to select the snapshot height (freshest height whose evidence is already advertised below tip = proactive option (c), so the walk-forward is guaranteed to encounter it). Keep verify_and_load (snapshot->root R check, bootstrap.rs:96). Return `Provisional{block, root}`, NOT Attested/OnChainCheckpoint.
- Persist the pending anchor across the bootstrap->start CLI boundary (today BootstrapResult is dropped at main.rs:1063): write pending_trust.json {anchor_block, anchor_root, threshold, attestors} into the state dir. update_head as today.

### P2 — read gate (hard-refuse; DECISION LOCKED)
- On start, if pending_trust.json exists & unpromoted -> gated mode: light-client HTTP read endpoints (http.rs) return 503 trust-not-established. Gate is GLOBAL (all h+1.. state sits on the unverified anchor). A full-replay daemon (da.sandmill.org) never writes the file -> never gated.

### P3 — promotion hook inside process_block raw-message loop (sync.rs:736-815)
- Trust observer: for each message that passed verify_message whose path/id == anchor's /sys/checkpoints/block-<h> OR /u/*/attestations/checkpoints/block-<h>, record (signing_key, payload.state_root).
- Match signing_key DIRECTLY against config-pinned attestors; keep those agreeing on anchor_root; count distinct pinned keys; promote at >= threshold. No /sys/names, no owner resolution, no StateDb re-scan.
- On promote: delete pending_trust.json, lift gate, log RootTrust::Attested{n}.

### P4 — unmet-threshold-at-tip (keep-waiting-gated; DECISION LOCKED)
- Reaching chain tip still unpromoted -> stay gated, keep tailing, log "trust pending n/threshold". Config `trust_timeout_{blocks,secs}` -> error-exit on expiry. Auto-restart-at-older-anchor DEFERRED to a follow-up.

### P5 — unify with proof path (seam for mingo-ikvs)
- Shape promotion as `try_promote(anchor) -> Option<RootTrust>` that accepts EITHER >= threshold pinned-key attestations OR a valid RootTrust::Proven receipt at the anchor height. mingo-ikvs plugs into this single gate.

### Invariant to assert
- Anchor evidence (checkpoint + attestations) must land at heights > snapshot height h (else it's baked into the snapshot where signing_key is unrecoverable). Holds by construction (checkpoint_if_due submits at head -> lands h+k, attestations later). Assert + clear error if evidence is at/below h.

### P6 — tests
- unit: promotion counting — promote at threshold, not below, ignore key NOT in pinned set, ignore wrong-root.
- adversarial (must FAIL to trust): (a) serving node advertises fake root + fake manifest attestations but no matching pinned-key attestation exists on-chain -> stays gated; (b) attestation signed by a key not in the pinned set -> doesn't count; (c) below-threshold -> gated; (d) evidence-at/below-h invariant.
- then the plumbing happy-path (local attestor -> real threshold-2 promotion) becomes a MEANINGFUL trust test (was mingo-hqp2's deferred test).

### Deferred to follow-ups
- Email-rooted attestors: verifiable trustlessly TODAY via the existing DNSSEC-rooted browserid/persona machinery (roots in the DNSSEC chain, NOT a per-IdP pinned key — config needs only the DNSSEC root). Separate bean.
- Auto-restart-at-older-anchor on trust_timeout.


## Summary of Changes (2026-07-06) — implemented + deployed (dormant)

Implemented the key-pinned trustless fast-sync verifier. sbo commit 5855e99 (pushed origin/main); mingo pin bumped (Cargo.toml sbo-core + Dockerfile SBO_REV) at mingo 3cd0cd8, CI image-deploy triggered to da.sandmill.org.

### Code (all in crates/sbo-daemon)
- NEW trust.rs: TrustPolicy (Vec<PublicKey> + threshold), PendingAnchor (persisted pending_trust.json), TrustGate (observe/promote/gate), ObservedClaim, claim_from_message(). 8 unit tests (threshold, distinct-key dedup, unpinned/wrong-root/wrong-block rejection, real Message->claim + promotion).
- config.rs: [trust] section {attestors: [ed25519:hex], threshold, timeout_blocks}; default empty = non-enforcing = legacy behaviour.
- bootstrap.rs: bootstrap_provisional() — manifest demoted to a height-selection HINT; loads snapshot, verifies bytes->root only; trust deferred. Returns RootTrust::ServingNode (nothing trusted yet).
- main.rs: CLI bootstrap uses provisional path + persists PendingAnchor when [trust] enforcing; DaemonState carries SharedTrustGate loaded from pending_trust.json at start; tail loop feeds result.trust_evidence to the gate, promotes at threshold (lifts gate), and stops sync on timeout_blocks (reads stay refused); RepoApi::read_gate_reason() implemented.
- sync.rs: BlockProcessResult.trust_evidence — captures signing_key+root from raw validated checkpoint/attestation wire messages (StoredObject drops the signature, so capture happens in process_block).
- http.rs: check_read_gate() -> 503 on /v1/object|list|state-root|dnssec while gated. ApiError::unavailable().

### Security model realized
- Sync already verifies every object signature (verify_message) + L2 auth, replaying from Avail DA (not the serving node). The gap was sequencing: bootstrap trusted the UNSIGNED manifest and served snapshot state immediately.
- Fix: provisional anchor + read gate + walk-forward promotion that matches the raw wire signing_key against config-PINNED public keys (never names — on-chain /sys/names is untrusted pre-anchor, circular). Promote at >= threshold distinct pinned keys agreeing on the anchor root.
- try_promote seam left open for mingo-ikvs RootTrust::Proven.

### Verification status
- [x] cargo build/check --workspace green; clippy clean on sbo-daemon; 48 daemon unit tests + 8 new trust tests pass; mingo-app builds against new pin.
- [ ] End-to-end live fast-sync + attestor promotion NOT run (requires the deferred local-attestor harness). Dormant in prod (da.sandmill.org full-replays, no [trust] config) so the deploy is inert — same safety posture as the zkvm dormant deploys.
- [ ] The real e2e trust test is mingo-hqp2 (now unblocked design-wise; still needs a live attestor via mingo-02ta).

### Not done (deferred, tracked)
- Email-rooted (DNSSEC) attestors: mingo-n4gw.
- Auto-restart-at-older-anchor on timeout (only stop-and-stay-gated implemented).
