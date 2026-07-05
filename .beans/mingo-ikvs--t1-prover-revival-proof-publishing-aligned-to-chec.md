---
# mingo-ikvs
title: T1 prover revival + proof publishing (aligned to checkpoint height)
status: in-progress
type: task
priority: normal
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-04T19:51:06Z
parent: mingo-o5t1
blocked_by:
    - mingo-0vkj
---

Enable --features zkvm; fix recursive guest image id + block-hash binding; e2e tests; publish SBOP aligned to h; client verifies proof. Relates to mingo-5zru.


## Design: T1 zk-proof under the unified trust model (2026-07-04)

### Framing — a proof DISCHARGES the (h, root) claim (it is not another signer)
In the unified model a client's trust is a decision over signed (block, state_root) claims {attestors, threshold}. A ZK proof is categorically different from a checkpoint/attestation: it is not one more backer to COUNT toward a threshold — a valid recursive proof for (h, root) settles the claim OUTRIGHT (trustless), regardless of attestors. So:
- Add `RootTrust::Proven` and make a verified proof SHORT-CIRCUIT the threshold: if a proof commits new_state_root == snapshot's rebuilt root at h → accept, no signer trusted.
- Trust precedence at bootstrap: Proven > Attested(threshold) > OnChainCheckpoint > ServingNode.

### What a proof must commit to be a trustless anchor at h
Guest journal already commits `BlockProofOutput { prev_state_root, new_state_root, block_number, block_hash, data_root, version }` (sbo-zkvm/src/types.rs). A SINGLE proof at h only proves the transition INTO h given prev — NOT that root(h) follows from genesis. Trustlessness requires the RECURSIVE chain genesis→h collapsed into one succinct/groth16 proof (each guest verifies the previous via env::verify). So the deliverable anchor is: a recursive proof whose journal has block_number==h and new_state_root==checkpoint.state_root, verifying back to genesis.

### BLOCKER 1 — recursive guest image-id (self-recursion chicken-and-egg)
guest/src/main.rs:190-201 hardcodes a placeholder image id `[0;8]` for env::verify(prev) because the guest's own SBO_ZKVM_GUEST_ID is only known AFTER compiling it. Fix (standard risc0 pattern): pass the assumed guest image-id as guest INPUT, use it in env::verify(assumed_id, prev_journal), and COMMIT it to the journal (add `verified_with_image_id: [u32;8]`). The external verifier then asserts journal.verified_with_image_id == the real SBO_ZKVM_GUEST_ID. A forged chain either fails env::verify or commits a wrong id the verifier rejects → binds the whole chain to one guest without hardcoding a fixpoint. Genesis (block 0 / is_first_proof) commits a sentinel and requires no prev.

### BLOCKER 2 — block-hash binding to the real DA chain
generate_zkvm_receipt (daemon prover.rs) sets `parent_hash = *pre_state_root` (a placeholder) and block_hash = sha256(block_data). That does NOT tie the proof chain to the canonical Avail DA ordering. Fix: bind block_hash/parent_hash to the ACTUAL DA block hash (from header_data) so proof N's parent_hash must equal proof N-1's committed DA block_hash. Combined with the existing DA verification (verify_data_availability over header_data/row_data + raw_cells_hash), this makes the proof chain follow real history, not an arbitrary hash chain.

### Publishing aligned to checkpoint height + discovery
- Align prover batching so a proof's to_block coincides with checkpoint heights (batch to the same cadence, or force-emit at each checkpoint h). Proof commits new_state_root == checkpoint.state_root at h.
- SBOP is currently a raw DA submission (turbo.submit_proof; core/proof/sbop.rs) — NOT queryable by height. Surface proofs in the manifest: add `proofs: [{block, state_root, receipt_kind, ref}]` to SyncPointsView (mirrors the attestations array). Client discovers the proof for checkpoint h without walking.

### Client verification path (bootstrap)
Reuse sbo-zkvm/src/verifier.rs `verify_receipt(bytes) -> BlockProofOutput` (checks receipt.verify(SBO_ZKVM_GUEST_ID)). In bootstrap_with_policy: for the chosen snapshot at h, if a proof is advertised at h → fetch, verify_receipt, assert block_number==h && new_state_root==rebuilt root && verified_with_image_id==GUEST_ID (recursion valid) → RootTrust::Proven (trustless; skip attestor logic). Cheap for succinct/groth16 — no replay.

### Build / deploy strategy (risc0 toolchain)
zkvm is excluded from default-members; building -p sbo-daemon --features zkvm needs the risc0 toolchain (rzup) + guest ELF build. Split the concerns:
- VERIFY (light, cheap): clients + serving nodes need only verify_receipt + SBO_ZKVM_GUEST_ID. Keep this in a lighter feature so verification ships without the full prover toolchain if feasible (risc0 verify still needs the verifier deps but not the guest-compile toolchain).
- PROVE (heavy, opt-in): the prover runs on a capable node (CPU/GPU); [prover] config already gates it. Deploy the prover separately or on a beefier box.
- Dockerfile: add an rzup/risc0 install stage for the prover image; the guest ELF + image-id are build artifacts. Pin the risc0 version. (Compounds mingo-e1dd caching — cook the risc0 deps in a layer too.)

### Phasing
1. dev_mode pipeline end-to-end (RISC0_DEV_MODE): prove→publish SBOP@h→manifest proofs→client RootTrust::Proven path, no real proving. Validates wiring cheaply. (Note: DEV: receipts can't yield roots in light mode — see sync.rs; handle by carrying roots in dev SBOP metadata for the pipeline test.)
2. Real recursion: implement the image-id-commit fix + block-hash binding; get a genesis→h chain verifying.
3. Checkpoint alignment + manifest proofs + bootstrap RootTrust::Proven.
4. Deploy strategy (prover node + verify-in-daemon) + spec update (State Commitment: proof discharges the claim; proofs in manifest).

### Open decisions (need input)
- A. Prover placement: co-locate on da.sandmill.org (heavy, may starve the DA node) vs a separate prover node? (recommend separate.)
- B. Recursion granularity: prove EVERY block (batch_size=1, continuous recursion) vs prove only checkpoint-to-checkpoint spans? (affects prover load + how often a fresh trustless anchor exists.)
- C. Receipt kind for the published anchor: groth16 (~256B, cheap to verify/serve, slow to make) — recommend groth16 for the checkpoint-aligned anchor.
- D. Scope of THIS bean vs mingo-5zru (state-root/SBOQ proofs under rpc_only): where does the boundary sit?

## Decisions (2026-07-04)
- Prover placement: SEPARATE prover node (da.sandmill.org stays lean: verify + serve proofs only).
- Recursion cadence: checkpoint-to-checkpoint spans (one recursive anchor per checkpoint height), not every block.
- Receipt kind for the published anchor: groth16 (~256B; cheap verify/serve).
- Start: REAL recursion first — fix guest image-id-commit + DA block-hash binding (needs risc0 toolchain locally), then plumbing.


## Phase 1 implementation plan — guest recursion fix (precise diffs, ready to apply once risc0 toolchain installs)

### The fix: image-id-as-input-and-commit (avoids the two-stage build)
The circular dependency (guest needs its own image id to build) dissolves if the image id is DATA, not compiled-in:

1. `BlockProofInput` (sbo-zkvm/src/types.rs) — add `pub guest_image_id: [u32; 8]`. The host sets it to the real SBO_ZKVM_GUEST_ID (available in the methods crate).
2. `BlockProofOutput` (journal) — add `pub verified_with_image_id: [u32; 8]`.
3. guest main.rs verify_header_chain continuation — replace the placeholder:
   `let guest_id = Digest::from(input.guest_image_id); env::verify(guest_id, prev_journal)...`
4. guest main.rs main() — commit `verified_with_image_id: input.guest_image_id` in the output. Genesis/first_proof commit input.guest_image_id too (a proof that verified nothing prior still declares which id its chain uses).
5. verifier.rs verify_receipt — after receipt.verify(SBO_ZKVM_GUEST_ID) (proves THIS proof is our guest), ALSO assert journal.verified_with_image_id == SBO_ZKVM_GUEST_ID. This binds the RECURSIVE chain to the real guest: a forged chain that verified a malicious prev must commit that malicious id (guest commits exactly what it used for env::verify) → rejected here; and it cannot commit our id while verifying a different one.
6. host prover.rs (prove_block/prove_continuation/prove_genesis) — populate input.guest_image_id = SBO_ZKVM_GUEST_ID; the env::verify assumption resolves against the passed prev receipt + matching id.

### Why this is sound
- `receipt.verify(GUEST_ID)` proves the outermost proof ran our guest.
- Our guest, being our guest, used input.guest_image_id for env::verify and committed it.
- Verifier asserts committed id == GUEST_ID ⇒ the prev proof was verified against our guest id ⇒ by induction the whole chain is our guest. No hardcoded fixpoint, no two-stage build.

### DA block-hash binding (Blocker 2), same phase
- daemon prover.rs generate_zkvm_receipt: stop using `parent_hash = *pre_state_root` / `block_hash = sha256(block_data)`. Bind block_hash to the real Avail DA block hash (from header_data) and parent_hash to the prior DA block hash, so proof N's parent_hash == proof N-1's committed block_hash tracks the canonical DA chain (verify_data_availability already ties actions_data→cells→DA row).

### Test plan (needs risc0 toolchain; RISC0_DEV_MODE for fast iteration where possible)
- unit: genesis proof commits (0-root → new root, block 0, guest_image_id).
- unit: 2-block recursive chain verifies; tampering prev_journal or guest_image_id → verify_receipt rejects.
- unit: verifier rejects a journal whose verified_with_image_id != GUEST_ID.
- (real proving is slow; keep the chain short in tests, use succinct compression for the recursive step.)

STATUS: blocked on local risc0 toolchain install (rzup install running). Apply + build + test when ready.

## Phase 1a DONE — recursion fix committed (sbo 386a890), compile-verified
Image-id-as-input-and-commit implemented across types/guest/prover/verifier/lib + real-proof test. Guest ELF regenerates clean; non-prove build + verify path green.
VALIDATION GAP: real recursive-proof e2e NOT run — this macOS box can't link risc0's prover (Metal SDK needs full Xcode; RISC0_SKIP_BUILD_KERNELS drops the CPU kernels too → undefined _risc0_circuit_*_cpu_* at link). Run tests/recursion.rs on the Linux prover node/CI:
  cargo test -p sbo-zkvm --features prove --test recursion -- --ignored --nocapture
Dormant in prod (daemon not built --features zkvm), so committing to main is safe.
- [ ] Run recursion test on Linux to cryptographically confirm the binding.
- [ ] Phase 1b: DA block-hash binding (parent_hash → real Avail block hash).
- [ ] Phase 2: checkpoint-aligned SBOP publish + manifest proofs[] + client RootTrust::Proven.
