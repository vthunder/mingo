---
# mingo-lsjh
title: 'T2.1 checkpoint publishing (daemon): dual-trigger, sign+submit checkpoint.v1'
status: completed
type: task
priority: high
created_at: 2026-07-02T16:25:37Z
updated_at: 2026-07-02T19:40:34Z
parent: mingo-o5t1
---

[checkpoint] config (authority, writes>=100/blocks>=1000). On trigger h: state_root(h) -> sign+submit checkpoint.v1 via turbo.submit_raw. Genesis policy grants /sys/checkpoints/**; exclude checkpoint objects from write count.

## Progress 2026-07-02 (sbo 7e1a7f9)
DONE: config [checkpoint] (enabled/publish/key_file/every_writes=100/every_blocks=1000/snapshots_dir); dual-trigger scheduling in the sync task (caught-up + writes/blocks since last), computes state root + object set, generates snapshot at the tip (keep newest 3).
REMAINING (on-chain publish path): build+sign+submit checkpoint.v1 via turbo.submit_raw. Gated behind publish=true + key_file — currently WARNs and skips (a deliberate deploy decision; needs the sys/authority signing key on the daemon, or a delegated checkpoint identity + genesis policy grant). Enabled locally (snapshots generated + served); on-chain checkpoint objects not yet published.

## LIVE + VERIFIED 2026-07-02 (sbo ce7d450, da.sandmill.org)
Local checkpoint scheduling + snapshot generation working in prod:
- Log: 'checkpoint @ block 3562408: snapshot 17 objects, 44543 -> 9449 bytes (gz)'.
- /v1/sync-points advertises snapshots [3562408, 3562400] (survived redeploy — persistent /data), genesis, head, latest_state_root (matches snapshot root).
- /v1/snapshot?block=latest streams gzip + X-Snapshot-* headers; decompresses to 17 objects.
- Fast test cadence every_blocks=20 / every_writes=5; env-tunable (SBO_CHECKPOINT_EVERY_*).
STILL REMAINING (this bean): on-chain checkpoint.v1 publishing (publish path, needs authority key).

## DONE 2026-07-02 — on-chain publish + genesis authority
- Daemon (sbo 7776903): [checkpoint].publish + key_file → build+sign+submit checkpoint.v1 (write-once /sys/checkpoints/block-<h>) via TurboDA at each checkpoint height; key loaded from {secret_key:hex}; gated/off by default.
- Genesis (mingo 57b606b): key-rooted `checkpointer` identity (/sys/names/) + grant CREATE-ONLY on /sys/checkpoints/** (per user: create, not update — write-once). `mingo genesis` CLI mints/takes a checkpoint key and writes checkpoint-key.json for the daemon. Brand-new chains get it automatically; daemon never needs the sys key. Tests: create-only grant + checkpointer identity + batch count 14.

ACTIVATION (deploy step, not done): on the LIVE chain, publishing needs a regenesis (to include the checkpointer grant) + deploy checkpoint-key.json + set publish=true + bump SBO_REV. A fresh chain is automatic. Until then bootstrap trust = ServingNode; once on, upgrades to OnChainCheckpoint.

## Activation live (2026-07-02)

On-chain checkpoint publishing is ACTIVE on the live chain.

- Regenesis carrying the /sys/checkpoints/** grant landed at Avail turing block **3562782** (genesis hash ff7567f3…, broker browserid.me, sys 564aafe4…, domain 8ef0381e…). Daemon reseeded (entrypoint reset marker .reset-genesis-3562782) and reports `Genesis verified`.
- Daemon (SBO_REV 7776903, config publish=true, key_file from SBO_CHECKPOINT_KEY env) signs checkpoint.v1 with the dedicated checkpointer key (create-only on /sys/checkpoints/**) and submits via TurboDA.
- **Bug found + fixed mid-activation:** the first regenesis (B=3562721) used a bare-name grant `to:"checkpointer"`; policy actors canonicalize to name@domain, so checkpoint writes were policy-denied ("No matching grant") and never indexed. Fixed by matching the authority by **public key** (Identity::Key) — regenesis B=3562782. Checkpoint writes now apply (`policy:✓ state:✓ applied`).
- Verified end-to-end: /v1/sync-points advertises checkpoints[block-3562786], and `sbo-daemon bootstrap --node https://da.sandmill.org` loads with **trust=OnChainCheckpoint** (upgraded from ServingNode).
- Follow-up: mingo-ca71 (roles.admin same bare-name defect, out of scope here).
