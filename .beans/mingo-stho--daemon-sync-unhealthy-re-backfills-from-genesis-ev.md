---
# mingo-stho
title: 'Daemon sync unhealthy: re-backfills from genesis every restart AND stalls before chain tip'
status: todo
type: bug
priority: high
created_at: 2026-06-30T22:05:51Z
updated_at: 2026-07-01T12:51:27Z
---

Found 2026-06-30/07-01 while deploying the dnssec fix. Two related sbo-daemon sync problems on da.sandmill.org (app 506):

1. RE-BACKFILL EVERY RESTART (~14 min downtime/deploy). On restart the daemon reports state missing at /data/.sbo/repos/avail_turing_506/state (NO first_block suffix) while the actual state dir is /data/.sbo/repos/avail_turing_506_3545910 (WITH suffix). A repo-dir naming inconsistency in the sbo sync/state code (suffixed vs unsuffixed) makes it think state is absent and re-seed head=3545906 → full genesis→tip replay on every boot. Contradicts mingo-vus5's premise that state persists across deploys.

2. SYNC STALLS BEFORE TIP / DOESN'T TAIL. After a restart the backfill stopped at block 3548489 and the daemon processed no further blocks for >1h (only its own TurboDA submissions logged). New writes (e.g. the re-applied /sys/policies/root dnssec policy) therefore never confirm — state-root frozen. The daemon is not tailing new finalized Avail blocks after catching up (or the finalized-head fetch isn't advancing it).

Impact: gates ALL on-chain liveness (any new write fails to confirm), and specifically blocks activation of the dnssec self-auth feature ([[mingo-c9ci]]/[[mingo-3sle]]) since its policy update can't confirm. No user impact today (service idle) but must fix before the chain is usable.

## Tasks
- [x] Fix the repo-dir path inconsistency (avail_turing_506 vs avail_turing_506_3545910) so state persists across restarts (no spurious re-backfill). — sbo 420d192 (branch fix/stho-stable-repo-identity)
- [x] Ensure the sync loop tails new finalized blocks after catching up (investigate why it stalled at 3548489). — sbo 5d5b4fa (stalled-LC → RPC-only fallback)
- [ ] Relates to mingo-vus5 (faster cold-start) — but this is correctness, not just speed.
- [ ] Operational: daemon dokku app has zero-downtime ON + single-writer RocksDB → deploys need manual ps:stop first (new container can't open the locked DB). Consider disabling zero-downtime checks for sbo-daemon or scripting stop-first.

## Root-cause investigation (2026-07-01)

All refs in `~/src/sbo/crates/sbo-daemon/` unless noted.

### Problem 1 — re-backfill every restart (path-naming inconsistency)
State-dir path is derived from `repo.uri.to_string()`, which INCLUDES the `@firstBlock` anchor. `sanitize_uri_for_path` (lib.rs:61-90) turns `@` into `_`, so `sbo+raw://avail:turing:506@3545910/` → dir `avail_turing_506_3545910`; the same URI WITHOUT the anchor → `avail_turing_506`. The two never point at the same RocksDB dir.
- Path build: `sanitize_uri_for_path` lib.rs:61-90 → `repo_dir_for_uri` lib.rs:94-97 → `state_db_path_for_uri` lib.rs:101-103.
- Anchor injection: `SboRawUri::render` (sbo-core/src/uri.rs:344-359) appends `@<first_block>` when `first_block` is Some; Display/to_string goes through it (uri.rs:362-374).
- Writer (suffixed): `SyncEngine::get_state_db` sync.rs:441-450, called with `r.uri.to_string()` sync.rs:491,497.
- Reader (unsuffixed) — prime suspect: `RepoManager::update_uri` repo.rs:305-322 replaces `repo.uri` with the DNS-resolved URI (no `@firstBlock`) AND resets `head=0` (line 313). After a DNS relink the dir name flips to unsuffixed → old RocksDB invisible → genesis replay. (head=3545906 vs anchor 3545910 consistent with re-seed at from_block-1; seeding main.rs:965-998, repo.rs:47-49.)
- NB: the exact 'state missing at .../avail_turing_506/state' log line is emitted mingo-side, not in sbo; but the split it observes is produced by this anchor-vs-no-anchor to_string() behavior.
- **Fix:** make state-dir name independent of the optional/mutable `@firstBlock` — key off stable identity (`SboRawUri::authority()` uri.rs:318, or repo `compute_id` hash repo.rs:86-91) or strip the anchor before sanitizing in `state_db_path_for_uri`. Also make `update_uri` preserve `first_block` and not blindly reset head=0.

### Problem 2 — stalls before tip / doesn't tail
The ACTIVE sync loop is the inline one in main.rs:724-921 (NOT `SyncEngine::run`). It caps the window at the light-client DAS availability window, not the finalized head:
- main.rs:802 `start = (*head+1).max(status.available_first)`
- main.rs:803 `end = status.available_last.min(status.latest_block)`
`available_last` = LC /v2/status `blocks.available.last` (lc.rs:85). If the LC's availability window freezes (LC behind/stopped verifying — common on Turing) at 3548489, `end` is pinned there forever while `latest_block` climbs → empty range (main.rs:810-812), loop spins every 2s (main.rs:920) but ceiling never moves. Only own TurboDA submissions keep logging — matches symptom.
- `SyncEngine::run` (sync.rs:1198-1229) + `LcManager::subscribe_blocks` (lc.rs:106-131) DO tail on finalized head (`blocks.latest`) with no availability ceiling — but that path is DEAD CODE, never called by the active loop.
- RPC-only fallback (main.rs:749-758) sets available_last = finalized head, so tailing works there → confirms stall happened while LC was up but its window stopped advancing.
- **Fix:** don't gate the upper bound on `available_last`. Advance to `status.latest_block` (or `rpc.get_finalized_head()` rpc.rs:454) and use availability only as a per-block readiness gate (skip/wait a specific not-yet-DAS-available block), not the loop ceiling. Alt: retire inline loop in favor of `SyncEngine::run`. Add a warning when available_last lags latest_block by a large margin (stalled-LC visibility).

Both fixes are independent and can land separately.

## Problem 1 fix (2026-07-01) — sbo commit 420d192

Root cause: repo identity (state-dir name, add-dedup, DNS-relink) was derived from the full rendered URI, which includes the optional/mutable `@firstBlock` anchor. So `...506@3545910/` and the anchorless form mapped to different RocksDB dirs; a relink dropping the anchor or an idempotent re-add stranded synced state → genesis re-backfill every restart. (`head` is read from the repo index, not the state DB, so a reset head or a fresh dir both force replay.)

Fix (branch `fix/stho-stable-repo-identity` in ~/src/sbo):
- `SboRawUri::to_identity_string()` — chain+app+path, no anchor, no query (uri.rs).
- `repo_dir_for_uri()` derives the state-dir name from the identity form (lib.rs).
- RepoAdd dedup (main.rs:955) and `update_uri` (repo.rs) compare on identity; relink keeps `head` unless the chain/path actually changed, and preserves `first_block` if the resolved URI dropped it.
- Regression test `identity_string_ignores_anchor_and_query` (uri.rs). Full sbo-core + sbo-daemon suites green.

DEPLOY NOTE: state-dir name changes from `avail_turing_506_3545910` to `avail_turing_506`, so the first boot after this lands does ONE final backfill onto the new stable path, then persists forever. Not yet pushed to github.com/vthunder/sbo or pinned in mingo (Cargo.toml sbo-core rev + deploy/sbo-daemon/Dockerfile SBO_REV). Problem 2 (LC availability-window ceiling / tailing stall) is still open.

## Problem 2 fix (2026-07-01) — sbo commit 5d5b4fa

Correction to the earlier investigation's proposed fix: `is_block_available(n)` is DEFINED as `n >= available_first && n <= available_last` (lc.rs:92) — so a 'per-block DAS gate' is IDENTICAL to the current `available_last` ceiling. Advancing the ceiling to finalized head while gating per-block would re-stall on a frozen window, just louder. It's not a daemon ceiling bug; the LC stopped sampling (available_last froze while finality climbed).

Real fix: detect the LC availability window lagging finalized head by more than `LC_STALL_LAG_BLOCKS` (30, ~10 min at 20s blocks) and fall back to RPC-only tailing — the SAME full-node-trust path already used when the LC is unreachable (main.rs:744-767). This restores liveness (new writes confirm) and logs the stall for operators. Safe: identical trust model to the existing LC-down fallback; `latest_block` is finalized, so we never process beyond finality.

Remaining tasks on this bean (mingo-vus5 relation; dokku zero-downtime/single-writer RocksDB stop-first) are operational, not addressed here.

## Deployed 2026-07-01 (mingo c6ef4de, sbo 5d5b4fa)

- sbo main FF-merged to 5d5b4fa, pushed; mingo Cargo.toml/Cargo.lock/Dockerfile SBO_REV bumped; mingo-idp release build validated.
- Disabled dokku zero-downtime checks on sbo-daemon (`checks:disable`, list=_all_) so single-writer RocksDB deploys stop-then-start without manual ps:stop — addresses this bean's operational task 4. (This deploy: manually ps:stop'd first, then pushed.)
- Deploy required pushing to the app's `main` branch (Makefile's `main:master` only updates the ref; `main:main` triggers the build). Build ~30 min (sbo rev bump → full sbo-daemon + rocksdb recompile).
- VERIFIED in prod: new code created the UNSUFFIXED `/data/.sbo/repos/avail_turing_506` state dir (12:49) — matches the entrypoint's STATE_DIR self-heal check, so future restarts skip the re-backfill. Genesis verified at 3545910; head climbing (one final backfill from genesis in progress, RPC-only). Policy enforcement ACTIVE (observed `Policy denied ... No matching grant`), i.e. not genesis mode.
- Root cause (mingo side): entrypoint.sh self-heal checks unsuffixed `avail_turing_506/state`, but old daemon wrote suffixed `avail_turing_506_3545910` (uri.to_string includes @firstBlock) → check never passed → repos.json deleted every boot → reseed head=3545906 → full backfill. Fix aligns the daemon's write path with the entrypoint's expected path.

Optional follow-up: remove the now-stale `avail_turing_506_3545910` dir to reclaim disk. Remaining bean task (mingo-vus5 cold-start relation) untouched.
