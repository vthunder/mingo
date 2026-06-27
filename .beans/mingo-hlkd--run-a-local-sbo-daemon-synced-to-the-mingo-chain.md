---
# mingo-hlkd
title: Run a local sbo-daemon synced to the mingo chain
status: completed
type: task
priority: normal
created_at: 2026-06-26T18:31:24Z
updated_at: 2026-06-26T18:40:03Z
---

Run ~/src/sbo sbo-daemon locally, isolated HOME, syncing Avail turing app 506 (the mingo chain), serving /v1 on 127.0.0.1:7890, independent of the production daemon at da.sandmill.org. Point mingo-web at it via ?daemon=http://127.0.0.1:7890.

## Summary of Changes

Set up and launched a second, fully isolated sbo-daemon syncing the Mingo chain (Avail turing, app 506), independent of the production daemon at da.sandmill.org.

- Built `sbo-cli` + `sbo-daemon` from ~/src/sbo (release).
- Created an isolated instance under `~/src/sbo/.local-mingo/` with its own HOME so it gets a private RocksDB state dir (the state path is HOME-derived, `$HOME/.sbo/repos/...`, not configurable — this is what lets it coexist with the existing ~/.sbo daemon).
- `config.toml`: RPC-only sync from turing-rpc.avail.so, app_id 506.
- Seeded `repos.json` at head=3528751 (just before genesis block 3528752) so RPC-only sync replays genesis + all app-506 writes and rebuilds state.
- `run.sh` convenience launcher (clears stale socket, sets HOME, runs foreground).
- Verified: /v1 API on 127.0.0.1:7890 serves synced state (state-root, /v1/list communities), head advancing from genesis toward chain tip.

Caveat: the HTTP /v1 port is hardcoded to 7890, so only one daemon can serve it at a time. Point mingo-web at this instance with ?daemon=http://127.0.0.1:7890. Submitting writes needs SBO_TURBO_DA_API_KEY.
