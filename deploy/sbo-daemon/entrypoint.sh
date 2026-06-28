#!/bin/sh
set -e

mkdir -p /data/repos
# Remove a stale unix socket left by a non-graceful container exit, else the
# daemon refuses to start ("Socket already exists").
rm -f /data/daemon.sock

# One-shot fresh-genesis reset (Phase 7). The pre-genesis container persisted an
# OLD-format repos.json (pre-SboRawUri `path_prefix`, head=3528751) and old-chain
# state under /data/.sbo — both incompatible with this build. On the first boot of
# this image we wipe /data state unconditionally so the seed below rebuilds from the
# NEW genesis (B=3545910). The marker makes this idempotent across later restarts;
# it also wins any race with the retiring old container (which may rewrite /data
# during the deploy overlap). To re-run a reset, bump the marker name.
RESET_MARKER=/data/.reset-genesis-3545910
if [ ! -f "$RESET_MARKER" ]; then
  echo "fresh-genesis reset: wiping /data state to rebuild from B=3545910"
  rm -rf /data/.sbo /data/repos /data/repos.json
  mkdir -p /data/repos
  touch "$RESET_MARKER"
fi

# Self-heal a head/state mismatch: the RocksDB state index lives under
# $HOME/.sbo (now /data/.sbo, persistent). If it's missing but a repo head was
# carried over in repos.json, the head sits past genesis while state is empty —
# reads return nothing forever. Drop repos.json so the seed below re-registers
# at head=3545906 and sync rebuilds state from Avail.
STATE_DIR=/data/.sbo/repos/avail_turing_506/state
if [ -f /data/repos.json ] && [ ! -d "$STATE_DIR" ]; then
  echo "state index missing at $STATE_DIR — resetting repo head to backfill from genesis"
  rm -f /data/repos.json
fi

# Seed the repo registration on first boot. head is set to the Avail turing
# finalized tip captured at fresh-genesis submission time (C=3545906); the new
# genesis lands at some block B>C, so RPC-only sync (starting at head+1) replays
# the *new* genesis + all later app-506 writes and rebuilds state from Avail. The
# old (pre-3545906) chain stays below this head and is invisible.
# The new genesis landed at B=3545910 (sys=ed25519:564aafe4…, domain=ed25519:8ef0381e…).
# uri.first_block + expected_genesis make the daemon verify the reconstructed genesis
# hash at block B (non-fatal; logs "Genesis verified" / "GENESIS VERIFICATION FAILED").
# NOTE: the uri object is the canonical SboRawUri serialization (chain/app_id/
# first_block/path/query); the id is sha256(to_string)[..8] of the bare repo URI.
if [ ! -f /data/repos.json ]; then
  cat > /data/repos.json <<'JSON'
[{"id":"f86a7b415defc6cf","uri":{"chain":{"namespace":"avail","reference":"turing"},"app_id":506,"first_block":3545910,"path":null,"query":{"genesis":null,"as_of":null,"content_hash":null,"content_type":null,"content_schema":null,"encoding":null,"size":null,"extra":{}}},"display_uri":"sbo+raw://avail:turing:506/","path":"/data/repos/mingo","head":3545906,"created_at":1782336171,"expected_genesis":"sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3"}]
JSON
  echo "seeded /data/repos.json (head=3545906, will backfill from new genesis)"
fi

exec sbo-daemon --config /app/config.toml start --foreground
