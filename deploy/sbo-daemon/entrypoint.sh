#!/bin/sh
set -e

mkdir -p /data/repos
# Remove a stale unix socket left by a non-graceful container exit, else the
# daemon refuses to start ("Socket already exists").
rm -f /data/daemon.sock

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
# NOTE: the uri object is the canonical SboRawUri serialization (chain/app_id/
# first_block/path/query); the id is sha256(to_string)[..8] of the bare repo URI.
if [ ! -f /data/repos.json ]; then
  cat > /data/repos.json <<'JSON'
[{"id":"f86a7b415defc6cf","uri":{"chain":{"namespace":"avail","reference":"turing"},"app_id":506,"first_block":null,"path":null,"query":{"genesis":null,"as_of":null,"content_hash":null,"content_type":null,"content_schema":null,"encoding":null,"size":null,"extra":{}}},"display_uri":"sbo+raw://avail:turing:506/","path":"/data/repos/mingo","head":3545906,"created_at":1782336171}]
JSON
  echo "seeded /data/repos.json (head=3545906, will backfill from new genesis)"
fi

exec sbo-daemon --config /app/config.toml start --foreground
