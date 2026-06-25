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
# at head=3528751 and sync rebuilds state from Avail.
STATE_DIR=/data/.sbo/repos/avail_turing_506/state
if [ -f /data/repos.json ] && [ ! -d "$STATE_DIR" ]; then
  echo "state index missing at $STATE_DIR — resetting repo head to backfill from genesis"
  rm -f /data/repos.json
fi

# Seed the repo registration on first boot. head is set to just before the
# genesis block (3528752) so the RPC-only sync replays genesis + all app-506
# writes from Avail and rebuilds state. (available_first=0 in RPC-only mode, so
# sync starts at head+1.)
if [ ! -f /data/repos.json ]; then
  cat > /data/repos.json <<'JSON'
[{"id":"f86a7b415defc6cf","uri":{"chain":{"namespace":"avail","reference":"turing"},"app_id":506,"path_prefix":null},"display_uri":"sbo+raw://avail:turing:506/","path":"/data/repos/mingo","head":3528751,"created_at":1782336171}]
JSON
  echo "seeded /data/repos.json (head=3528751, will backfill from genesis)"
fi

exec sbo-daemon --config /app/config.toml start --foreground
