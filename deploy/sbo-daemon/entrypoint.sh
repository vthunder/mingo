#!/bin/sh
set -e

mkdir -p /data/repos
# Remove a stale unix socket left by a non-graceful container exit, else the
# daemon refuses to start ("Socket already exists").
rm -f /data/daemon.sock

# Write the checkpoint-authority secret key (KEEP SECRET) from the injected env
# var into the persistent mount, where config.toml's [checkpoint] key_file points.
# Kept out of the image/repo — set via `dokku config:set sbo-daemon SBO_CHECKPOINT_KEY=<hex>`.
if [ -n "${SBO_CHECKPOINT_KEY:-}" ]; then
  printf '{"secret_key":"%s"}' "$SBO_CHECKPOINT_KEY" > /data/checkpoint-key.json
  chmod 600 /data/checkpoint-key.json
fi

# Same pattern for the checkpoint ATTESTOR key ([attest] in config.toml, mingo-02ta).
# The attestor's identity is provisioned ONCE, out of band, with
#   SBO_AGENT_API_KEY=bidk_… sbo id provision-agent <name> <uri>
# (agent-native browserid, mingo-ua8w) using this same key — after that key-rooted
# claim, the daemon only needs the key to sign attestations; no browserid at runtime.
if [ -n "${SBO_ATTEST_KEY:-}" ]; then
  printf '{"secret_key":"%s"}' "$SBO_ATTEST_KEY" > /data/attest-key.json
  chmod 600 /data/attest-key.json
fi

# One-shot fresh-genesis reset. On the first boot of an image with a new genesis we
# wipe /data state unconditionally so the seed below rebuilds from the NEW genesis
# (B=3899192 — the 2026-09-18 regenesis. Same sys, domain and checkpointer keys as
# v5, so admin identity and the daemon's [checkpoint] key are unchanged. This
# reset also retires the second database that used to be seeded below.).
# The marker makes this idempotent across later restarts. It does NOT reliably win
# the race with the retiring old container: on 2026-09-18 the first v6 deploy failed
# dokku's container check AFTER wiping /data, and the old container — still running
# the previous image — re-seeded the retired second database into repos.json. The
# successful rerun then found the marker and repos.json present, skipped both steps,
# and inherited a repos.json registering a repo whose head was ~8k blocks back. The
# sync loop starts from the MINIMUM head across registered repos, so nothing new
# confirmed on either database until the marker was bumped again (`-r2`).
#
# To re-run a reset — for a regenesis, or to recover from that race — bump the marker
# name. Check `cat /data/repos.json` after any deploy that was meant to change which
# repos are followed.
RESET_MARKER=/data/.reset-genesis-3899192-r2
if [ ! -f "$RESET_MARKER" ]; then
  echo "fresh-genesis reset: wiping /data state to rebuild from B=3899192"
  rm -rf /data/.sbo /data/repos /data/repos.json
  mkdir -p /data/repos
  touch "$RESET_MARKER"
fi

# Self-heal a head/state mismatch: the RocksDB state index lives under
# $HOME/.sbo (now /data/.sbo, persistent). If it's missing but a repo head was
# carried over in repos.json, the head sits past genesis while state is empty —
# reads return nothing forever. Drop repos.json so the seed below re-registers
# at head=3899191 and sync rebuilds state from Avail.
STATE_DIR=/data/.sbo/repos/avail_turing_506/state
if [ -f /data/repos.json ] && [ ! -d "$STATE_DIR" ]; then
  echo "state index missing at $STATE_DIR — resetting repo head to backfill from genesis"
  rm -f /data/repos.json
fi

# Seed the repo registration on first boot. head is set to one below the genesis
# block (3899191), so RPC-only sync (starting at head+1=3899192=B) replays the new
# genesis + all later app-506 writes and rebuilds state from Avail. The old
# (pre-3899192) chain stays below this head and is invisible.
# The new genesis landed at B=3899192 (sys=ed25519:564aafe4…, domain=ed25519:8ef0381e…,
# sys-checkpointer=ed25519:937fc1e8…, broker browserid.me).
# uri.first_block + expected_genesis make the daemon verify the reconstructed genesis
# hash at block B (non-fatal; logs "Genesis verified" / "GENESIS VERIFICATION FAILED").
# NOTE: the uri object is the canonical SboRawUri serialization (chain/app_id/
# first_block/path/query); the id is sha256(to_string)[..8] of the bare repo URI
# (anchor-independent, so it stays f86a7b415defc6cf across regenesis).
if [ ! -f /data/repos.json ]; then
  cat > /data/repos.json <<'JSON'
[{"id":"f86a7b415defc6cf","uri":{"chain":{"namespace":"avail","reference":"turing"},"app_id":506,"first_block":3899192,"path":null,"query":{"genesis":null,"as_of":null,"content_hash":null,"content_type":null,"content_schema":null,"encoding":null,"size":null,"extra":{}}},"display_uri":"sbo+raw://avail:turing:506/","path":"/data/repos/mingo","head":3899191,"created_at":1782336171,"expected_genesis":"sha256:fb64dc3b5f869041db99546f93cf777671a6f473856e77b6676146590902f652"}]
JSON
  echo "seeded /data/repos.json (head=3899191, will backfill from new genesis B=3899192)"
fi

# This node follows one database. A second one (Avail turing app 530) was
# seeded here until 2026-09-18 and has been retired; its state was removed from
# /data/repos.json and /data/repos/. If another database is added later, the
# repository that owns it keeps its own runbook — and note that ANY change in
# this directory redeploys and restarts the daemon, which re-processes from the
# minimum head across every repo it follows.

exec sbo-daemon --config /app/config.toml start --foreground
