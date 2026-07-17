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
# (B=3623864 — the 2026-07-17 regenesis onto the policy-delegation model: govern-
# aware root policy + per-community moderator-delete and reserved sys takedown
# grants; sbo P1 4b28d8e, beans mingo-qjkf / sbo-orvt).
# The marker makes this idempotent across later restarts; it also wins any race with
# the retiring old container (which may rewrite /data during the deploy overlap). To
# re-run a reset for a future regenesis, bump the marker name to the new block.
RESET_MARKER=/data/.reset-genesis-3623864
if [ ! -f "$RESET_MARKER" ]; then
  echo "fresh-genesis reset: wiping /data state to rebuild from B=3623864"
  rm -rf /data/.sbo /data/repos /data/repos.json
  mkdir -p /data/repos
  touch "$RESET_MARKER"
fi

# Self-heal a head/state mismatch: the RocksDB state index lives under
# $HOME/.sbo (now /data/.sbo, persistent). If it's missing but a repo head was
# carried over in repos.json, the head sits past genesis while state is empty —
# reads return nothing forever. Drop repos.json so the seed below re-registers
# at head=3623863 and sync rebuilds state from Avail.
STATE_DIR=/data/.sbo/repos/avail_turing_506/state
if [ -f /data/repos.json ] && [ ! -d "$STATE_DIR" ]; then
  echo "state index missing at $STATE_DIR — resetting repo head to backfill from genesis"
  rm -f /data/repos.json
fi

# Seed the repo registration on first boot. head is set to one below the genesis
# block (3623863), so RPC-only sync (starting at head+1=3623864=B) replays the new
# genesis + all later app-506 writes and rebuilds state from Avail. The old
# (pre-3623864) chain stays below this head and is invisible.
# The new genesis landed at B=3623864 (sys=ed25519:564aafe4…, domain=ed25519:8ef0381e…,
# sys-checkpointer=ed25519:937fc1e8…, broker browserid.me).
# uri.first_block + expected_genesis make the daemon verify the reconstructed genesis
# hash at block B (non-fatal; logs "Genesis verified" / "GENESIS VERIFICATION FAILED").
# NOTE: the uri object is the canonical SboRawUri serialization (chain/app_id/
# first_block/path/query); the id is sha256(to_string)[..8] of the bare repo URI
# (anchor-independent, so it stays f86a7b415defc6cf across regenesis).
if [ ! -f /data/repos.json ]; then
  cat > /data/repos.json <<'JSON'
[{"id":"f86a7b415defc6cf","uri":{"chain":{"namespace":"avail","reference":"turing"},"app_id":506,"first_block":3623864,"path":null,"query":{"genesis":null,"as_of":null,"content_hash":null,"content_type":null,"content_schema":null,"encoding":null,"size":null,"extra":{}}},"display_uri":"sbo+raw://avail:turing:506/","path":"/data/repos/mingo","head":3623863,"created_at":1782336171,"expected_genesis":"sha256:ca27c61143c18786fc9ffee4fee25b458e7881390601e2ab55e0d9df9dc585bc"}]
JSON
  echo "seeded /data/repos.json (head=3623863, will backfill from new genesis B=3623864)"
fi

exec sbo-daemon --config /app/config.toml start --foreground
