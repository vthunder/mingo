# Mingo genesis record — fresh genesis (Phase 7, 2026-06-28)

The live mingo.place SBO database, re-genesised on a new (backed-up) sys key after the
original was lost. Reuses **Avail turing app 506**; the old pre-genesis chain remains on
app 506 *below* block B and is invisible to the re-seeded daemon.

## Canonical identity

```
avail:turing:506:3545910:sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3
```
(`{chain}:{appId}:{firstBlock}:{genesisHash}` — see the SBO URI/Genesis specs.)

| Field | Value |
|-------|-------|
| Chain | `avail:turing` (Avail turing testnet) |
| App ID | `506` |
| **Genesis block (B)** | **3545910** |
| **Genesis hash** | `sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3` |
| Domain | `mingo.place` |
| Pinned broker | `browserid.me` (fallback attribution broker; primary `@mingo.place` via the domain object + `_browserid.mingo.place`) |
| sys pubkey | `ed25519:564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd` |
| domain pubkey | `ed25519:8ef0381e356a7f10e48ab8be637862586e8c8088f39b7c672a16cbb2f0503ad2` |
| Daemon seed head (C) | `3545906` (finalized tip at submission; sync starts at C+1 and picks up genesis at B) |
| TurboDA submission_id | `d3123661-6d43-4117-8e18-383ac1a0f7aa` |
| Genesis wire | `genesis.wire` (8832 bytes, committed alongside this file) |

## Key backups (DO NOT LOSE — the reason for this re-genesis)

- sys key   → `~/secure-backup/mingo-sys.key`
- domain key → `~/secure-backup/mingo-domain.key`

Both exported via `sbo key export … --output …` (mode 600). The sys pubkey is the admin
identity; the domain pubkey is the `mingo.place` root-of-trust.

## DNS record (`_sbo.mingo.place`)

```
_sbo.mingo.place.  IN  TXT  "v=sbo1 repo=sbo+raw://avail:turing:506@3545910/ genesis=sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3 node=https://da.sandmill.org"
```
`@3545910` is the genesis anchor (database-level, inherited by all paths); `genesis=` is the
identity hash; `node=` is the `/v1/*` data RPC. No `h=` — identity is on-chain. Requires the
sbo build at pin `cc207f8` (URI/DNS dialect).

## Reproduce / recover

```
sbo key import sys          ~/secure-backup/mingo-sys.key     # restore keys first
sbo key import mingo-domain ~/secure-backup/mingo-domain.key
mingo genesis --domain mingo.place --broker browserid.me --key sys --domain-key mingo-domain --out genesis.wire
# genesis.wire must hash to a3f28de0…; re-seed a daemon at head=3545906 to rebuild from B.
```
