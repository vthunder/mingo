# Mingo genesis record — regenesis v3 (2026-07-16)

**History:** v1 2026-06-28 @3545910 (`a3f28de0…`, after the original sys key was lost) → v2 @3567386 (`7c429116…`, added the /sys/checkpoints checkpointer grant + sys-checkpointer name; table below was not updated at the time) → v3 @3619219 (`3c614c5d…`, wipe of the rejected synthetic seed corpus, mingo-4rvr) → **v4 @3622378** (`3c614c5d…`, SAME genesis wire re-anchored under the SBO global-(path,id)-uniqueness keying — sbo-qv95; the trie-key change (creator dropped) shifts every computed state root, so the chain is re-established from a fresh anchor on the new daemon).

The live mingo.place SBO database, re-genesised on a new (backed-up) sys key after the
original was lost. Reuses **Avail turing app 506**; the old pre-genesis chain remains on
app 506 *below* block B and is invisible to the re-seeded daemon.

## Canonical identity

```
avail:turing:506:3622378:sha256:3c614c5d7d541024242662d8ec250a4ad4377a7c950999ec8829b0c18421f8f5
```
(`{chain}:{appId}:{firstBlock}:{genesisHash}` — see the SBO URI/Genesis specs.)

| Field | Value |
|-------|-------|
| Chain | `avail:turing` (Avail turing testnet) |
| App ID | `506` |
| **Genesis block (B)** | **3622378** |
| **Genesis hash** | `sha256:3c614c5d7d541024242662d8ec250a4ad4377a7c950999ec8829b0c18421f8f5` |
| Domain | `mingo.place` |
| Pinned broker | `browserid.me` (fallback attribution broker; primary `@mingo.place` via the domain object + `_browserid.mingo.place`) |
| sys pubkey | `ed25519:564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd` |
| domain pubkey | `ed25519:8ef0381e356a7f10e48ab8be637862586e8c8088f39b7c672a16cbb2f0503ad2` |
| Daemon seed head (C) | `3622377` (finalized tip at submission; sync starts at C+1 and picks up genesis at B) |
| TurboDA submission_id | `248c8ef0-26a4-498b-90ce-63246cd56f39` |
| Genesis wire | `genesis.wire` (10009 bytes, committed alongside this file) |

## Key backups (DO NOT LOSE — the reason for this re-genesis)

- sys key   → `~/secure-backup/mingo-sys.key`
- domain key → `~/secure-backup/mingo-domain.key`

Both exported via `sbo key export … --output …` (mode 600). The sys pubkey is the admin
identity; the domain pubkey is the `mingo.place` root-of-trust.

## DNS record (`_sbo.mingo.place`)

```
_sbo.mingo.place.  IN  TXT  "v=sbo1 repo=sbo+raw://avail:turing:506@3622378/ genesis=sha256:3c614c5d7d541024242662d8ec250a4ad4377a7c950999ec8829b0c18421f8f5 node=https://da.sandmill.org"
```
`@3545910` is the genesis anchor (database-level, inherited by all paths); `genesis=` is the
identity hash; `node=` is the `/v1/*` data RPC. No `h=` — identity is on-chain. Requires the
sbo build at pin `cc207f8` (URI/DNS dialect).

## Post-genesis: DNSSEC evidence (REQUIRED for @mingo.place writes)

The genesis establishes `/sys/trust/brokers` and `/sys/domains/mingo.place` but **not**
`/sys/dnssec/mingo.place`. Primary-domain (`@mingo.place`) writes carry an `Auth-Cert`
with no inline evidence, so the daemon resolves the DNSSEC proof from the conventional
on-chain `/sys/dnssec/<issuer>` object (`validate.rs::resolve_evidence`). Without it,
email-rooted writes fail L2 attribution ("email-rooted but signer carries no valid
attribution"). Established post-genesis on 2026-06-29 at block **3546123**:

```
sbo domain evidence mingo.place --key sys --out dnssec.wire   # captures RFC 9102 proof of _browserid.mingo.place
sbo debug da submit --file dnssec.wire --turbo                # → /sys/dnssec/mingo.place (dnssec.v1, sys-signed)
```

> **Operational caveat — expiry.** The DNSSEC proof carries RRSig validity windows
> (days–weeks). A write's attribution window is the intersection of the cert window and
> the proof window, so `/sys/dnssec/mingo.place` must be **re-captured and re-submitted
> periodically** (re-run the two commands) before the RRSigs expire, or `@mingo.place`
> writes will start failing again. Worth automating (cron). **Follow-up:** have
> `mingo_genesis` emit `/sys/dnssec/<domain>` (or the runbook include this step) so a
> fresh genesis is write-ready out of the box.

## Reproduce / recover

```
sbo key import sys          ~/secure-backup/mingo-sys.key     # restore keys first
sbo key import mingo-domain ~/secure-backup/mingo-domain.key
mingo genesis --domain mingo.place --broker browserid.me --key sys --domain-key mingo-domain --out genesis.wire
# genesis.wire must hash to a3f28de0…; re-seed a daemon at head=3545906 to rebuild from B.
```
