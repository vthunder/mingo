# Deployment Handoff — `/u/` Layout + Sovereignty (fresh genesis)

Start a fresh session with this note. Everything below is committed/pushed; nothing
is merged to `main` and **production (da.sandmill.org / app 506) is untouched**.

## What this is

A full SBO identity-model upgrade, ready to deploy as a **fresh genesis** on a new
sys key. mingo is the proving ground.

- **Why fresh genesis:** the original sys signing key was lost (wiped with `~/.sbo`),
  so the existing app-506 chain can't be re-governed. Zero real users → re-genesis
  with a new (backed-up!) sys key, shipping the new layout from the start.

## What's built (branches pushed, tests green, NOT merged)

- **sbo** `feat/identity-sovereignty-and-policy-vars` — protocol Phases 1–4, 6:
  - Four-variable policy model (`$owner`/`$user`/`$email`/`$name`), `$owner`
    de-circularized (declared `Owner`, not path segment), fail-closed.
  - `Creator` validated against signer (trie-spoofing gap closed).
  - Sovereignty resolution: a primary-domain email resolves *through*
    `/sys/names/<local>` (key record **wins over browserid**); canonical identity
    stays the email across the browserid→key upgrade.
  - Anti-hijack name claims (claiming `/sys/names/<x>` requires controlling
    `<x>@domain`).
  - Specs updated (Policy, Authorization, Identity); design doc
    `docs/plans/2026-06-27-identity-sovereignty-and-policy-variables.md`.
- **mingo** `feat/u-layout` — Phase 5: genesis root policy `/u/$owner/**`, app.js
  user data under `/u/<email>/…`, this runbook + handoff.

Also already **merged + live** from the prior session: the `uri` command suite and
real object transfer/move/delete + admin authority (sbo `main`). The deploy will
re-pin to the new sbo `main` which includes both.

## What to do

Follow **`docs/plans/2026-06-28-u-layout-migration-runbook.md`** end to end. Summary:

1. Merge both branches to `main`, push; bump mingo's sbo pin (`Cargo.toml` +
   `deploy/sbo-daemon/Dockerfile`) to the new sbo `main` SHA.
2. **Generate new sys + domain keys and BACK THEM UP** (`sbo key export …`). This is
   the step we cannot fumble again.
3. `mingo genesis mingo.place --key sys --domain-key mingo-domain --out genesis.wire`.
4. Note the current Avail turing finalized block `C`; `sbo debug da submit --file
   genesis.wire --turbo` (to app 506).
5. Re-seed the daemon (`deploy/sbo-daemon/entrypoint.sh` head=`C`), wipe `/data`,
   `git push dokku-daemon main`.
6. Verify the new chain (sys/domains/communities present, head advancing); record
   the genesis block `B`.
7. Deploy the web app; set DNS; save `genesis.wire` + `deploy/GENESIS.md`.

## DNS record to set (when ready)

```
_sbo.mingo.place.  IN  TXT  "v=sbo1 r=sbo+raw://avail:turing:506/ h=https://da.sandmill.org"
```

## Key facts / gotchas

- Reusing **app 506**; the existing TurboDA key works. Re-seeding the daemon at
  `head=C` makes old data below the new genesis invisible.
- The new daemon is backward-compatible, but we're wiping `/data` for a clean
  rebuild from the new genesis.
- dokku zero-downtime overlap on single-writer RocksDB → a transient `/v1` LOCK
  error right after deploy self-resolves (or `ps:stop`+`ps:start`).
- **Back up the sys + domain keys** before submitting genesis.
- The sovereignty browserid→key live path can't be unit-tested (DNSSEC); do the
  optional dry-run in step 10 to exercise it on the real chain.
