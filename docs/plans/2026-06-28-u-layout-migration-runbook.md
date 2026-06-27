# `/u/` Layout + Sovereignty — Production Migration Runbook (Phase 7)

**Status:** Ready to run; **not executed** (needs the sys signing key + live
verification — your call). Prepared overnight 2026-06-28.

Branches to ship:
- sbo `feat/identity-sovereignty-and-policy-vars` (Phases 1–4, 6: policy vars,
  Creator validation, sovereignty resolution, anti-hijack, lifecycle test).
- mingo `feat/u-layout` (Phase 5: genesis `/u/$owner/**`, app.js `/u/` paths).

Both are pushed, fully tested, and ready for PR/merge.

---

## Why a specific order

- The **new daemon is backward-compatible with the old on-chain policy**: with the
  de-circularized `$owner`, the existing `/$owner/**` grant still authorizes
  existing root-level writes (`$owner` = the declared `Owner` = `dan@mingo.place`,
  which matches `/dan@mingo.place/**`). So deploying the daemon first breaks
  nothing.
- But the **new app writes to `/u/…`**, which the *old* `/$owner/**` policy does
  **not** match. So the on-chain root policy must be updated to `/u/$owner/**`
  **before** the new app is deployed (or those writes are denied).
- There are **zero real users**, so no dual-read / transition window is needed.

Order: **daemon → root policy → data → app**.

## Prerequisites

- The **sys signing key** in the keyring (the genesis signer for app 506; the
  `~/.sbo` move wiped it — re-import it):
  `sbo key import <sys-key> --name sys`
- A local daemon built from the merged sbo branch, or just use the deployed one.
- `SBO_TURBO_DA_API_KEY` set (already in `~/.sbo/config.toml`).

---

## Steps

### 1. Merge + push both branches
```
cd ~/src/sbo   && git checkout main && git merge --no-ff feat/identity-sovereignty-and-policy-vars && git push origin main
cd ~/src/mingo && git checkout main && git merge --no-ff feat/u-layout && git push origin main
```
Capture the new sbo main SHA → `SBO_REV`.

### 2. Re-pin mingo to the new sbo + deploy the daemon
```
cd ~/src/mingo
#  - Cargo.toml: sbo-core rev = <SBO_REV>
#  - deploy/sbo-daemon/Dockerfile: ARG SBO_REV=<SBO_REV>
cargo update -p sbo-core      # refresh Cargo.lock
cargo build                   # sanity
git commit -am "chore: bump sbo pin to <SBO_REV> (/u layout + sovereignty)"
git push origin main
git push dokku-daemon main    # rebuild + redeploy da.sandmill.org
```
Verify: `curl -s https://da.sandmill.org/v1/state-root` returns a block;
`ssh dokku@sandmill.org -- enter sbo-daemon web -- cat /data/repos.json` head ≈ chain tip.
(NB: the deploy uses dokku's 60s zero-downtime overlap on a single-writer RocksDB;
if `/v1` briefly errors with a LOCK message, it self-resolves once the old
container retires — see the prior deploy notes.)

### 3. Update the live root policy in place (sign as sys)
The new root policy is the mingo genesis policy (now `/u/$owner/**`). Post it over
the existing `/sys/policies/ root` object — sys owns it and the admin `/**` grant
also authorizes it. Build the exact JSON from `mingo-app/src/genesis.rs` (the
`policy_payload` in `mingo_genesis`), write it to `root-policy.json`, then:
```
sbo uri post "sbo+raw://avail:turing:506/sys/policies/root" root-policy.json \
    --schema policy.v2 --owner sys --key sys
```
Wait ~1 block for it to confirm + sync (watch state-root advance).

> After this, root-level `/<email>/**` writes are no longer authorized; existing
> objects there are still **readable** until moved (step 4).

### 4. Migrate (or clear) existing user objects
List what's at the root (the only user data is `dan@mingo.place` and
`danmills@mingo.place`):
```
sbo uri list "sbo+raw://avail:turing:506/dan@mingo.place/attestations/dan@mingo.place/"
sbo uri list "sbo+raw://avail:turing:506/danmills@mingo.place/attestations/danmills@mingo.place/"
```
Then **either** move each object (preserves it), signing as sys (admin transfer):
```
sbo uri mv \
  "sbo+raw://avail:turing:506/dan@mingo.place/attestations/dan@mingo.place/membership-cooks" \
  "sbo+raw://avail:turing:506/u/dan@mingo.place/attestations/dan@mingo.place/membership-cooks" \
  --key sys
# …repeat per object…
```
**or** (simplest, zero users) just delete them and re-join via the app afterward:
```
sbo uri rm "sbo+raw://avail:turing:506/dan@mingo.place/attestations/dan@mingo.place/membership-cooks" --key sys
# …etc…
```
Each is one transfer/delete tx (~1 block to confirm + sync).

### 5. Deploy the new web app
The app.js `/u/` change ships with the mingo web/idp image (`deploy/mingo/`).
Deploy it the usual way (its dokku remote / pipeline — not `dokku-daemon`, which is
the DA gateway). Confirm mingo.place loads and a join writes under
`/u/<email>/attestations/…`.

### 6. Verify end-to-end
- Join a community in the UI → membership appears under
  `/u/<email>/attestations/<email>/membership-<id>` (`uri get` it).
- Post in a community → still works (community policy unchanged).
- `uri list "sbo+raw://avail:turing:506/u/"` shows the user namespaces; root is
  clean (`sys`, `communities`, `u`).

### 7. (Optional, later) Sovereignty dry-run on the proving ground
Once stable: pick a throwaway handle, claim `/sys/names/<h>` with a key while
browserid-attributed as `<h>@mingo.place`, then post a key-signed write owned by
`<h>@mingo.place` and confirm it's authorized via the record (control flipped).
This exercises the live browserid→key path that unit tests can't (DNSSEC).

---

## Rollback
- Daemon: redeploy the prior `SBO_REV` (revert the pin commit, `git push dokku-daemon`).
- Policy: re-post the previous root policy (`/$owner/**`) signed as sys.
- App: redeploy the prior web image.
Objects moved in step 4 can be moved back with `uri mv` (admin).
