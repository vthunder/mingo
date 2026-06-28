# `/u/` Layout + Sovereignty — Fresh-Genesis Deployment Runbook (Phase 7)

**Status:** Ready to run; **not executed**. Prepared 2026-06-28.

> **Why fresh genesis (not in-place migration):** the original **sys signing key was
> lost** (wiped with `~/.sbo`). Without it the existing app-506 chain can't be
> re-governed (no key to post the new root policy or sign admin moves). There are
> **zero real users**, so the clean move is to **re-genesis with a new sys key** —
> which also ships the new `/u/$owner/**` policy and sovereignty-ready layout from
> the start, with no data migration.

Branches to ship (pushed, tested):
- sbo `feat/identity-sovereignty-and-policy-vars` — Phases 1–4, 6.
- mingo `feat/u-layout` — Phase 5 (genesis `/u/$owner/**`, app.js `/u/` paths).

---

## Decisions baked in

- **Reuse Avail turing app 506** (not a new app-id): the existing TurboDA key is
  app-506-scoped, and re-seeding the daemon to start at the *new* genesis block
  makes the old data below it invisible. (A brand-new app-id is the alternative if
  you'd rather a pristine chain — it needs a new app-id + TurboDA key; see the note
  at the end.)
- **New sys + domain keys, BACKED UP THIS TIME** (the whole reason we're here).
- No data migration, no dual-read (zero users).

## Prerequisites

- sbo CLI + daemon built from the merged sbo branch.
- `SBO_TURBO_DA_API_KEY` (existing app-506 key) available.
- DNS access to `mingo.place` (for the `_sbo` TXT record, step 8).

---

## Steps

### 1. Merge + push both branches; bump the mingo pin
```
cd ~/src/sbo   && git checkout main && git merge --no-ff feat/identity-sovereignty-and-policy-vars && git push origin main
SBO_REV=$(git rev-parse HEAD)
cd ~/src/mingo && git checkout main && git merge --no-ff feat/u-layout && git push origin main
#  - Cargo.toml: sbo-core rev = $SBO_REV
#  - deploy/sbo-daemon/Dockerfile: ARG SBO_REV=$SBO_REV
cargo update -p sbo-core && cargo build
git commit -am "chore: bump sbo pin to $SBO_REV (/u layout + sovereignty)"
```

### 2. Generate the new keys — and BACK THEM UP
```
sbo key generate --name sys
sbo key generate --name mingo-domain        # domain root-of-trust (can reuse sys, but separate is cleaner)
# >>> EXPORT AND STORE SECURELY (do NOT lose these again) <<<
sbo key export sys           --output ~/secure-backup/mingo-sys.key
sbo key export mingo-domain  --output ~/secure-backup/mingo-domain.key
```
Record both public keys (`sbo key list`) — the sys pubkey is the admin identity; the
domain pubkey is the mingo.place root-of-trust.

### 3. Build the new genesis batch
```
cd ~/src/mingo
cargo run -p mingo-app --bin mingo -- genesis mingo.place \
    --key sys --domain-key mingo-domain --out genesis.wire
```
This emits the domain-certified `sys`, the `/sys/domains/mingo.place` object, the
pinned broker, the starter communities + space configs, and the **new root policy**
(`/u/$owner/**` + admin `/**`). Keep `genesis.wire`.

### 4. Submit genesis to app 506 and find its block
```
# Note the current finalized tip C (we'll seed the daemon just below the genesis):
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getFinalizedHead","params":[]}' \
     -H 'Content-Type: application/json' https://turing-rpc.avail.so/rpc   # -> hash -> chain_getHeader -> number C
sbo debug da submit --file genesis.wire --turbo                            # submits to app 506; note submission_id
```
The genesis lands at some block **B > C**. Seeding the daemon at `head = C` (step 5)
lets it backfill forward and pick up genesis at B; record the actual B from the
daemon's sync log once it processes it.

### 5. Update deploy config + re-seed the daemon
In `deploy/sbo-daemon/`:
- `config.toml`: `app_id` stays **506**.
- `entrypoint.sh`: change the seed so a fresh `/data` registers at `head = C`
  (the tip from step 4) instead of the old `3528751`, and **force a clean state
  rebuild** (the genesis self-heal already drops `repos.json` when state is
  missing — here we want a full reset, so wipe `/data` state on this one deploy).
  Repo `id`/`uri`/`path` are unchanged (same app 506 URI).
```
git commit -am "deploy: re-seed daemon at new genesis (head=C, fresh /data)"
git push origin main
```

### 6. Deploy the daemon (wipe old state) and verify
```
# Wipe the persisted old-chain state so it rebuilds from the new genesis:
ssh dokku@sandmill.org -- enter sbo-daemon web -- sh -c 'rm -rf /data/.sbo /data/repos /data/repos.json /data/daemon.sock'
git push dokku-daemon main      # rebuild (new SBO_REV) + redeploy
```
Verify:
```
curl -s https://da.sandmill.org/v1/state-root                                  # block advancing
curl -s "https://da.sandmill.org/v1/object?path=%2Fsys%2Fnames%2F&id=sys"      # new sys identity present
curl -s "https://da.sandmill.org/v1/object?path=%2Fsys%2Fdomains%2F&id=mingo.place"
curl -s "https://da.sandmill.org/v1/list?prefix=%2Fcommunities%2F"             # starter communities
ssh dokku@sandmill.org -- logs sbo-daemon | grep -i "Processed block"          # record genesis block B
```
(Re NB: dokku's 60s zero-downtime overlap on a single-writer RocksDB — if `/v1`
briefly errors `LOCK: Resource temporarily unavailable`, it self-resolves once the
old container retires; a `ps:stop` + `ps:start` forces a single clean container.)

### 7. Deploy the new web app
Deploy the mingo web/idp image (`deploy/mingo/`, the `/u/` app.js) via its usual
pipeline/remote (not `dokku-daemon`). Confirm mingo.place loads.

### 8. Set the DNS record (point `sbo://mingo.place` at the chain **+ its genesis**)
Add this **TXT** record (app 506 reused), per the locked SBO URI/DNS dialect (see
`~/src/sbo/docs/plans/2026-06-28-uri-dns-dialect-and-genesis-identity.md`). The genesis
**anchor** rides *inside* the `repo=` URI as `@B` (block **B** from step 6); `genesis=`
carries the hash (database identity `{chain}:{appId}:{firstBlock}:{genesisHash}`, recorded
in step 9); `node=` is the `/v1/*` data RPC:
```
_sbo.mingo.place.  IN  TXT  "v=sbo1 repo=sbo+raw://avail:turing:506@B/ genesis=sha256:<genesis-hash> node=https://da.sandmill.org"
```
(If you went with a new app-id N instead, use `repo=sbo+raw://avail:turing:N@B/`.)

> **Dialect notes:** `@B` is the genesis anchor (database-level; inherited by all paths,
> *not* a snapshot). `repo=` must be a **bare** repository URI (no path/query). There is
> **no `h=`** field — identity discovery is on-chain (browserid broker pinned in genesis
> + `/sys/names`). The *operational* sync pin is still the daemon seed (`head=C`, step 5);
> this record is the discovery/identity surface. **Requires the new sbo build** that
> parses `@firstBlock`/`repo=`/`genesis=` — ship the implementation pass before relying
> on third-party resolution.

### 9. Save the genesis (so this is reproducible / recoverable)
Commit a genesis record to the mingo repo:
- `genesis.wire` (the exact batch),
- a `deploy/GENESIS.md` noting: genesis **block B**, the **genesis hash**
  (`sha256(all_genesis_objects_bytes)` → canonical identity
  `avail:turing:506:sha256:<hash>`, Genesis Spec §Database Identity), app_id 506,
  sys pubkey, domain pubkey, seed `head = C`, and where the key backups live.

  The genesis hash + block B are exactly the `genesis=` / `firstBlock=` values for the
  DNS record in step 8, so fill those placeholders once recorded here.
```
git add genesis.wire deploy/GENESIS.md && git commit -m "chore: record new genesis (block B, app 506)" && git push
```

### 10. Verify end-to-end
- Join a community in the UI → membership under
  `/u/<email>/attestations/<email>/membership-<id>` (`uri get` it).
- Post in a community; confirm it works.
- `uri list "sbo+raw://avail:turing:506/u/"` shows user namespaces; root is clean.
- (Optional) sovereignty dry-run: browserid-claim `/sys/names/<h>` with a key, then
  a key-signed write owned by `<h>@mingo.place` is authorized via the record.

---

## Rollback
Fresh genesis is additive (old data still on app 506 below block B). To revert,
re-seed the daemon at the old `head=3528751` and redeploy the prior `SBO_REV` +
prior web image; the old chain reappears. Keep `genesis.wire` + key backups so the
new chain can always be re-stood-up.

## Alternative: brand-new app-id
If you prefer a pristine chain: obtain a new Avail turing app-id N + a TurboDA key
scoped to it, set `config.toml app_id = N`, seed `head = C`, submit genesis to N,
and use `r=sbo+raw://avail:turing:N/` in DNS. More operational friction (new key);
otherwise identical.
