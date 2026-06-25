# Deploying Mingo

Two dokku apps on the host **`sandmill.org`** (198.199.110.160), both built from
**this repo's root** with an app-specific Dockerfile:

| App | Domain | Dockerfile | Binary |
|-----|--------|-----------|--------|
| `sbo-daemon` | da.sandmill.org | `deploy/sbo-daemon/Dockerfile` | `sbo-daemon` (DA read/submit API) |
| `mingo` | mingo.place | `deploy/mingo/Dockerfile` | `mingo-idp` (primary IdP; also serves the `mingo-web` SPA) |

The broker (`id` → browserid.me) lives in a separate repo (`vthunder/browserid-ng`)
and is **not** deployed from here; we consume its `browserid-core` crate as a
pinned Cargo git dependency.

## Prerequisites (one-time)

Deploys authenticate with a dedicated key (the default SSH key is not authorized):
```
~/.ssh/donotuse_id_ed25519_service
```
Point each app at its Dockerfile and add git remotes (one repo, two apps):
```sh
ssh -i ~/.ssh/donotuse_id_ed25519_service dokku@sandmill.org \
  builder-dockerfile:set sbo-daemon dockerfile-path deploy/sbo-daemon/Dockerfile
ssh -i ~/.ssh/donotuse_id_ed25519_service dokku@sandmill.org \
  builder-dockerfile:set mingo dockerfile-path deploy/mingo/Dockerfile

git remote add dokku-daemon dokku@sandmill.org:sbo-daemon
git remote add dokku-mingo  dokku@sandmill.org:mingo
```

## Deploy

```sh
make deploy-daemon     # → da.sandmill.org
make deploy-mingo      # → mingo.place
make deploy            # both
```
(Each is `GIT_SSH_COMMAND="ssh -i <key>" git push dokku@sandmill.org:<app> main:master`.)

## Secrets (NOT in this public repo)

Set via `dokku config:set` so they stay out of git:
- **sbo-daemon:** `SBO_TURBO_DA_API_KEY` — the TurboDA submit key. `config.toml`
  leaves `api_key` blank; `Config::apply_env_overrides` injects it at runtime.
- **mingo:** `MINGO_IDP_SECRET`, `MINGO_ADMIN_TOKEN`, `MINGO_IDP_DB`,
  `MINGO_APP_ORIGIN`, `MINGO_BROKER_DOMAIN`, `MINGO_IDP_DOMAIN` — already set on
  the app.

```sh
ssh -i ~/.ssh/donotuse_id_ed25519_service dokku@sandmill.org \
  config:set sbo-daemon SBO_TURBO_DA_API_KEY=<key>
```

## Fast deploys

- **cargo-chef layering** — the dependency compile (incl. the slow bundled rocksdb)
  is cached on `Cargo.lock`; app-code changes recompile only our crates.
- **SPA-only changes** (`mingo-web/`) recompile **no Rust** — the SPA is copied in
  the final runtime layer of `deploy/mingo/Dockerfile`, so the cached binary layer
  is reused → deploy in seconds.
- **No resync on deploy** — daemon state persists on the `/data` mount and reads
  serve immediately while chain sync catches up in the background.

## Persistent state (daemon)

Dokku mount `/var/lib/dokku/data/storage/sbo-daemon` → `/data` in-container.
- State index: `/data/.sbo/repos/avail_turing_506/state` (HOME=/data puts
  `Config::sbo_dir()` = `$HOME/.sbo` on the persistent mount).
- Synced head: `/data/repos.json`; object files: `/data/repos/mingo`.
- DA: Avail turing app 506, repo `sbo+raw://avail:turing:506/`, genesis block
  **3528752**, RPC-only sync (no light client).

The entrypoint self-heals a head/state mismatch: if the state index is missing
but a head was carried over, it resets the head to backfill from genesis (a cold
backfill is ~15–20 min, one block at a time).

## Gotchas
- **Stale deploy lock** after an aborted push: `dokku apps:unlock <app>`.
- `dokku run` yields no output over non-interactive ssh (wants a TTY) — use
  `logs` / `config:show` / `ps:report`.
- `@mingo.place` posts currently fail the L2 attribution gate (auth-evidence gap);
  that's a content/identity workstream, not a deploy issue.
