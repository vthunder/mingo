# Mingo

**A federated forum + identity demo built on [SBO](https://github.com/vthunder/sbo).**

Mingo is an example application on top of Sovereign Blockchain Objects: users
sign in with a passwordless `@mingo.place` identity, join communities, and post —
with every write being a signed object anchored to the Avail DA layer, not a row
in a server's database. It exists to exercise the SBO reference implementation
end to end (identity, attribution, policy, content, optimistic reads) with a real
UI.

SBO itself — the `sbo-daemon`, the `sbo` CLI, and the core libraries — is
**application-agnostic and lives in [vthunder/sbo](https://github.com/vthunder/sbo)**.
This repo depends on it as a pinned git dependency and adds only the
mingo-specific layer.

## Live

- **[mingo.place](https://mingo.place)** — the SPA + the `mingo-idp` identity provider (same origin, so the IdP session cookie is first-party).
- **[da.sandmill.org](https://da.sandmill.org)** — the SBO daemon (read + submit API) following Avail turing **app 506**.

## What's here

| Component | Description |
|-----------|-------------|
| `mingo-app` | The forum layer on top of SBO: the `community.v1` schema, the community/membership genesis presets, and a thin `mingo` CLI (`genesis`, `open-community`). |
| `mingo-idp` | The mingo.place primary BrowserID identity provider — issues short-lived `<handle>@mingo.place` certificates. Also serves the SPA same-origin. |
| `mingo-web` | The browser SPA (`app.js`) — reads confirmed + pending state from the daemon's `/v1` API and builds signed writes in-browser. |
| `deploy/` | Dockerfiles (`mingo`, `sbo-daemon`), `Makefile`, and `DEPLOYMENT.md`. The daemon image builds `sbo-daemon` from `vthunder/sbo` at a pinned rev and layers mingo's app-506 seed config. |

## How it builds on SBO

- **Identity** — login is standard BrowserID discovery for the user's
  `@mingo.place` identity; `mingo-idp` mints the cert, `sbo-capture` captures the
  DNSSEC auth-evidence the daemon validates as L2 attribution.
- **Communities** — a `community.v1` descriptor names a community's issuer +
  policy. Membership is **per-community**: a user self-issues a
  `membership:<community>` attestation, and each community's policy grants posting
  only to holders of *its* membership (no policy-engine change — the matcher keys
  on the attestation `type`).
- **Optimistic reads** — the daemon's mempool overlay serves validated-but-
  unconfirmed writes, so a join or post shows immediately and posts validate
  against confirmed + pending state.

The protocol details live in the SBO specs ([vthunder/sbo](https://github.com/vthunder/sbo) `specs/`).

## Build

```bash
# Pulls the sbo crates from the pinned git dependency (see Cargo.toml).
cargo build -p mingo-idp        # the IdP
cargo build -p mingo-app        # forum layer + `mingo` CLI
```

The SBO daemon is built from the sbo repo — see `deploy/` and `DEPLOYMENT.md`.

## Deploy

```bash
make deploy-mingo     # mingo.place (mingo-idp + SPA)
make deploy-daemon    # da.sandmill.org (sbo-daemon from vthunder/sbo @ SBO_REV)
make deploy           # both, concurrently
```

When bumping the SBO dependency, update **both** the `sbo-core` git `rev` in
`Cargo.toml` and `SBO_REV` in `deploy/sbo-daemon/Dockerfile`.

## License

[MPL 2.0](https://mozilla.org/MPL/2.0/) unless otherwise indicated.
