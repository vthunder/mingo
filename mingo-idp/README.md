# mingo-idp — the mingo.place primary BrowserID IdP

A small, Mingo-owned service that makes **mingo.place** a real BrowserID
**primary IdP**. It issues its *own* `<handle>@mingo.place` certificates (signed
with mingo.place's key, discovered by the broker via DNSSEC), owns the handle
store, and serves the mingo-web SPA same-origin so its session cookie is visible
to the broker's `/provision` iframe.

It depends only on the `browserid-core` crate (cert signing, assertion verify,
discovery doc) — the **browserid.me broker is untouched** for the IdP role.

## Identity flow
1. SPA → broker dialog authenticates the user's **external** identity → assertion.
2. SPA → `POST /session/from-assertion {assertion}` → we verify it and set a
   mingo session cookie keyed by the external email.
3. New user → in-page handle picker → `POST /claim_handle {handle}`.
4. SPA → broker dialog with `provision_email=<handle>@mingo.place` → the broker
   discovers us (DNSSEC), loads `/provision` in a hidden iframe; the mingo session
   is present, so we mint the cert silently into broker custody.

Returning users repeat 1–2 (we return the existing handle) and skip the picker.

## Endpoints
- `GET  /.well-known/browserid` — discovery doc (our pubkey + `/auth` `/provision`)
- `POST /session/from-assertion` — root a mingo session from a broker assertion
- `GET  /whoami` — session probe (used by `/auth`)
- `POST /claim_handle` — claim `<handle>@mingo.place` (session required)
- `POST /cert_key` — issue the cert (session + handle ownership required)
- `GET  /provision`, `GET /auth` — the primary-IdP pages (+ shims)
- `POST /admin/seed` — demo seeding (`X-Admin-Token`)
- everything else → the mingo-web SPA (static)

## Configuration (env)
| var | default | meaning |
|---|---|---|
| `MINGO_IDP_BIND` | `0.0.0.0:7891` | bind address |
| `MINGO_IDP_DOMAIN` | `mingo.place` | cert issuer / app domain |
| `MINGO_APP_ORIGIN` | `https://mingo.place` | required audience of inbound assertions |
| `MINGO_BROKER_DOMAIN` | `browserid.me` | trusted broker |
| `MINGO_IDP_KEY_FILE` | `~/.sbo/mingo-idp-key.json` | Ed25519 keypair (browserid-core format) |
| `MINGO_IDP_DB` | `~/.sbo/mingo-idp.sqlite` | account/session store |
| `MINGO_IDP_STATIC` | `static` | IdP assets dir |
| `MINGO_SPA_DIR` | `../mingo-web` | mingo-web SPA dir |
| `MINGO_ADMIN_TOKEN` | (unset) | enables `/admin/seed` |
| `MINGO_ALLOW_HTTP` | `0` | dev: allow http issuer discovery + non-Secure cookie |

**Key pinning:** the public key in `_browserid.mingo.place` TXT must equal this
service's key. The live key is pinned at `~/.sbo/mingo-idp-key.json`
(pub `4CH9pIeke9niKtb8JiaLkhN8tEF8hDKamwgi82OU1pU`).

## Build & run (local dev)
```bash
# NB: dev machines set a shared cargo target dir (~/.cargo/config.toml), so the
# binary is NOT under ./target — `cargo run` resolves it wherever it lives.
# MINGO_APP_ORIGIN MUST equal the origin the SPA is loaded from — it's the
# audience the broker stamps into the assertion we verify.
MINGO_ALLOW_HTTP=1 MINGO_IDP_BIND=127.0.0.1:7891 \
  MINGO_APP_ORIGIN=http://127.0.0.1:7891 \
  cargo run -p mingo-idp
```
Open the SPA at `http://127.0.0.1:7891/` (`?daemon=…&broker=…&idp=…` to point at
local services). For the full silent-provision path locally, register `mingo.place`
in the broker's mock-primary registry (`POST /wsapi/test/set_mock_primary_idp`)
so discovery resolves without DNSSEC.

> Note: silent cross-site provisioning needs `SameSite=None; Secure` cookies,
> which require HTTPS. `MINGO_ALLOW_HTTP=1` downgrades to `Lax` for same-origin
> dev; the true cross-site silent path is exercised on the live HTTPS deploy.

## Deploy (mingo.place @ 198.199.110.160)
1. Switch the `browserid-core` dependency in `Cargo.toml` from the path dep to a
   pinned git dep so the build doesn't need a sibling checkout.
2. Deploy (dokku) on the broker host; mount `~/.sbo/mingo-idp-key.json` to the
   persistent key path; set `MINGO_ADMIN_TOKEN`.
3. DNS (already prepared): `_browserid.mingo.place` TXT = our pubkey + DNSSEC;
   `mingo.place` A → 198.199.110.160.
4. Verify: `dig +adflag TXT _browserid.mingo.place` shows the `ad` flag; the
   broker's `address_info?email=x@mingo.place` returns `type:primary`.

## Tests
`cargo test --manifest-path reference_impl/mingo-idp/Cargo.toml` — store
uniqueness, handle validation, and the trustless cert round-trip.
