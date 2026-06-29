# Session handoff — fresh-genesis deploy + URI/DNS dialect + identity-flow fixes

**Date:** 2026-06-29. **Status: mingo.place is LIVE on the fresh genesis and validated
end-to-end** — sign-in, joining communities, and posting all work. This note captures
everything so any open thread can resume from a clean context.

---

## TL;DR of what shipped

1. **sbo: genesis-anchored URI/DNS dialect (Phases A–G)** — designed, spec'd, implemented,
   merged. New `sbo+raw://chain:appId[@firstBlock]/…?genesis=…&as_of=…` grammar; `_sbo`
   DNS record `v=sbo1 repo=… genesis=… node=…`; canonical `SboRawUri` type; genesis-hash
   verify-on-sync.
2. **mingo: fresh genesis** on Avail turing **app 506**, new (backed-up) sys key, `/u/$owner/**`
   layout. Genesis at **block 3545910**. Daemon rebuilt + verified genesis on-chain.
3. **mingo: web app (`/u` app.js + mingo-idp)** redeployed.
4. **browserid-ng: dialog 409 bug fixed** — existing/primary emails no longer get dumped
   into the create-account path. Deployed to browserid.me.
5. **mingo-idp: reject `@mingo.place` as an external sign-in identity** — committed
   (`e11c0fd`); **dokku build was in progress at handoff time** (verify it swapped in).

---

## Canonical deploy facts (see `deploy/GENESIS.md` for the authoritative copy)

- **Identity:** `avail:turing:506:3545910:sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3`
- **Genesis block B = 3545910**; seed head C = 3545906; broker `browserid.me`.
- **Keys (BACKED UP):** `~/secure-backup/mingo-sys.key`, `~/secure-backup/mingo-domain.key` (mode 600).
  - sys pubkey `ed25519:564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd`
  - domain pubkey `ed25519:8ef0381e356a7f10e48ab8be637862586e8c8088f39b7c672a16cbb2f0503ad2`
- **DNS:** `_sbo.mingo.place TXT "v=sbo1 repo=sbo+raw://avail:turing:506@3545910/ genesis=sha256:a3f28de0… node=https://da.sandmill.org"`
- **`genesis.wire`** committed in the mingo repo.

## Branches / commits (all pushed)

- **sbo** `main` = `cc207f8` (merged sovereignty + URI/DNS dialect). Plan:
  `~/src/sbo/docs/plans/2026-06-28-uri-dns-dialect-and-genesis-identity.md`.
- **mingo** `main` = `e11c0fd` (pin bump to sbo cc207f8, /u layout, genesis record, idp guard).
- **browserid-ng** `main` = `027d3dc` (dialog fix). Deployed to browserid.me (dokku app `id`).

## Services & where they live

- **da.sandmill.org** — sbo-daemon (dokku app `sbo-daemon`). Chain state DB under `/data` (RocksDB).
  Seeded via `deploy/sbo-daemon/entrypoint.sh` (head=3545906, marker-reset, genesis verify anchor).
- **mingo.place** — mingo-idp (primary BrowserID IdP) + `/u` SPA (dokku app `mingo`).
  Handle registry at `/data/mingo-idp.sqlite` (accounts: external_email→handle; sessions).
  **Only mingo-idp** uses that DB.
- **browserid.me / id.sandmill.org** — browserid-ng broker (dokku app `id`). Its own user/password DB.
- TurboDA key: `~/.turbo/key-turing-unencrypted` (= dokku `sbo-daemon` config `SBO_TURBO_DA_API_KEY`).
  Local submit config: `~/.sbo/config.toml` (`[turbo_da] app_id=506`).

---

## Post-genesis fixes that were REQUIRED (so they're not surprises)

The bare genesis booted but `@mingo.place` writes initially failed. Two things had to be
added on-chain after genesis (both sys-signed, no re-genesis):

1. **`/sys/dnssec/mingo.place`** (block 3546123) and **`/sys/dnssec/browserid.me`** (block 3546154).
   The daemon resolves the conventional `/sys/dnssec/<cert-issuer>` evidence object when a
   write carries `Auth-Cert` with no inline evidence (`validate.rs::resolve_evidence`).
   Genesis only established `/sys/trust/brokers`, not these — so attribution failed until posted.
   Command: `sbo domain evidence <domain> --key sys --out d.wire && sbo debug da submit --file d.wire --turbo`.
2. **mingo-idp handle DB cleanup.** Junk accounts (`other@z.com`, `danmills@mingo.place` which
   wrongly owned handle `dan`, `dan@mingo.place`) blocked the real `danmills@sandmill.org` login.
   Deleted via `sqlite3 /data/mingo-idp.sqlite` (had to `apt-get install -y sqlite3` in the
   container first). The `e11c0fd` idp guard prevents this class of pollution going forward.
   NB: an `/admin/delete-account` endpoint already exists for resets.

---

## OPEN THREADS / follow-ups (none blocking; pick up any from clean context)

### ⏰ TIME-SENSITIVE — DNSSEC evidence expiry (bean `mingo-3sle`, HIGH)
The `/sys/dnssec/{mingo.place,browserid.me}` proofs carry **RRSig windows that expire ~2026-07-09**.
When they lapse, `@mingo.place` attribution breaks again (same symptom as today). Need to:
- Have `mingo_genesis` emit `/sys/dnssec/<domain>` so a fresh genesis is write-ready.
- **Automate periodic re-capture + resubmit before expiry (cron).** This is the most important
  follow-up — it's a recurring outage otherwise.

### browserid-ng identity-flow hardening (bean `mingo-a9uj`)
- Dialog 409 fix is DONE + deployed. **Deferred:** server-side `address_info` should not silently
  downgrade a known-primary email to secondary on a transient discovery failure — needs **discovery
  result caching** (fall back to last-known-good incl. auth/prov URLs). A partial fix is incorrect
  without the cached URLs.

### sbo URI/DNS dialect deferred items (in the sbo plan doc)
- **Serve `?as_of`** historical reads — currently recognized but returns 501; needs versioned
  object state (the state DB stores only latest LWW values).
- **Block-only genesis ambiguity** detection (>1 genesis at a height) — needs DA-layer inspection.
- **`appId` opaqueness** — `AppId` newtype is in place; relax inner repr for non-Avail chains later.
- **Prover/proof discovery** — SBOP validity proofs are generated but unserved by design (trust on-chain).

### Identity architecture notes (design, not bugs)
- The on-chain attribution cert is issued via the **primary IdP** of the email's domain
  (`mingo.place` for `@mingo.place`, `sandmill.org` for `@sandmill.org`); `browserid.me` is the
  fallback signer only. Both `/sys/dnssec/mingo.place` and `/sys/dnssec/browserid.me` are on-chain,
  covering both paths.

---

## Gotchas worth remembering

- **`dokku enter … sh -c '…'` mangles quoted args** (ssh flattens). For SQL etc., wrap the WHOLE
  remote command in one local-quoted string: `ssh dokku@host 'enter app web -- sqlite3 /path "SQL"'`.
  Stdin is **not** forwarded through `dokku enter`.
- **Daemon `/v1/submit` validates synchronously** and returns `400 "<Stage>: <reason>"` — the reason
  is NOT logged server-side; read it from the HTTP response (DevTools Network) when debugging writes.
- **dokku zero-downtime overlap (~60s)** + single-writer RocksDB on the daemon → stop the old
  container before re-seeding `/data` (the entrypoint marker-reset also guards this).
- DB backup of the idp store was pulled locally during the session (base64 from `/data/mingo-idp.sqlite`).

## Verify-on-resume checklist
- mingo.place: sign in (real external email), join a community, post → all should work.
- `ssh dokku@sandmill.org ps:report mingo` → confirm the `e11c0fd` idp container swapped in, and that
  signing in with a `@mingo.place` email is now rejected.
- `da.sandmill.org/v1/state-root` advancing; `/v1/list?prefix=/u/` shows real user namespaces.
