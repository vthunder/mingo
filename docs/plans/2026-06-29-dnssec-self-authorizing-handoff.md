# Self-authorizing /sys/dnssec writes — implementation handoff

**Date:** 2026-06-29. **Status:** core landed on branches (not merged, not deployed).
Beans: `mingo-c9ci` (sbo side), `mingo-3sle` (mingo client side, blocked-by c9ci).

## The design (agreed)

`@<domain>` attribution needs an unexpired on-chain `/sys/dnssec/<domain>` RFC 9102
proof. RRSIG windows are short (mingo.place's expire **~2026-07-09**), so a static
proof goes stale → `@mingo.place` writes get carried-but-filtered. Instead of a cron
refreshing all domains, make the object **self-authorizing**: the DNSSEC proof is
verified offline against the pinned IANA root on every replay, so the payload proves
its own write-authority. Any signer may refresh it, lazily, on their own writes.

This rides the existing policy engine — the only net-new primitive is one `require`
predicate, `dnssec_proof`, in the same family as `require_payload_signed_by`.

## What's DONE (committed, build-green, NOT merged/deployed)

### sbo — branch `feat/self-authorizing-dnssec-writes` (commit 2c3d4d8)
- `attribution::verify_dnssec_proof_for_domain(proof, domain)` — pub wrapper over the
  existing `extract_provider_key`; validates the RFC 9102 chain AND requires
  `_browserid.<domain>` (so a proof for a different domain is rejected). Returns the
  RRSIG window.
- `policy::types::Requirements.dnssec_proof: bool` (defaults false, skipped in serde).
- `policy::evaluate::check_dnssec_proof` — derives the domain from `message.id` (a
  dnssec write is `path=/sys/dnssec/`, `id=<domain>`), runs the verifier, denies on
  failure. **Guards shipped: 1 (valid chain) + 2 (intrinsic domain binding).**
- Tests: predicate fires on the container path `/sys/dnssec/`, rejects invalid/absent
  payloads; default-false is a no-op. `cargo test -p sbo-core policy::` green;
  `cargo build -p sbo-daemon` green.

### mingo — branch `feat/self-authorizing-dnssec-policy` (commit ccaa577)
- `mingo-app/src/genesis.rs` hub root policy: added grant
  `{to:"*", can:[create,update], on:/sys/dnssec/**}` + restriction
  `{on:/sys/dnssec/**, require:{schema:dnssec.v1, content_type:application/octet-stream, dnssec_proof:true}}`.
  Additive (admin grant unchanged). `cargo test -p mingo-app genesis` green.
- Beans reframed.

## What's REMAINING

### 1. Daemon `/v1/dnssec` query/capture API (sbo) — generic, READ-ONLY, no submits
**Request:** `GET /v1/dnssec?domain=<d>&needed_by=<unix>&margin=<secs>&repo=<opt>`
- `needed_by` (optional, default = now): the time the client needs the proof valid for.
- `margin` (optional): extra headroom added to `needed_by` for inclusion latency.

**Response (JSON, UTF-8 safe):**
```
{ "on_chain": { "inception": <unix>, "expiration": <unix> } | null,
  "needs_refresh": <bool>,
  "proof_b64": "<base64url>"   // present ONLY when needs_refresh is true
}
```
- `needs_refresh = on_chain is null OR on_chain.expiration < needed_by + margin`.
- When `needs_refresh` is true, the daemon **captures a fresh proof from live DNS** and
  returns it base64url-encoded; the client decodes and submits it. When false, the
  client submits a bare write and `proof_b64` is omitted (no bandwidth). This is the
  timestamp-gated, return-only-when-needed behavior we agreed on.

**Implementation notes:**
- **Encode the proof, don't pass raw through ObjectView.** `RepoApi::get_object`'s
  `ObjectView.payload_text` is **lossy UTF-8** — corrupts the binary proof. For the
  on-chain window read, add a small raw-bytes getter to the `RepoApi` trait
  (`crates/sbo-daemon/src/http.rs:126`), impl on `DaemonState`
  (`crates/sbo-daemon/src/main.rs:352`) + test `MockState`, then parse the window with
  `attribution::verify_dnssec_proof_for_domain`. (Returning base64url in the *response*
  is the right call per review — but the daemon still needs the real bytes internally;
  the lossy `payload_text` can't provide them.)
- **Capture** (the `needs_refresh` path): `sbo-capture` is NOT yet a daemon dependency —
  add it (`crates/sbo-daemon/Cargo.toml`) and call its capture fn. The returned proof is
  the *fresh* one (the on-chain one is stale by definition when a refresh is needed).
  CLI precedent: `crates/sbo-cli/src/commands/domain.rs:84`, lib
  `crates/sbo-capture/src/lib.rs:187`.
- Router: add `.route("/v1/dnssec", get(...))` at `http.rs:222`.

### 2. mingo client (bean mingo-3sle)
On write: call `/v1/dnssec?domain=<signer domain>`. If fresh → bare write. If
stale/absent/near-expiry → fetch proof bytes, (a) inline on this write for immediacy,
(b) submit a `/sys/dnssec/<domain>` refresh write (self-authorizing) for the next
writer. Writer bears the cost. Pick a freshness margin with headroom for inclusion
latency. (Web client / `/u` app.js; also mingo-idp submits on the client's behalf.)

### 3. Guard 3 — monotonic freshness (deferred, lower severity)
Reject a proof whose RRSIG expiration isn't strictly newer than the stored object's.
Needs prior-object state threaded into `evaluate()` (mirror the `is_attested` closure
pattern). Worst case without it: a mildly-earlier expiry / rollback griefing; the next
writer self-heals. Do as a fast-follow.

### 4. Spec zettels (sbo `specs/`)
Document the `dnssec_proof` predicate, its guards, the intrinsic id→domain binding (no
`$domain` variable), and the default `/sys/dnssec/*` policy. Files: `SBO Policy
Specification.md`, `SBO Authorization Specification.md`, `SBO Genesis Specification.md`.

## STATUS 2026-06-29: all code built, tested, committed, PUSHED. Deploy not run.

Everything below the code line is done. Branches pushed to origin:
`sbo:feat/self-authorizing-dnssec-writes` (HEAD e276ac6),
`mingo:feat/self-authorizing-dnssec-policy` (HEAD d16a8e8). The mingo client
(`mingo-web/app.js`) lazy-refresh is implemented and committed.

**Verified deploy preconditions:**
- `sbo key list` has alias `sys` = `ed25519:564aafe4…` (genesis sys key), default key →
  `sbo uri post … --key sys` is ready for the policy update.
- Daemon `entrypoint.sh` will NOT wipe `/data` on a routine redeploy (the one-shot
  reset marker `/data/.reset-genesis-3545910` already exists); it just restarts + resumes sync.
- ⚠️ **Daemon dokku app has zero-downtime ON** (`dokku checks:report sbo-daemon` →
  `wait to retire: 60`). Old + new containers overlap 60s. The daemon is single-writer
  RocksDB on `/data/.sbo`, so the new container can't open the DB while the old holds it →
  a plain `git push dokku-daemon` will fail/abort. **Must stop the old container first**
  (brief da.sandmill.org downtime). This is why the redeploy wasn't auto-driven.

## DEPLOY runbook — ORDER MATTERS, stop-first daemon deploy

> Remaining = production-operational: a stop-first maintenance redeploy of the live DA
> node + an irreversible (though repostable) on-chain governance change. Run with eyes on
> da.sandmill.org. Exact sequence:

1. **Merge** both branches (after review) and **bump mingo's sbo pin** (workspace
   `Cargo.toml:33`, currently `cc207f81…`) to the merged sbo rev — REQUIRED because
   `genesis.rs` + the daemon both now need the new sbo (`dnssec_self_auth_policy_entries`
   + `dnssec_proof` + `/v1/dnssec`). Push the pin bump to mingo `main`.
   Exact commands:
   ```
   # after merging sbo to main and noting its commit <SBO_SHA>:
   cd ~/src/mingo
   sed -i '' 's#rev = "cc207f81.*"#rev = "<SBO_SHA>"#' Cargo.toml
   cargo update -p sbo-core && cargo build -p sbo-app   # refresh lock, sanity build
   git commit -am "chore: bump sbo pin to <SBO_SHA> (dnssec self-auth)"
   ```
2. **Deploy the daemon FIRST** (dokku `sbo-daemon`, da.sandmill.org), stop-first:
   ```
   ssh dokku@sandmill.org ps:stop sbo-daemon      # frees the RocksDB lock; ~downtime starts
   cd ~/src/mingo && git push dokku-daemon main    # builds new image (new sbo), restarts
   ssh dokku@sandmill.org ps:report sbo-daemon     # confirm Running: true
   curl -s https://da.sandmill.org/v1/state-root   # confirm it advances / responds
   curl -s 'https://da.sandmill.org/v1/dnssec?domain=mingo.place'  # NEW endpoint must 200
   ```
   The new daemon MUST be confirmed healthy + expose `/v1/dnssec` BEFORE the policy post.
   - **Why order matters:** an OLD daemon deserializes the unknown `dnssec_proof`
     field to nothing → the restriction becomes empty → the `to:*` grant is
     UNGUARDED → anyone could write arbitrary bytes to `/sys/dnssec/*`. Never post
     the policy against an old daemon.
3. **Post the updated root policy to the CURRENT (already-existing) live repo.** The
   genesis change only governs *future* geneses; the running mingo.place repo (app 506,
   genesis 3545910) already has `/sys/policies/root` on chain — so update it explicitly.
   It's an LWW `update`, additive, and **reversible** (re-post the prior JSON to revert).
   - First capture the CURRENT policy as a rollback artifact:
     `curl -s 'https://da.sandmill.org/v1/object?path=/sys/policies/&id=root' | jq -r .value > /tmp/root-policy.prev.json`
   - Write the NEW policy JSON = the current one + the two dnssec entries (the exact
     fragment from `sbo_core::presets::dnssec_self_auth_policy_entries`):
     grant `{"to":"*","can":["create","update"],"on":"/sys/dnssec/**"}` and restriction
     `{"on":"/sys/dnssec/**","require":{"schema":"dnssec.v1","content_type":"application/octet-stream","dnssec_proof":true}}`.
     (Match `mingo-app/src/genesis.rs` exactly.) Save to `/tmp/root-policy.new.json`.
   - Post it sys-signed:
     ```
     sbo uri post sbo+raw://avail:turing:506/sys/policies/root /tmp/root-policy.new.json \
       --schema policy.v2 --content-type application/json --key sys
     ```
   - Verify: `curl -s '…/v1/object?path=/sys/policies/&id=root' | jq .value` shows the entries.
4. **Deploy the web app** (client lazy-refresh): `git push dokku-mingo main` (dokku app
   `mingo`). No chain interaction; safe anytime after the daemon + policy are live.
5. **Smoke-test end-to-end:**
   - On mingo.place, sign in and make a post. With the on-chain proof currently expired,
     the client should auto-submit a key-rooted `/sys/dnssec/mingo.place` refresh first,
     then the post succeeds. Confirm `…/v1/object?path=/sys/dnssec/&id=mingo.place` shows a
     fresh window, and a second post does a bare write (no refresh).
   - Negative checks (CLI): garbage payload → rejected `dnssec_proof: invalid proof…`;
     a valid proof for the WRONG domain into `/sys/dnssec/mingo.place` → rejected.
   - Rollback if needed: re-post `/tmp/root-policy.prev.json` (step 3) with `--key sys`.

## ⏰ Interim outage stopgap (until the above ships)

mingo.place's current on-chain proofs expire **~2026-07-09**. Before then, manually
re-run the old privileged path to avoid the attribution outage:
```
sbo domain evidence mingo.place --key sys --out d.wire && sbo debug da submit --file d.wire --turbo
```
(Pull the REAL current RRSIG expiry to confirm the deadline; ~2026-07-09 is from the
prior handoff, not re-measured this session.)
