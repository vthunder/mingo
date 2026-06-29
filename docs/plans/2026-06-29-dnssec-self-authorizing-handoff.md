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

## DEPLOY runbook — ORDER MATTERS (not yet executed)

> Not done autonomously: live-chain mutation + daemon redeploy are consequential and
> wanted verification. Steps, in order:

1. **Merge** both branches (after review): sbo `feat/self-authorizing-dnssec-writes`,
   mingo `feat/self-authorizing-dnssec-policy`. **Bump mingo's sbo pin** (workspace
   `Cargo.toml:33`, currently `cc207f81…`) to the merged sbo rev — now REQUIRED because
   `genesis.rs` calls `sbo_core::presets::dnssec_self_auth_policy_entries()`.
2. **Deploy the daemon FIRST** (dokku app `sbo-daemon` on da.sandmill.org). Rebuild
   from merged sbo. ⚠️ Stop the old container before re-seeding `/data` (single-writer
   RocksDB; the entrypoint marker-reset guards this). The new daemon must understand
   `dnssec_proof` BEFORE the policy below is posted.
   - **Why order matters:** an OLD daemon deserializes the unknown `dnssec_proof`
     field to nothing → the restriction becomes empty → the `to:*` grant is
     UNGUARDED → anyone could write arbitrary bytes to `/sys/dnssec/*`. Never post
     the policy against an old daemon.
3. **Post the updated root policy to the CURRENT (already-existing) live repo.** The
   genesis change only governs *future* geneses; the running mingo.place repo (app 506,
   genesis block 3545910) already has a root policy on chain, so this must be an
   explicit **update of `/sys/policies/root`** on that repo. Sys-signed with the
   backed-up `~/secure-backup/mingo-sys.key`. Use the exact merged hub-root-policy JSON
   (now sourced from the shared sbo fragment, so it matches the daemon predicate). It's
   an `update` to an existing object (LWW), additive + reversible (post again to revert).
   Build the wire (small preset / `sbo` CLI) and submit via `sbo debug da submit --turbo`.
   Confirm afterward with `GET /v1/object?path=/sys/policies/&id=root`.
4. **Verify:** as a non-sys user, submit a `/sys/dnssec/<domain>` write carrying a
   freshly-captured valid proof → should be accepted; a garbage payload → rejected
   with `dnssec_proof: invalid proof…`; a valid proof for the WRONG domain → rejected.
5. Then ship the client (remaining #2) so refresh happens automatically.

## ⏰ Interim outage stopgap (until the above ships)

mingo.place's current on-chain proofs expire **~2026-07-09**. Before then, manually
re-run the old privileged path to avoid the attribution outage:
```
sbo domain evidence mingo.place --key sys --out d.wire && sbo debug da submit --file d.wire --turbo
```
(Pull the REAL current RRSIG expiry to confirm the deadline; ~2026-07-09 is from the
prior handoff, not re-measured this session.)
