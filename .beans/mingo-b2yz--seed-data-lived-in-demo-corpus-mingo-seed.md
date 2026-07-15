---
# mingo-b2yz
title: 'Seed data: lived-in demo corpus (mingo-seed)'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-15T19:57:49Z
updated_at: 2026-07-15T21:26:08Z
parent: mingo-y9gb
---

Generate a rich sample corpus so mingo looks lived in: several communities, ~15 personas (<handle>@mingo.place), posts/comments/votes with staggered timestamps, plus cross-issued vouches/badges so passports are non-empty. Mechanism TBD after recon — likely server-side (mingo-idp holds the IdP key needed to mint persona certs), triggered by an admin endpoint or one-shot job. Must handle membership attestations (daemon validates), community creation policy, and HLC backdating limits.

## Recon (mingo side, 2026-07-15)

- Live communities are cooks/woodworking/homelab from the pre-signed genesis batch (deploy/GENESIS.md); NEW communities need the sys key (~/secure-backup/mingo-sys.key) — descriptor + open policy + spaces/general/_config, same builders as genesis.rs. v1 can seed into existing communities.
- Personas: POST /admin/provision (routes.rs:345, X-Admin-Token, validated end-to-end in mingo-acmx) reserves the handle in the accounts table AND mints a chain-valid <handle>@mingo.place cert for a supplied pubkey. Use sentinel external emails (reject_own_domain forbids @mingo.place). Reserving handles avoids future collisions with real users.
- Writes: the poster path is NOT reusable (needs a real user warrant); seeder signs directly with each persona key + provisioned cert (the client's non-agent path, app.js:630-640): membership attestation.v1 at /u/<email>/attestations/<email>/ id membership-<c> type 'membership:<c>' first (member role, genesis.rs:109-113), then post.v1/comment.v1/reaction.v1 into /communities/<c>/spaces/general/. Submit via POST /v1/submit (submit_wire, poster.rs:393). ensure_dnssec_fresh(mingo.place) once, first.
- Root policy: anyone may create /sys/names/*; owner owns /u/$owner/**; ban restriction on spaces.
- Shape: a 'seed' subcommand on the existing mingo-app CLI (bin/mingo.rs — no new crate, no Dockerfile impact), run locally against prod with MINGO_ADMIN_TOKEN; embedded corpus with relative ages.
- Open question (sbo recon pending): HLC backdating limits at submit; envelope exposure for provenance.

## Recon (sbo side) — backdating verdict

- HLC must be within [now-W, now+5min] at submit (validate.rs:442-466); default W=5min BUT widened per-collection by a collection.v1 _config 'max_authoring_lag_s' AT the write's exact path (validate.rs:468-489, presets.rs:978-1004). Genesis already posts spaces/general/_config per community — check its lag value; if small, seed step 0 posts an updated _config with a large lag (needs whoever policy allows — sys key from ~/secure-backup if members can't).
- Cert/DNSSEC windows are checked against SUBMIT-time now (attribution.rs:548-562) — a currently-valid cert + fresh /sys/dnssec works fine for backdated-HLC content. Future-dating capped at +5min. Membership in-force check also uses inclusion time, not HLC — no ordering constraint vs backdated posts.
- sbo-core presets already ship the builders the seeder needs: signed_object/post_object/collection_config/attestation + membership/post/comment/reaction payloads (presets.rs:824-1041). mingo-app depends on sbo-core → seed subcommand on the mingo CLI uses these directly.
- Vouches: attestation.v1 in issuer namespace /u/<issuer>/attestations/<subject>/, any subject — app.js getPassport matches by subject across namespaces, so cross-persona vouches light up passports.

## Plan
- [x] Read genesis.rs collection_config lag + /admin/provision req/resp + preset builder signatures
- [x] Corpus (embedded JSON): 3 communities, ~15 personas, threads/comments/votes with ages, vouches + badges
- [x] mingo CLI 'seed' subcommand: dnssec fresh → provision personas → widen _config if needed → memberships → content (backdated HLC) → vouches
- [ ] Dry-run against a local daemon if feasible (writes are append-only — no undo on prod)
- [ ] Run against prod, verify in the UI

## Implementation (2026-07-15, uncommitted — in working tree for review)

- `mingo-app/src/seed.rs` + embedded `mingo-app/src/seed_corpus.json` (override: `--corpus`); `seed` subcommand wired in `bin/mingo.rs`. Deps added: reqwest (blocking+json), base64.
- Corpus: 15 personas, 21 posts (7/community), 65 comments, 95 upvotes, 14 vouches, 5 badges; 32 memberships derived from participation → 232 writes.
- Deterministic ids (`p-/c-/r-<b36(sha256(corpus key))>`), so re-runs LWW-overwrite. Persona keys are fresh per run (owner is the email; cert re-binds).
- Without --sys-key ages compress order-preservingly to ≤20h (knee 12h); with --sys-key (`ed25519:<hex>` export or `{"secret_key":hex}`) _config widens to 45d then restores 24h, even if a submit aborts mid-run.
- Prod run: `MINGO_ADMIN_TOKEN=… mingo seed --sys-key ~/secure-backup/mingo-sys.key --execute` (defaults: --idp https://mingo.place --daemon https://da.sandmill.org). Aborts on first 400 with stage/reason.

## Provenance variety (dan's request, follow-up pass)

Corpus now exercises three receipt flavors: ~60% mingo.place author + client-signed, 3 external-identity personas (lidia.m/grubb/birchbark → @example.com, broker-fallback-certified), and 13 agent-signed items (4 posts + 9 comments incl. two 📬 digest-bot roundups) by asha/jjnguyen/grubb — grubb overlaps both flavors. 234 writes total.

Decisions:
- External emails restricted to @example.com or vthunder@gmail.com at BOTH layers (corpus validation + the broker's new /wsapi/admin/cert_key hard allowlist, env BROKER_ADMIN_MINT_ALLOWLIST; no allowlist = mint nothing; route unmounted without BROKER_ADMIN_TOKEN). The broker must never attest an address that could belong to a real third party.
- Agent = seeder-run digest-bot@mingo.place, never the real mingo-poster. Agent certs MUST be agent-shaped (sbo attribution.rs:263-274 requires agent_cert.agent_parent == warrant.iss), so /admin/provision gained an optional agent_parent field minting mingo-poster-shaped certs (one per delegating author). Warrants signed by each author's own identity key via browserid_core::Warrant::create (90d, mingo-poster scopes, as:<author>); no status ref (the daemon doesn't require one; fabricating indices into the real status list would collide with real revocations).
- Cross-issuer chains (external author's browserid.me parent cert + mingo.place agent cert) are accepted by the daemon per attribution.rs:311-314 (is_broker) — same shape as dan's live mingo-poster post.
- DNSSEC freshness now covers browserid.me too when external personas exist.

Execute now also needs BROKER_ADMIN_TOKEN in the env (and the broker deployed with it + BROKER_ADMIN_MINT_ALLOWLIST=example.com).
