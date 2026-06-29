---
# mingo-uy6v
title: Deploy /u layout + sovereignty (fresh genesis, Phase 7)
status: completed
type: task
priority: normal
created_at: 2026-06-28T08:43:48Z
updated_at: 2026-06-28T22:05:42Z
---

Execute docs/plans/2026-06-28-u-layout-migration-runbook.md end to end. Tweak: DNS record must pin to the new chain's genesis block specifically (per SBO URI/DNS spec), not just the app.

## LOCKED: DNS discovery + sbo+raw URI dialect (design settled 2026-06-28)

Final surface (replaces the old \`v=sbo1 r=… h=…\` record and \`@block\`=snapshot):

**sbo+raw URI grammar:** \`sbo+raw://chain:appId[@firstBlock]/path[?genesis=<hash>][?as_of=<block>]\`
- Authority stays pure \`chain:appId\` (CAIP-2 + appId); \`@firstBlock\` is a delimited suffix, NOT a 4th colon component (keeps appId opaqueness-safe).
- \`@firstBlock\` = genesis **anchor** (database-level; applies to all composed paths). Redefines \`@block\` from snapshot→anchor.
- \`?genesis=<hash>\` = optional identity verify/disambiguate (hash only).
- \`?as_of=<block>\` = historical snapshot read (moved out of \`@block\`).

**Reference vs identity:** reference may be \`@block\` (locator) and/or \`?genesis=hash\` (identity). Canonical identity tuple = \`{chain}:{appId}:{firstBlock}:{genesisHash}\`. block-only resolves but MUST error on ambiguity (>1 genesis at that height); hash-only locates by scan/checkpoint.

**DNS \`_sbo\` record (data only):** \`v=sbo1 repo=sbo+raw://avail:turing:506@12345/ genesis=sha256:<hash> node=https://da.sandmill.org\`
- \`r=\`→\`repo=\` (word-keys). Drop \`h=\` (dead: get_discovery_host has no callers; identity = browserid broker pinned in genesis + /sys/names).
- \`node=\` = /v1/* data RPC (distinct role from auth). \`checkpoint=\` optional (state-root fast-forward; trust still from on-chain proofs, never DNS).
- \`_sbo-id\` confirmed dead (deleted in 2026-06-23 reconciliation); scrub stale docs.

**Decisions:** (1) implement \`@block\`(anchor)+\`?genesis\`+\`?as_of\` on SboUri. (3) appId opaqueness = tracked follow-up.

## Progress 2026-06-28 — spec locked & aligned; impl plan written

DONE:
- Specs updated + aligned to the locked dialect: SBO URI Spec (canonical: DNS record format, sbo+raw grammar incl @firstBlock anchor, query params incl ?as_of, Database Identity 4-tuple, reference-vs-identity, resolution semantics), SBO Genesis Spec (identity tuple, record example, bootstrap flow), SBO Identity Spec (record fields, no h=/_sbo-id), crates/README.md (record examples, Demo 3 email-rooted, raw URI grammar).
- Implementation plan: ~/src/sbo/docs/plans/2026-06-28-uri-dns-dialect-and-genesis-identity.md (Phases A-G: canonical SboRawUri in sbo-core, DNS parser, genesis identity hash+verify, daemon from_block wiring, ?as_of read path, CLI, tests; appId-opaqueness + prover-discovery tracked as follow-ups).
- Deploy runbook step 8 + handoff DNS records updated to: v=sbo1 repo=sbo+raw://avail:turing:506@B/ genesis=sha256:<hash> node=https://da.sandmill.org

DEPLOY DEPENDENCY (new): third-party sbo:// resolution now requires the sbo URI/DNS implementation pass (Phases A-G) to ship before deploy's DNS step is meaningful. The daemon itself still syncs via the operator seed (head=C), so the chain comes up regardless — but the locked DNS record is only honored by the new build. Sequence: implement Phases A-G in sbo → merge → bump mingo pin → run deploy runbook.

## Implementation progress (sbo branch feat/uri-dns-dialect)

Commits landed (all tests green per phase):
- Phase A (keystone): sbo-core/src/uri.rs — SboRawUri/ChainId/AppId/UriQuery, parse/emit/compose/identity, 14 tests.
- Phase A2+B: daemon repointed onto SboRawUri (deleted local ChainId/SboUri); dns.rs rewritten to v=/repo=/genesis=/node=/checkpoint= with bare-repo rule + anchor-preserving resolve_uri; dropped h=/_sbo-id.
- Phase C: sbo-core genesis_hash + genesis_hash_from_wire (sha256 of canonical wire concat).
- Phase D pt1: daemon seeds from_block from @firstBlock anchor when no override.
- Phase E: ?as_of recognized + refused with 501 (state DB has no versioned values — honest backend gap, tracked follow-up); reject_as_of on /v1/object + /v1/list.

In progress (delegated agent): Phase F (CLI parsers onto core type, id-resolve doc fix) + Phase G (workspace stale-ref sweep, full test + clippy).

Remaining / decisions:
- Phase D pt2 (genesis-hash verify-on-sync + block-only ambiguity): chain-coupled plumbing (expected_genesis through RepoAdd->Repo->sync). To implement after agent finishes (avoids daemon-file races).
- Tracked follow-ups: versioned object state (to actually serve ?as_of); appId opaqueness (AppId newtype already in place); prover/proof discovery.

## Implementation COMPLETE (sbo feat/uri-dns-dialect) — all phases A–G green

Final commits (full workspace tests green, 0 failures):
- A keystone (uri.rs), A2/B (daemon+dns onto SboRawUri), C (genesis_hash), D pt1 (from_block from anchor), E (as_of recognized+refused 501), F/G (CLI repoint + sweep), D pt2 (genesis verify-on-sync plumbing + Repo::verify_genesis + tests).

Tracked follow-ups (NOT gaps in the dialect; separate efforts):
- Versioned object state → to actually SERVE ?as_of historical reads (currently 501).
- Genesis verify end-to-end only exercisable against live chain (genesis block data); block-only ambiguity (>1 genesis at a height) needs DA-layer inspection.
- appId opaqueness (AppId newtype already in place; relax inner repr later).
- Prover/proof discovery (SBOP unserved by design; trust on-chain).

NEXT: merge feat/uri-dns-dialect into sbo (after the sovereignty branch per deploy runbook step 1), then the mingo pin bump picks it up and the deploy DNS record (repo=...@B genesis=sha256:.. node=..) is honored by the new build.

## DEPLOY IN PROGRESS (2026-06-28)

Genesis SUBMITTED + landed:
- Genesis block B = 3545910 (confirmed via da scan: post /sys/domains/mingo.place)
- Genesis hash = sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3
- Canonical identity: avail:turing:506:3545910:sha256:a3f28de0...
- app_id 506; seed head C = 3545906; broker = browserid.me
- sys pubkey ed25519:564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd
- domain pubkey ed25519:8ef0381e356a7f10e48ab8be637862586e8c8088f39b7c672a16cbb2f0503ad2
- TurboDA submission_id d3123661-6d43-4117-8e18-383ac1a0f7aa
- Key backups: ~/secure-backup/mingo-sys.key, ~/secure-backup/mingo-domain.key (mode 600)

Done: merges+pin (sbo cc207f8, mingo main), keys+backup, genesis build+submit, deploy/GENESIS.md written, entrypoint reseed (head=C, new SboRawUri format, marker-reset, verify anchor B+expected_genesis).

In progress: daemon rebuild on dokku (~40-50 min Rust build; old container stopped pre-build to avoid /data race). Polling da.sandmill.org/health for completion.

Remaining: verify new chain (sys/domains/communities, head advancing, "Genesis verified" log at B); deploy web app (dokku-mingo); commit genesis.wire+GENESIS.md; SET DNS (user-manual): _sbo.mingo.place TXT "v=sbo1 repo=sbo+raw://avail:turing:506@3545910/ genesis=sha256:a3f28de0... node=https://da.sandmill.org"; end-to-end verify.

## Daemon LIVE + genesis VERIFIED on-chain (2026-06-28 ~21:51)

Daemon rebuilt (sbo cc207f8) and came up after ~37min. Logs confirm:
- "fresh-genesis reset: wiping /data state" + "seeded /data/repos.json (head=3545906)" → marker-reset worked
- All genesis objects applied at block 3545910 (sys domain, communities cooks/woodworking/homelab + spaces, /sys/policies/root)
- "Genesis verified for repo f86a7b415defc6cf at block 3545910" → Phase D pt2 verify PASSED on real chain
- /v1/state-root, /v1/object (sys/domains/mingo.place), /v1/list (communities) all serving correctly

DNS verified: _sbo.mingo.place TXT set + parses with real sbo parser; anchor inheritance confirmed (compose /communities/cooks/ → ...@3545910/communities/cooks/).

genesis.wire + deploy/GENESIS.md committed (mingo aa7ddf1).

In progress: web app redeploy (dokku-mingo, /u app.js — required because new root policy is /u/$owner/**; old app paths would be denied).
Remaining: confirm web app up; end-to-end (join community → /u/<email>/attestations/.../membership; post).

## Summary of Changes — DEPLOY COMPLETE (2026-06-29)

Fresh-genesis cutover of mingo.place (Avail turing app 506) is live:
- Implemented the genesis-anchored URI/DNS dialect end-to-end in sbo (Phases A–G, merged to sbo main cc207f8) + aligned all specs.
- Merged mingo /u layout to main, bumped sbo pin to cc207f8.
- Generated NEW sys+domain keys, BACKED UP to ~/secure-backup/ (mode 600).
- Built + submitted genesis to app 506 → landed at block 3545910, hash sha256:a3f28de0f9e185328693b106e8368ab6539607d27e0142d147263fbf1da5d8b3.
- Rebuilt daemon (race-safe marker reset, reseed head=3545906); daemon VERIFIED genesis on-chain ("Genesis verified ... at block 3545910").
- DNS _sbo.mingo.place set (repo=...@3545910 genesis=sha256:a3f28de0... node=https://da.sandmill.org), propagated + parses.
- Redeployed web app (/u app.js) — new container live, mingo.place 200, SPA is /u-aware.
- Committed genesis.wire + deploy/GENESIS.md (mingo aa7ddf1).
- Verified: /sys/domains/mingo.place, communities, clean /u/ root.

REMAINING (user-side, requires live browser + browserid — can't be done headlessly):
- End-to-end UI test: log in at mingo.place, join a community → confirm membership lands under /u/<email>/attestations/.../membership-<id>; post a message in a community.

Tracked follow-ups (separate from deploy): serve ?as_of (versioned state); block-only genesis ambiguity (DA inspection); appId opaqueness; prover/proof discovery.
