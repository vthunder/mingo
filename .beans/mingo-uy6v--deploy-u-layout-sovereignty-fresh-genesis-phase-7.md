---
# mingo-uy6v
title: Deploy /u layout + sovereignty (fresh genesis, Phase 7)
status: in-progress
type: task
priority: normal
created_at: 2026-06-28T08:43:48Z
updated_at: 2026-06-28T20:25:28Z
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
