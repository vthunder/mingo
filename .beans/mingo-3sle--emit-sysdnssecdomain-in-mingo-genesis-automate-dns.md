---
# mingo-3sle
title: 'mingo: client-driven, lazy DNSSEC proof refresh (call daemon API, inline-when-stale)'
status: in-progress
type: task
priority: high
created_at: 2026-06-28T22:20:01Z
updated_at: 2026-06-30T22:06:08Z
blocked_by:
    - mingo-c9ci
    - mingo-stho
---

Reframed 2026-06-29. Supersedes the original genesis-emit + cron plan (both dropped — see below). Depends on the sbo self-authorizing /sys/dnssec write predicate ([[mingo-c9ci]]).

Problem recap: @mingo.place attribution needs an unexpired on-chain /sys/dnssec/<domain> RFC 9102 proof. RRSIG windows are short (current ones expire ~2026-07-09), so a static genesis-emitted proof goes stale and writes start failing (carried-but-filtered). We do NOT want a cron refreshing all domains' proofs continuously (work scales with registered domains, not active writers) — instead refresh lazily, only when a user actually writes, and only if the on-chain proof is stale.

Design: the sbo daemon exposes a generic READ-ONLY DNSSEC query/capture API (see [[mingo-c9ci]]); the mingo client uses it and submits any refresh itself (writer bears the write cost; no second on-chain-writing surface). The on-chain object self-heals: first writer after expiry repopulates it via the self-authorizing write, everyone after goes bare.

## Tasks
- [ ] On write, mingo client calls the daemon DNSSEC API for the signer's domain to learn the on-chain proof window (null/expired flag if absent or stale).
- [ ] If the on-chain proof is fresh enough, submit a BARE write (no inline evidence) — daemon uses the absent-evidence fallback to /sys/dnssec/<domain>. No bandwidth spent.
- [ ] If stale/absent/near-expiry: fetch fresh proof bytes from the API, then: (a) inline the proof on THIS write (immediacy — the client's own write could otherwise be ordered before the refresh lands), AND (b) submit a /sys/dnssec/<domain> refresh write so subsequent writers go bare. Both client-submitted.
- [ ] Decide the freshness margin (how close to expiry triggers a refresh) — leave headroom for inclusion latency.

## Open question (resolve with sbo side)
- If the daemon guarantees intra-batch ordering (refresh ordered before a dependent write in the same submission), task (a) inline could be dropped. Until confirmed, do inline + refresh.

## Dropped from the original plan
- mingo_genesis emits /sys/dnssec/<domain> — unnecessary; first writer populates it via the self-authorizing write.
- cron periodic re-capture+resubmit — replaced by lazy, client-driven, demand-based refresh.
- daemon warning/metric on near-expiry — optional nice-to-have.

## TIME-SENSITIVE caveat
Current on-chain proofs expire ~2026-07-09. Until this ships, @mingo.place writes break again at expiry. Interim stopgap: manually re-run `sbo domain evidence mingo.place --key sys --out d.wire && sbo debug da submit --file d.wire --turbo` before the window lapses (block 3546123 precedent).

## Built 2026-06-29 (NOT deployed)

Client lazy-refresh implemented + committed + pushed (branch feat/self-authorizing-dnssec-policy, web commit d16a8e8). Daemon /v1/dnssec API + dnssec_proof predicate + shared sbo policy fragment also done + pushed (sbo branch feat/self-authorizing-dnssec-writes, e276ac6). All build+test green.

Design note: did NOT inline proof into the user write (Auth-Evidence is part of signed content → would need signer change). Instead the refresh is a KEY-ROOTED /sys/dnssec/<domain> write (authorized by the self-authorizing policy); the subsequent email-rooted write attributes against it via the daemon confirmed+pending overlay. Freshness margin 1h.

Deploy deferred (needs eyes on da.sandmill.org): stop-first daemon redeploy (dokku zero-downtime + single-writer RocksDB confirmed) then irreversible-but-repostable on-chain /sys/policies/root update. Full runbook: docs/plans/2026-06-29-dnssec-self-authorizing-handoff.md
