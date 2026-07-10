---
# mingo-2rbx
title: 'Phase 4: foreign-domain identities on-chain + federation (needs design)'
status: draft
type: feature
priority: normal
created_at: 2026-07-09T23:40:40Z
updated_at: 2026-07-09T23:41:40Z
parent: mingo-sux8
---

Split out of mingo-ua8w (completed) — the deferred federation/polish bucket. None of this is needed for the checkpoint attestor (live as attestor2@mingo.place); this is about admitting identities from OTHER browserid domains and recording delegation lineage on-chain. Hairy enough to need real design work before implementation — hence draft.

## Items

1. **Foreign-domain identities on-chain.** The validator today binds /sys/names/<name> claims to <local>@<primary-domain> (i.e. @mingo.place). An agent minted at browserid.me is <name>@browserid.me — foreign to the mingo chain. Using it on-chain requires the resolver/controller logic to accept an email-form owner from a non-primary domain: Controller::Email with per-write Auth-Cert + browserid.me DNSSEC Auth-Evidence. NOTE: the broker-certified attribution path this depends on is now working (external-email work + the /sys/dnssec fixes), so the remaining work is validator-side: name-claim/controller resolution for foreign domains and how a foreign-domain name coexists with the local handle namespace.

2. **n4gw trust-policy identities.** Admit identities via a configured trust policy rather than only the primary-domain sovereignty record — generalizes "who counts as a valid identity in this repo."

3. **On-chain parent attribution (optional).** mingo is an RP we control, so writes could be delegation-aware: an agent posts as itself while the ledger also records the parent identity it was delegated from (subordinate_to / cm8z machinery). Plain login to the world, attributable on the ledger.

4. **Retire the handoff note.** Delete docs/notes/browserid-for-agents-handoff.md — the worked hard-path runbook the agent-native flow now supersedes.

## Related
- Parent epic mingo-sux8. Sibling: n4gw. Design context: docs/plans/2026-07-09-agent-native-attestor-plan.md (Option B). Depends conceptually on mingo-jyzt (foreign-domain owner resolution at shared (path,id)).

## Open design questions (why draft)
- How does <name>@browserid.me coexist with <name>@mingo.place and the local handle namespace? Collision rules?
- Can a foreign-domain identity get a key-rooted /sys/names claim, or is it always Controller::Email (per-write cert+evidence)?
- Trust policy: which foreign domains/brokers are admissible, configured where (on-chain /sys/trust vs node config)?
- Parent attribution: on-chain schema + privacy of recording delegation lineage publicly.
