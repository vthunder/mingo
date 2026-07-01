---
# mingo-b763
title: Auth-Evidence RRSIG refresh for @mingo.place writes
status: scrapped
type: task
priority: normal
tags:
    - identity
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-30T22:05:51Z
---

The on-chain /sys/dnssec/mingo.place auth-evidence (RFC-9102 RRSIG) goes stale as signatures expire. Add periodic refresh so @mingo.place writes keep attributing. CLI: 'sbo domain evidence'.

## Reasons for Scrapping
Superseded by the lazy, client-driven, self-authorizing design in [[mingo-c9ci]]/[[mingo-3sle]]. We explicitly rejected the periodic/cron refresh approach this bean proposes in favor of clients submitting a fresh proof on their own writes (gated by the new dnssec_proof policy predicate). The on-chain refresh path now exists; no separate periodic job is wanted.
