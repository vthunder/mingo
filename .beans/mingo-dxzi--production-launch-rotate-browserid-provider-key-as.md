---
# mingo-dxzi
title: 'Production launch: rotate _browserid provider key as final ceremony step'
status: todo
type: task
priority: deferred
created_at: 2026-07-04T14:57:51Z
updated_at: 2026-07-04T14:57:51Z
---

For the CURRENT testing chain we reused the mingo _browserid provider key (e021fda4) directly as the domain root key and did NOT rotate afterward. When we launch a REAL production chain, rotate _browserid.<domain> to a fresh provider key as the final ceremony step: because domain self-cert is point-in-time, the genesis-time proof for the old key stands forever, so rotating neutralizes any residual exposure from having used the key at genesis, with zero effect on the (immutable) self-cert. Steps: mint new provider key -> update _browserid.<domain> DNS -> idp signs future certs with it. Documented in sbo specs/proposals/domain-self-certification.md (Prerequisite/Production-launch note). This bean is the reminder so we don't forget.
