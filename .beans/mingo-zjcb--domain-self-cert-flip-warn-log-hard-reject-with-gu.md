---
# mingo-zjcb
title: 'Domain self-cert: flip warn-log -> hard-reject (with guards)'
status: todo
type: task
priority: normal
created_at: 2026-07-04T14:57:50Z
updated_at: 2026-07-04T14:58:00Z
blocked_by:
    - mingo-2xnj
---

The daemon's domain.v1 DNSSEC self-cert check (sbo-daemon sync.rs, verify_domain_self_cert) is currently **warn-log** (non-fatal), per the safe-rollout plan. It's now verified passing live (regenesis B=3567386: 'Domain mingo.place self-certified'). Flip it to a hard reject so a domain.v1 whose self-cert is present-but-fails is rejected.

## Guards (from the security review, mingo-d7bi/m6z7)
- inclusion_time == None → **skip, not reject** (e.g. non-DA-anchored / early backfill).
- Only reject when the domain object DECLARES evidence (Auth-Evidence ref present) and it fails; absence of a ref → plain self-signed fallback (do not reject).
- Verify the JWT's inner public_key equals the envelope signing_key (a hard-reject path shouldn't trust only the envelope key).
- Since binding is via Auth-Evidence ref to the exact /sys/dnssec/<domain> leaf resolved as-of the block, the shadowing/overwrite concern is already addressed.

## Where
sbo-daemon/src/sync.rs domain.v1 branch (currently tracing::warn on SELF-CERT FAILED) and/or move enforcement into validate.rs so a failing genesis block is refused. Needs SBO_REV bump + (ideally) a regenesis or at least a daemon redeploy to take effect. Blocked-by the e2e test.
