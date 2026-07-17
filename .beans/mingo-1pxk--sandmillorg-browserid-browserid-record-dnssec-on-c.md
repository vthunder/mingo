---
# mingo-1pxk
title: 'sandmill.org browserid: _browserid record + DNSSEC + on-chain /sys/dnssec/sandmill.org evidence'
status: todo
type: task
created_at: 2026-07-17T11:37:01Z
updated_at: 2026-07-17T11:37:01Z
---

Prerequisite for email-rooted admin (danmills@sandmill.org). To attribute a danmills@sandmill.org write on the mingo chain, the daemon needs an on-chain RFC 9102 DNSSEC proof at /sys/dnssec/sandmill.org (mirrors what mingo.place has), and sandmill.org must have a _browserid record + DNSSEC.

## User-dependent (DNS access to sandmill.org)
- [ ] Enable DNSSEC on sandmill.org (registrar/DNS provider).
- [ ] Add `_browserid.sandmill.org` TXT record naming the browserid provider (browserid.me), so danmills@sandmill.org is browserid-attributable via the pinned broker.
- [ ] Verify/register danmills@sandmill.org at browserid.me.

## Chain step (reuses existing tooling)
- [ ] `sbo domain evidence sandmill.org --key <signer> --out sandmill-dnssec.wire` (captures the RFC 9102 proof; same command used for mingo.place), submit to the daemon. The write to /sys/dnssec/** is self-authorizing (dnssec_proof policy), so any signer works.
- [ ] Keep it fresh (RRSig expiry) like mingo.place — cron/automate.

Once this is live, an admin op attributed to danmills@sandmill.org will resolve; then proceed with the admin migration.
