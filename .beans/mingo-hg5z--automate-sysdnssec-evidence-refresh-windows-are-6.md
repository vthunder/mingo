---
# mingo-hg5z
title: Automate /sys/dnssec evidence refresh (windows are ~6 days; manual refresh already lapsed once)
status: todo
type: task
created_at: 2026-07-31T08:24:43Z
updated_at: 2026-07-31T08:24:43Z
---

2026-07-31: attribution of every email-rooted write on the live chain broke silently because /sys/dnssec/mingo.place's RRSIG window expired (~39h stale) and /sys/dnssec/bsky.browserid.me was absent — surfaced as 'signer carries no valid attribution' on the first me@<handle> live test (which was itself innocent). GENESIS.md warned proofs expire and asked for a refresher.

Done now: mingo-app/src/bin/dnssec-refresh.rs — no-key, cron-friendly (daemon captures proof via /v1/dnssec, throwaway-signed self-authenticating submit). Manual run refreshed mingo.place + bsky.browserid.me + confirmed browserid.me fresh.

Remaining decision + work: WHERE it runs on a schedule. RRSIG windows observed ~5.8 days, so it needs to run at least every ~4 days. Options: (a) host cron on sandmill.org running the binary (needs it in the deploy image or a copied binary), (b) the daemon self-refreshing on a timer (cleanest, but sbo-daemon writing to its own chain needs design), (c) launchd on the dev Mac (fragile — laptop). Also worth a monitoring hook: alert when any pinned issuer's on-chain window has <48h left.
