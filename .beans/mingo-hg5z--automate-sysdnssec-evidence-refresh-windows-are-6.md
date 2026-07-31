---
# mingo-hg5z
title: Automate /sys/dnssec evidence refresh (windows are ~6 days; manual refresh already lapsed once)
status: completed
type: task
priority: normal
created_at: 2026-07-31T08:24:43Z
updated_at: 2026-07-31T09:08:43Z
---

2026-07-31: attribution of every email-rooted write on the live chain broke silently because /sys/dnssec/mingo.place's RRSIG window expired (~39h stale) and /sys/dnssec/bsky.browserid.me was absent — surfaced as 'signer carries no valid attribution' on the first me@<handle> live test (which was itself innocent). GENESIS.md warned proofs expire and asked for a refresher.

Done now: mingo-app/src/bin/dnssec-refresh.rs — no-key, cron-friendly (daemon captures proof via /v1/dnssec, throwaway-signed self-authenticating submit). Manual run refreshed mingo.place + bsky.browserid.me + confirmed browserid.me fresh.

Remaining decision + work: WHERE it runs on a schedule. RRSIG windows observed ~5.8 days, so it needs to run at least every ~4 days. Options: (a) host cron on sandmill.org running the binary (needs it in the deploy image or a copied binary), (b) the daemon self-refreshing on a timer (cleanest, but sbo-daemon writing to its own chain needs design), (c) launchd on the dev Mac (fragile — laptop). Also worth a monitoring hook: alert when any pinned issuer's on-chain window has <48h left.

## Direction change (2026-07-31, per user): NO cron — on-demand refresh at write time

The on-demand machinery already existed; the real bug was that it ensured only ONE issuer:

- mingo-idp poster.rs submit: ensured only the CONFIG cert's issuer (the user's — e.g. browserid.me), never the poster's own access-cert issuer (mingo.place). Same-issuer grants masked it; the first cross-issuer grant (broker-rooted me@<handle> user) hit the stale mingo.place proof. FIXED: presentation_issuers() ensures every distinct issuer (access + config), unit-tested.
- mingo-app CLI post: had NO ensure at all. FIXED: sign_as_logged_in_user returns the presentation's issuers; post ensures each before submit.
- mingo-web SPA: already correct for its case (browser self-signing is always same-issuer; it ensures the access cert's issuer).
- mingo-app/src/bin/dnssec-refresh stays as a manual ops tool, not a cron.

Remaining (optional): surface EvidenceWindowMismatch distinctly in the daemon error instead of the generic 'no valid attribution'.

## Summary of Changes

Shipped in 38f5859 + 4fbd06e (deployed to mingo.place via dokku):
- mingo-idp poster: presentation_issuers() — every distinct issuer (access + config cert) gets an on-demand /sys/dnssec ensure before submit; unit test covers cross-issuer (broker-rooted me@<handle> grantor) and same-issuer dedup.
- mingo-app CLI post: previously no ensure at all; now ensures each presentation issuer before --execute submit.
- mingo-web SPA: unchanged — browser self-signing is always same-issuer and it already ensured the access cert's issuer.
- bin/dnssec-refresh: manual ops tool only. NO cron, per decision: freshness is guaranteed at write time by whoever writes.

Left open elsewhere: daemon could surface EvidenceWindowMismatch instead of the generic 'no valid attribution' (noted, no bean).
