---
# mingo-acmx
title: 'IdP: admin-authed programmatic account+cert provisioning (/admin/provision)'
status: completed
type: feature
priority: high
created_at: 2026-07-07T12:36:52Z
updated_at: 2026-07-07T19:47:40Z
---

Add POST /admin/provision (X-Admin-Token) to mingo-idp: binds handle->external_email AND issues a <handle>@<domain> cert for a supplied pubkey in one call, bypassing the interactive browserid session + SMTP email verification. Enables programmatic/test provisioning of mingo.place identities. Mirrors /cert_key's Certificate::create exactly so the cert is chain-valid. Unblocks the mingo-hqp2 attestor e2e test (provision attestor@mingo.place -> attestor key without email round-trip).

## Built 2026-07-07 (not yet deployed)
Endpoint added + committed + pushed (mingo 9c05f29), builds clean. Deploy path: git push dokku-mingo (the 'mingo' dokku app IS the mingo.place IdP). Needs MINGO_ADMIN_TOKEN set on the app. NOT deployed yet — host SSH temporarily rate-limited after many connections this session.
Remaining to USE it for the attestor e2e: (a) deploy or run mingo-idp locally with the prod IdP keypair; (b) POST /admin/provision {external_email, handle:'attestor', pubkey:attestor1} -> auth_cert; (c) capture DNSSEC auth_evidence for _browserid.mingo.place (sbo domain evidence); (d) assemble identity.email.v1 via claim_email_identity — needs a sbo-cli cert-injection path (create_domain_certified hardwires broker capture) OR a throwaway; (e) submit to chain; then run attestor (full replay) + client to observe threshold-2 promotion.

## VALIDATED end-to-end 2026-07-07
/admin/provision minted a chain-valid cert for attestor@mingo.place -> attestor key. Combined with new sbo-cli 'id create --email --cert' (cert injection + --dry-run), assembled + submitted identity.email.v1 which LANDED + validated on-chain at /sys/names/attestor (block 3584213, owner_ref attestor@mingo.place). Programmatic mingo.place identity provisioning now works without SMTP/broker-password. Feature deployed-locally-verified; PROD deploy of /admin/provision still pending (git push dokku-mingo).
