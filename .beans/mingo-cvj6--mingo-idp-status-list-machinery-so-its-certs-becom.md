---
# mingo-cvj6
title: 'mingo-idp: status-list machinery so its certs become revocable (device-revoke endpoint)'
status: todo
type: feature
created_at: 2026-08-02T23:31:35Z
updated_at: 2026-08-02T23:31:35Z
---

Follow-up to browserid-ng-ft55. mingo-idp issues certs with status: None — no status list exists, so mingo.place certs are structurally irrevocable until expiry (90d), and the broker's /account now shows the honest 'issuer offers no revocation endpoint' message for them.

Work: (1) per-identity status allocation on issuance + /.well-known/browserid-status signed list (copy the bridge's idp_status pattern — the bridge was adapted FROM mingo-idp, so this ports back cleanly); (2) GET /idp/revoke-device page + session-scoped POST (mirror bridge ad1a961), advertised via the support document's device-revoke field (browserid-core 4a0daed); (3) verifiers already check cert status refs fail-closed, so refs start working the moment they appear on new certs.
