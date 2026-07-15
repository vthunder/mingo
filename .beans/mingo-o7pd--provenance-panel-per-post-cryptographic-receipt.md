---
# mingo-o7pd
title: 'Provenance panel: per-post cryptographic receipt'
status: completed
type: feature
priority: normal
created_at: 2026-07-15T19:57:49Z
updated_at: 2026-07-15T21:51:01Z
parent: mingo-y9gb
---

Tap a post/comment → drawer showing who signed it (owner identity + signing key), cert issuer chain, warrant when posted via mingo-poster (agent + revocability), block/state-root + pending/confirmed, verifiable inclusion proof. Depends on what /v1/object exposes — may need a daemon tweak to return envelope fields (auth_cert, auth_warrant, signature).

## Recon + design (sbo side)

- Plain /v1/object|/v1/list responses have NO envelope fields. The full signed wire (Signing-Key, Signature, Auth-Cert, Auth-Warrant, Auth-Evidence headers) IS available via ?proof=1: the sboq text embeds the original wire (sboq.rs:48-69, main.rs:265-295). Proof reads serve CONFIRMED objects only; proof binds to current head root, not the confirming block (display honestly).
- Panel plan (client-only, no daemon changes): on tap, fetch /v1/object?path&id&proof=1 → parse sboq → extract embedded wire headers → decode JWS payloads (cert: iss/sub/iat/exp; warrant: iss/agent/aud/scopes) → drawer showing owner identity, signing key, issuer chain, agent+delegator when posted via mingo-poster, block, object_hash, state root, confirmed status. Pending objects: show 'receipt available after confirmation'.
- Stretch: client-side proof verification if sbo-wasm exposes sboq verify.


## Implementation status (mingo-web, 2026-07-15)

- [x] Receipt affordance (🧾, title "cryptographic receipt") on feed rows, thread post, and comments; wired post-render like wireVoteButtons
- [x] Drawer (modal-overlay/.modal.card pattern) with loading + error states; one request per open: /v1/object?path&id&proof=1
- [x] Tolerant sboq parser in app.js (header lines → blank line → single-line proof JSON → embedded wire headers); validated against REAL da.sandmill.org objects (client-signed p-mrb1w3x5 + poster-signed p-mrmgtqy5 in /communities/cooks/)
- [x] Sections: Author (owner + Public-Key, tap-to-copy) / Certified by (Auth-Cert iss→principal.email, iat/exp) / Posted via agent (Auth-Warrant agent, iss, aud, scope chips, exp — poster posts only) / On-chain (confirming block, object hash, honest "proven in state root … at block N (current head)") / Status
- [x] Pending objects: no fetch, drawer shows author + hlc time + "⏳ pending confirmation — full receipt available once on-chain"
- [x] node --check passes; .mono/.scope/.receipt-section CSS added
- [ ] Deploy
- [ ] Verify on a real device (tap-to-copy on mobile Safari, drawer scroll on small screens)

Format facts: wire header is `Public-Key` (not Signing-Key) per sbo wire/serializer.rs; sboq Block/State-Root are the CURRENT head (differ from the object's confirming block); proof JSON never wraps (serializer escapes newlines).

## Restructure per dan's feedback (2026-07-15, uncommitted — review pending)

New drawer structure (validated by running the real app.js functions against both live objects in node):
- Status: '✓ verified · confirmed in block N' (no 'on chain' wording); pending unchanged.
- Author (identity-centric): identity, identity key (from warrant's parent-cert when agent-signed, else the wire key), vouch line distinguishing primary IdP ('mingo.place — the identity's own provider — certified…') vs fallback ('browserid.me — a fallback certifier — vouched for X, whose domain gmail.com doesn't run its own identity provider'), cert validity dates, DNSSEC anchor link to /sys/dnssec/<iss> on the daemon, and 'posted directly by the author from their own browser' when client-signed.
- Posted by (agent path only): agent email '(an agent, not the author)', agent signing key, agent's own vouch line, then 'authorized by the author' — warrant sentence (author → grants → agent), validity, audience, scope chips.
- Who did what: one derived sentence per party actually involved (author's certifier, agent's certifier, author-signed warrant, mingo the app as operator/submitter, data layer recording + proof).
- Record (renamed from On-chain): full path+id (mono), schema, authored time, object hash, and 'inclusion proof computed against the current state root … (block M) — Merkle proof ↗' linking to the ?proof=1 URL. Also DNSSEC/'Merkle proof' links open the daemon's raw JSON (.rlink style added).

Key fact discovered: the warrant payload carries the AUTHOR's cert as the `parent-cert` claim (JWS; payload iss/principal.email/public-key.publicKey/iat/exp) — that's what lets the Author section show its own vouching line on agent-signed posts. Verified live: p-mrmgtqy5's parent-cert iss=browserid.me for vthunder@gmail.com (fallback path), top cert iss=mingo.place for mingo-poster (primary path).

## Summary of Changes

Shipped receipt v1 then v2 (identity-centric per dan's review): status without 'on chain', Author with own-key + voucher (primary vs fallback wording, DNSSEC link), Posted-by with directional warrant grant, per-party 'Who did what' ledger, Record with path/schema/authored time/Merkle-proof link. Validated against live client-signed, poster-signed, external-author, and digest-bot objects.
