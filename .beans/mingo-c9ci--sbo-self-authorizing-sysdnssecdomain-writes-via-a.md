---
# mingo-c9ci
title: '[sbo] Self-authorizing /sys/dnssec/<domain> writes via a content-validation policy predicate'
status: in-progress
type: feature
priority: high
created_at: 2026-06-29T14:59:24Z
updated_at: 2026-06-30T22:06:08Z
blocked_by:
    - mingo-stho
---

NB: this is **sbo-side** work (repo ~/src/sbo), tracked here because sbo has no beans tracker and this blocks the mingo work.

Motivation: @<domain> attribution requires an on-chain /sys/dnssec/<domain> RFC 9102 proof whose RRSIG window must stay unexpired (attribution window = intersection(cert window, proof window); the proof is the fast-expiring half). Today this object is sys-signed only, so keeping it fresh needs a privileged refresher (cron) and a genesis-emit. We want any writer to refresh it lazily, when they actually need to write — because the proof is self-authenticating (re-verified offline against the pinned IANA root KSK on every replay), it can authorize its own write.

Design (rides the existing policy engine — sbo specs: Policy/Authorization/Genesis). The ONLY net-new primitive is one `require` predicate, in the same family as the existing `require_payload_signed_by` (a payload-content validator). Everything else is policy config.

## Tasks
- [x] Add a `dnssec_proof` requirement to the policy `require` vocabulary (sbo-core: policy/types.rs + check_requirements in policy/evaluate.rs). When present it enforces THREE guards intrinsically:
  1. Valid chain: payload parses as RFC 9102 and verifies against the pinned IANA root KSK. Reuse verify_rr_stream from attribution.rs (today that runs only at attribution/read time — this moves equivalent validation to write/authorization time).
  2. Domain-binding: extract the domain from the write's CONCRETE target path (last segment of /sys/dnssec/<domain>) and require the proof's _browserid.<name> owner-name to equal it. The predicate sees the real target_path (evaluate() already receives target_path + message), so NO $domain grammar variable is needed. Binding is intrinsic/un-skippable on purpose — a security invariant, not a policy-author choice; an omitted binding is the "valid proof for a different domain" hole.
  3. Monotonic freshness: reject a proof whose RRSIG window is not strictly newer (by expiration) than the currently-stored object's. Blocks rollback/griefing. Stateful (compares to prior object) and distinct from HLC LWW, which would otherwise let a later-submitted OLDER proof win. Lower-severity than 1+2 (worst case = mildly-earlier expiry) and separable — could ship as fast-follow for a minimal v1.
- [x] Ship the default root policy in genesis (mingo genesis.rs, branch feat/self-authorizing-dnssec-policy). NB: LIVE chain still needs a posted /sys/policies/root update — see handoff.
      {"to":"*","can":["create","update"],"on":"/sys/dnssec/*","require":{"schema":"dnssec.v1","content_type":"application/octet-stream","dnssec_proof":true}}
      Makes a fresh genesis write-ready with NO /sys/dnssec/<domain> emitted at genesis (first writer populates it). Admins stay sovereign: to tighten to "valid proof AND existing user" they just add the EXISTING `attested` requirement, e.g. require:{...,"attested":{"type":"membership","by":"<domain>"}} — zero new mechanism. To lock down, replace with sys-only. We deliberately do NOT add a non-defeasible floor: policy is sovereign everywhere in sbo, /sys/dnssec is no different.
- [ ] (REMAINING) Add a generic daemon DNSSEC query/capture API (READ-ONLY — never submits on-chain). Generic because the proof concept is app-agnostic, so it belongs in the node, not in mingo:
  - report the on-chain proof window for a domain (parse stored /sys/dnssec/<domain>; return null / already-expired flag if absent or stale), and
  - capture fresh proof bytes from live DNS (the part a browser can't do; reuses sbo-capture).
  Clients call this and submit the tx themselves so the WRITE COST is borne by the writer; avoids a second on-chain-writing surface.
- [ ] (REMAINING) Spec update (zettels under specs/): document the `dnssec_proof` predicate, its three guards, the intrinsic path-domain binding (no $domain), and the default /sys/dnssec/* policy.

## Spelled-out predicate (keep verbatim)
A write to /sys/dnssec/<domain> satisfies `dnssec_proof` iff ALL of:
1. payload is a valid RFC 9102 proof verified against the pinned IANA root KSK;
2. the proof's owner-name is exactly _browserid.<domain> for the <domain> in the CONCRETE target path;
3. the proof's RRSIG expiration is strictly newer than the stored object's (if any).

## Open micro-decisions
- Domain binding via predicate-internal path derivation (recommended) vs a generic $domain path variable (deferred — add only when a second "content-field == path-segment" use case appears).
- Monotonicity (guard 3) all-in-v1 (recommended) vs fast-follow.


## Progress 2026-06-29
DONE (sbo branch feat/self-authorizing-dnssec-writes, commit 2c3d4d8): predicate impl + guards 1+2 + tests, sbo-core + sbo-daemon build green. DONE (mingo branch feat/self-authorizing-dnssec-policy, ccaa577): default genesis policy.
REMAINING: daemon /v1/dnssec read+capture API (needs RepoApi raw-bytes getter — ObjectView.payload_text is lossy UTF-8, unusable for the binary proof; capture half needs sbo-capture as a new daemon dep), guard-3 monotonicity, spec zettels, LIVE deploy. See docs/plans/2026-06-29-dnssec-self-authorizing-handoff.md.


## Update 2026-06-29 (later)
DONE: shared sbo policy fragment (presets::dnssec_self_auth_policy_entries, commit aca8b9e); daemon GET /v1/dnssec read+capture API (commit e276ac6, sbo-capture added as daemon dep, base64url response, timestamp-gated via needed_by+margin). sbo-daemon builds + http tests green. Remaining on sbo side: guard-3 monotonicity (deferred), spec zettels. Client side = mingo-3sle (in progress).


## ROOT CAUSE (2026-06-30): daemon was in genesis mode
The deployed daemon accepted ALL /sys/dnssec writes (garbage, wrong-domain, non-admin) NOT because the dnssec_proof predicate was wrong, but because check_root_policy_exists looked up /sys/policies/root with a hardcoded creator "sys". This Mode-B genesis has an EMAIL-rooted sys identity, so the root policy object creator is "sys@mingo.place" — the lookup missed it and the daemon fell into genesis mode (accept-all, ZERO policy enforcement chain-wide, exposed by the genesis-anchored-identity sbo upgrade). Fix (sbo 8c78a4c): check_root_policy_exists uses get_first_object_at_path_id (creator-agnostic). Proven via full-path validate_message regression test. The dnssec_proof predicate itself was correct all along.


## Status 2026-07-01: code DONE + enforcement fix verified live; feature activation BLOCKED by [[mingo-stho]]
CRITICAL fix shipped: the daemon was in genesis mode (no policy enforcement) due to check_root_policy_exists hardcoding creator "sys" vs the email-rooted sys@mingo.place — fixed in sbo 8c78a4c (merged main, deployed). VERIFIED LIVE: daemon log shows "Policy denied Create on /sys/dnssec/ ... No matching grant"; predicate + full-path regression test pass. dnssec_proof predicate, daemon /v1/dnssec API, shared policy fragment, and mingo client lazy-refresh all merged. Live policy currently reverted (safe). Re-applying the feature policy is pending because [[mingo-stho]] (sync stall) prevents new writes from confirming. Once sync is healthy: re-post feature policy, verify valid-accepted/garbage-denied, restore mingo.place to sys control, delete junk /sys/dnssec test objects (enftest*, dbgtest*, randtest.example, evil.example, test.invalid, finaltest.example).
