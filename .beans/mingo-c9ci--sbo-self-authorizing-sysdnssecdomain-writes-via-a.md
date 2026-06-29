---
# mingo-c9ci
title: '[sbo] Self-authorizing /sys/dnssec/<domain> writes via a content-validation policy predicate'
status: in-progress
type: feature
priority: high
created_at: 2026-06-29T14:59:24Z
updated_at: 2026-06-29T15:00:48Z
---

NB: this is **sbo-side** work (repo ~/src/sbo), tracked here because sbo has no beans tracker and this blocks the mingo work.

Motivation: @<domain> attribution requires an on-chain /sys/dnssec/<domain> RFC 9102 proof whose RRSIG window must stay unexpired (attribution window = intersection(cert window, proof window); the proof is the fast-expiring half). Today this object is sys-signed only, so keeping it fresh needs a privileged refresher (cron) and a genesis-emit. We want any writer to refresh it lazily, when they actually need to write — because the proof is self-authenticating (re-verified offline against the pinned IANA root KSK on every replay), it can authorize its own write.

Design (rides the existing policy engine — sbo specs: Policy/Authorization/Genesis). The ONLY net-new primitive is one `require` predicate, in the same family as the existing `require_payload_signed_by` (a payload-content validator). Everything else is policy config.

## Tasks
- [ ] Add a `dnssec_proof` requirement to the policy `require` vocabulary (sbo-core: policy/types.rs + check_requirements in policy/evaluate.rs). When present it enforces THREE guards intrinsically:
  1. Valid chain: payload parses as RFC 9102 and verifies against the pinned IANA root KSK. Reuse verify_rr_stream from attribution.rs (today that runs only at attribution/read time — this moves equivalent validation to write/authorization time).
  2. Domain-binding: extract the domain from the write's CONCRETE target path (last segment of /sys/dnssec/<domain>) and require the proof's _browserid.<name> owner-name to equal it. The predicate sees the real target_path (evaluate() already receives target_path + message), so NO $domain grammar variable is needed. Binding is intrinsic/un-skippable on purpose — a security invariant, not a policy-author choice; an omitted binding is the "valid proof for a different domain" hole.
  3. Monotonic freshness: reject a proof whose RRSIG window is not strictly newer (by expiration) than the currently-stored object's. Blocks rollback/griefing. Stateful (compares to prior object) and distinct from HLC LWW, which would otherwise let a later-submitted OLDER proof win. Lower-severity than 1+2 (worst case = mildly-earlier expiry) and separable — could ship as fast-follow for a minimal v1.
- [ ] Ship the default root policy granting the self-authorizing write (Genesis spec + genesis emission of /sys/policies/root):
      {"to":"*","can":["create","update"],"on":"/sys/dnssec/*","require":{"schema":"dnssec.v1","content_type":"application/octet-stream","dnssec_proof":true}}
      Makes a fresh genesis write-ready with NO /sys/dnssec/<domain> emitted at genesis (first writer populates it). Admins stay sovereign: to tighten to "valid proof AND existing user" they just add the EXISTING `attested` requirement, e.g. require:{...,"attested":{"type":"membership","by":"<domain>"}} — zero new mechanism. To lock down, replace with sys-only. We deliberately do NOT add a non-defeasible floor: policy is sovereign everywhere in sbo, /sys/dnssec is no different.
- [ ] Add a generic daemon DNSSEC query/capture API (READ-ONLY — never submits on-chain). Generic because the proof concept is app-agnostic, so it belongs in the node, not in mingo:
  - report the on-chain proof window for a domain (parse stored /sys/dnssec/<domain>; return null / already-expired flag if absent or stale), and
  - capture fresh proof bytes from live DNS (the part a browser can't do; reuses sbo-capture).
  Clients call this and submit the tx themselves so the WRITE COST is borne by the writer; avoids a second on-chain-writing surface.
- [ ] Spec update (zettels under specs/): document the `dnssec_proof` predicate, its three guards, the intrinsic path-domain binding (no $domain), and the default /sys/dnssec/* policy.

## Spelled-out predicate (keep verbatim)
A write to /sys/dnssec/<domain> satisfies `dnssec_proof` iff ALL of:
1. payload is a valid RFC 9102 proof verified against the pinned IANA root KSK;
2. the proof's owner-name is exactly _browserid.<domain> for the <domain> in the CONCRETE target path;
3. the proof's RRSIG expiration is strictly newer than the stored object's (if any).

## Open micro-decisions
- Domain binding via predicate-internal path derivation (recommended) vs a generic $domain path variable (deferred — add only when a second "content-field == path-segment" use case appears).
- Monotonicity (guard 3) all-in-v1 (recommended) vs fast-follow.
