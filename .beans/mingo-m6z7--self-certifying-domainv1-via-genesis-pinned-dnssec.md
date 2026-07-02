---
# mingo-m6z7
title: Self-certifying domain.v1 via genesis-pinned DNSSEC proof
status: in-progress
type: feature
priority: normal
created_at: 2026-07-02T20:47:48Z
updated_at: 2026-07-02T21:48:03Z
---

Make the on-chain domain root-of-trust (/sys/domains/<D>, currently a self-signed JWT iss:self with NO DNS-control proof) verifiable from on-chain state alone, so genesis self-certifies domain authority and a client can verify with zero trust in the _sbo publisher.

## Decision (2026-07-02)
Go all-in on DNSSEC (already required for browserid). Use **point-in-time semantics (option i)**: the domain object is written ONCE at genesis, and verification checks inclusion_time ∈ RRSIG window (attribution.rs). Genesis inclusion_time is a fixed historical instant, so ONE genesis-embedded RFC-9102 proof whose RRSIG window brackets the genesis block verifies the domain FOREVER — **no periodic RRSIG refresh needed** (unlike browserid user attribution / mingo-b763, which refreshes because users keep making new writes). Liveness/revocation (option ii) is explicitly out of scope — a genesis-pinned root doesn't promise ongoing liveness.

## Work
1. **DNS**: publish the domain root-of-trust key (ed25519:8ef0381e… for mingo.place) in a DNSSEC-signed record — extend _sbo or add a dedicated record. (Distinct from _browserid.<D>, which carries the browserid PROVIDER key.)
2. **Verifier**: variant of extract_provider_key / verify_dnssec_proof_for_domain (sbo-core/src/attribution.rs:225) that binds THAT record's key, not the _browserid key.
3. **Carry the proof on-chain**: embed the genesis-time RFC-9102 proof in domain.v1's payload OR a companion genesis object. NOTE /sys/dnssec/<D> is already used for the browserid proof — use a distinct path/id to avoid collision.
4. **Genesis + validation**: mingo genesis captures the proof at build time (RRSIG window must cover the genesis block time — fine, genesis lands within minutes); daemon verifies domain.v1 against it at sync. Non-fatal-log vs hard-fail TBD.
5. Requires a regenesis to take effect on the live chain (domain.v1 is genesis-immutable).

## Threat model motivating this
Federated / hand-someone-just-appId@block/genesisHash verification, and closing the plain-DNS _sbo-spoof gap. Single-operator Mingo works fine without it today; this is the correctness/federation upgrade.

Related: [[dnssec-self-authorizing-writes]], mingo-b763 (user attribution refresh).

## Refined design (2026-07-02): reuse the _browserid key, no new DNS record

KEY DECISION: unify the domain root-of-trust key with mingo's _browserid PROVIDER key (e021fda4 = _browserid.mingo.place, DNSSEC-proven, mingo-owned — NOT the browserid.me broker key oBxScFH3). Drop the separate mingo-domain key (8ef0381e) at the next regenesis.
- Why safe under (i): the domain key's only jobs (sign domain.v1, certify sys) happen ONCE at genesis and are immutable; sys runs under 564aafe4 afterward. A later e021fda4 compromise can't rewrite genesis → zero new post-genesis risk beyond existing browserid exposure.
- Reuses existing proof + verifier: extract_provider_key / verify_dnssec_proof_for_domain (attribution.rs:225) already pull e021fda4 from the _browserid.<domain> proof. New verification = confirm extracted key == domain.v1 public_key AND genesis inclusion_time ∈ RRSIG window. NO new DNS record, NO new verifier variant.
- MUST verify against the on-chain-MIRRORED genesis proof, never live DNS (so provider-key rotation doesn't break historical verification).
- Alt considered: design C (keep cold 8ef0381e, cross-signed once by e021fda4). Preserves hot/cold separation but adds a cross-cert. Leaning unify (A).
- Operational cost of A: genesis ceremony must sign domain.v1 + sys cert with the IDP production key (e021fda4).

## Spec changes required (this REVERSES an existing MUST-NOT)
1. Identity spec 'Domain Objects (domain.v1)' (SBO Identity Specification.md:252): prose + new Validation Rule 4 (domain key certified by mirrored proof, RRSIG window brackets genesis inclusion time). **Two senses of domain table (:274)** — revise 'distinct keys' + 'never mirrored on chain' + Trust cell → 'DNSSEC-proven at genesis (point-in-time)'.
2. Genesis spec (:401): 'never stored on chain' note becomes false for root domain; Mode B gains capture+mirror of _browserid proof, sign with proven key.
3. Authorization/Attribution spec: note verify_dnssec_proof_for_domain now also certifies the domain root key at genesis (point-in-time).
4. State Commitment spec: domain authority verifiable from snapshot/state alone (proof in state, covered by root).
5. Deferred note (Identity+Genesis): post-genesis lapse/transfer/revocation (liveness) explicitly OUT of scope — point-in-time-at-genesis only.

## Carrying the proof on-chain
Embed the genesis-time RFC-9102 proof in domain.v1 payload OR a companion object. NOTE /sys/dnssec/<D> already used for the browserid user-attribution proof — if reusing that path, use a distinct id, else a new path. (Same proof bytes may serve both since it's the same _browserid record — de-dup opportunity.)

## Proposal drafted
Full proposal (spec diffs for 5 sections + core→daemon→genesis impl plan) committed to sbo branch `docs/domain-self-certification`: specs/proposals/domain-self-certification.md. Review gate before applying normative spec edits + implementing.

## Implementation progress (2026-07-02 overnight) — code-complete, ceremony-pending

Spec + code landed on feature branches (NOT deployed; activation needs a supervised regenesis with the real _browserid provider key + captured DNSSEC chain).

**sbo `feat/domain-self-certification`** (pushed):
- Applied all 5 spec edits to the normative specs (Identity/Genesis/Authorization/State Commitment).
- sbo-core: `verify_domain_self_cert` + offline-testable `check_domain_binding` (attribution.rs); 3 new tests pass.
- sbo-daemon: domain.v1 self-cert check on apply in sync.rs (locate /sys/dnssec/<domain> evidence → verify against inclusion time), **warn-log** for now.
- Proposal doc at specs/proposals/domain-self-certification.md.

**mingo `feat/domain-self-certification`** (pushed):
- mingo_genesis gains optional domain_dnssec_evidence → seeds dnssec.v1 at /sys/dnssec/<domain> before domain.v1; CLI `--dnssec-evidence`. Additive (None = plain Mode B). New test passes.

All builds green; sbo-core + sbo-daemon full suites pass.

### Remaining before activation (ceremony, needs Dan)
1. Import the mingo _browserid provider secret (e021fda4) into the keyring as an alias (e.g. mingo-provider), OR delegated-sign at genesis. [security review]
2. Capture the _browserid.mingo.place DNSSEC chain (RFC-4034 wire) — reuse the tool that produces user-attribution /sys/dnssec proofs. RRSIG window must bracket the genesis block time.
3. Flip the daemon check from warn-log to hard-reject (validate.rs) once verified live.
4. Batched regenesis: run `mingo genesis --domain-key mingo-provider --dnssec-evidence <file> …`, submit, reseed entrypoint, deploy, update _sbo DNS. Optionally restore roles.admin:["sys"] (spec form; email/key already work).
5. Decide: enforce self-cert REQUIRED for Mode B, or keep optional (default: optional in spec, always-emitted by Mingo).
