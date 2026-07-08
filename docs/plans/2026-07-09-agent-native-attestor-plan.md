# Plan — Agent-native browserid for the SBO checkpoint attestor

**Date:** 2026-07-09
**Status:** Plan for review (no code yet)
**Beans:** mingo-ua8w (this plan), mingo-02ta (go-live), parent mingo-sux8
**Upstream:** browserid-ng `l8lw` shipped 2026-07-08/09 — provisioning +
grant-exchange REST spec (`browserid-ng/docs/specs/agent-provisioning-and-grant-api.md`),
broker implementation (deployed to browserid.me with `AGENT_PROVISIONING=1`),
`browserid-agent` SDK crate, `browserid-rp` crate.

## Goal

Retire the hard provisioning path (admin-token `/admin/provision` + the manual
5-step ceremony recorded in `docs/notes/browserid-for-agents-handoff.md`,
mingo-acmx/hqp2) and get a **live checkpoint attestor** (mingo-02ta) whose
identity is minted the agent-native way: human mints an API key once, the
attestor provisions its own key-rooted, attributed identity headlessly, and
signs attestations with plain signatures forever after.

## The key decision: which IdP mints the attestor's identity

### Option A (recommended): mingo-idp implements the provisioning spec

The attestor's identity is **`<name>@mingo.place`** — local to the domain
repo — so the entire existing on-chain machinery works unchanged:

- `/sys/names/<name>` key-rooted claim (`identity.v1`) proving control of
  `<name>@mingo.place` via browserid Auth-Cert + DNSSEC Auth-Evidence — the
  gate that already exists (`validate.rs` name-claim, ~L714).
- After the one-time claim: `Controller::Key` → attestation writes are
  authorized **by signature alone** (`build_attestation_wire` already sets
  `owner = attestor, auth_cert: None`).
- `_browserid.mingo.place` DNSSEC is already published; no new trust anchors.

mingo-idp is a natural second implementation of the federation spec (which is
exactly what l8lw Phase 3 wanted validated): it already has accounts with
`external_email` (the attribution root, cm8z `subordinate_to` machinery),
sqlite, sessions, and cert issuance. What's missing is only the API surface.

### Option B (follow-up, not the critical path): browserid.me agent identities

browserid.me now mints agent identities today (`<name>@browserid.me`), but
using one on-chain is blocked on **foreign-domain identity support** in the
validator (`/sys/names` claims currently bind to `<local>@<primary-domain>`;
an email-form owner would be `Controller::Email` → per-write auth-certs +
browserid.me DNSSEC evidence, heavier attestations, and n4gw trust-policy
work). That's the federation story — file it separately; don't couple the
attestor to it.

## Phases

### Phase 1 — mingo-idp: implement provisioning API (spec §4)

- `api_keys` table: `account_id`, `key_hash` (SHA-256 of `bidk_…` secret,
  shown once), `name`, `created_at`, `last_used_at`, `revoked_at`.
  Attribution root = the account's `external_email` (already recorded).
- `agent_identities` table: `name` (UNIQUE, shares the handle namespace —
  collision-checked against `accounts.handle`), `account_id`, `revoked_at`.
- Routes per spec §4.2–4.5: `POST /agent/identities` (idempotent
  re-provision), `POST /agent/cert`, `GET /agent/identities`,
  `POST /agent/identities/revoke`. Bearer-key gated; per-account quota
  (default 5); spec's status-code contract (401/403/404/409/429) including
  the 404 anti-enumeration rule.
- Key minting (spec §4.1, IdP-local): session+CSRF-gated
  `POST /agent_keys` + list/revoke; curl-able, UI later.
- Conformance check: run the `browserid-agent` SDK e2e flow against
  mingo-idp in a test (git dep on browserid-ng crates).
- `/admin/provision` stays for genesis/admin seeding but is no longer the
  agent path; mark it deprecated in routes.rs docs.

### Phase 2 — one-shot attestor provisioning (sbo repo)

New `sbo id provision-agent --idp https://mingo.place --name <name>`
(API key from `SBO_AGENT_API_KEY`), built on the `browserid-agent` crate:

1. `AgentIdentity::provision(idp, api_key, name)` — agent generates/keeps
   its own keypair; IdP returns `<name>@mingo.place` + cert. Persist with the
   SDK's identity file (never contains the API key).
2. Capture DNSSEC Auth-Evidence for `_browserid.mingo.place` (`sbo-capture`).
3. Build the **key-rooted** on-chain claim:
   `claim_name_attributed(signing_key, name, auth_cert, auth_evidence)`
   with the fresh cert as Auth-Cert; submit via turbo.
4. Idempotent: name already claimed by this key → no-op; cert expired →
   `/agent/cert` re-mint (the API key is the standing credential).

After the claim the daemon needs **no browserid at runtime** — attestations
are signature-authorized. Guardrail sbo-4arq holds: the identity is
API-key-minted and attributed upstream (quota + `parent_email`), never a
bare key.

Daemon wiring: `[attest]` config unchanged (`key_file` + `attestor`);
entrypoint gains the provision-if-needed step (reads the SDK identity file or
provisions on first boot), replacing the `SBO_ATTEST_KEY` hand-seeding.

### Phase 3 — go live (mingo-02ta)

- Deployment choice from 02ta: start **co-located on da.sandmill.org**
  (validates produce→serve→consume live). The identity is *distinct from
  sys-checkpointer* by construction — it's a fresh agent identity — which was
  02ta's hard requirement. Operational independence (a full-replay attestor
  node elsewhere) becomes cheap later precisely because provisioning is now
  one command + one env var.
- Flip `[attest] enabled = true` with the new identity; watch
  `checkpoint-attestation.v1` objects flow; verify a fast-sync client with
  `{attestors: [<attestor key>], threshold: 1}` counts the backer.

### Phase 4 — follow-ups (separate beans, not this plan)

- Foreign-domain identities on-chain (`@browserid.me` agents) — remainder of
  mingo-ua8w's original scope; enables Option B.
- mingo-n4gw: email-rooted attestors in fast-sync trust policy (pin
  identities, not keys).
- Optional on-chain parent attribution (mingo as a delegation-aware RP).
- Retire `docs/notes/browserid-for-agents-handoff.md` once Phase 2 lands.

## Risks / open questions

- **Handle vs agent-name namespace**: agent identities share
  `@mingo.place` with human handles; Phase 1 must enforce one namespace
  (unique across both tables) or squatting/collision follows.
- **Cert validity window at claim time**: the on-chain claim embeds a 24 h
  cert as Auth-Cert; validators check it at claim validation time — fine for
  a fresh mint, but the provision command should always re-mint immediately
  before claiming.
- **Quota for service accounts**: the operator account minting the attestor
  key is a normal account; default quota (5) is plenty for now.
- **API key custody on the host**: dokku config env (`SBO_AGENT_API_KEY`),
  same custody class as the existing `SBO_CHECKPOINT_KEY`; revocable at the
  IdP, which the old raw-key scheme never was.
