# Handoff: making browserid / mingo identity agent-native

*Discussion starter, 2026-07-08. Written after a session that provisioned a
service identity (a checkpoint attestor) on mingo.place the hard way. The goal
here is to pick this up with fresh context and decide how an agent (or any
automated service) should acquire and use a browserid-backed identity **without**
a human-in-the-loop email/browser flow.*

## Why this came up

To give an automated attestor an on-chain identity on the mingo.place domain
repo, we had to walk the entire human-oriented browserid ceremony by hand. It
worked, but it took a new IdP endpoint, a new CLI flag, and several dead ends.
That friction is the subject: **agents have a keypair and want to act as a
first-class identity; the current path assumes a human with an inbox and a
browser.**

## How identity works today (the mechanics we confirmed)

Layers:
- **browserid.me broker** (the dokku `id` app): verifies an *external* email via
  **SMTP** (resend), then issues a signed **assertion** for that email.
- **mingo.place primary IdP** (`mingo-idp`, the dokku `mingo` app): takes a
  broker assertion → sets a session → lets you **claim a handle** →
  issues a **cert** for `<handle>@mingo.place` bound to your key. Its signing key
  is published in `_browserid.mingo.place` (DNSSEC).
- **The chain**: an on-chain `/sys/names/<handle>` record is the identity's
  control policy. Writes are authorized by resolving the owner to a controller.

Two identity kinds (`crates/sbo-daemon/src/validate.rs::name_lookup`,
`sbo-core/src/resolve.rs::resolve_controller`):
- **Key-rooted** (`identity.v1`, pubkey in the JWT) → `Controller::Key` →
  writes authorized **by signature**, no per-write cert. *This is what an agent
  wants.*
- **Email-rooted** (`identity.email.v1`, owner_ref = an email) → `Controller::Email`
  → each write must carry a fresh **browserid Auth-Cert** proving the email.

On a **domain repo**, claiming `/sys/names/<handle>` also claims
`<handle>@<domain>`, so the claim write must prove control of that email
(browserid Auth-Cert + DNSSEC Auth-Evidence) — even for a key-rooted record. That
one-time attribution is the gate; after it, a key-rooted record just needs
signatures.

## The friction points for an agent (what actually hurt)

1. **SMTP email verification is a hard wall.** The broker proves an email by
   emailing it. An agent can't receive that. We bypassed it by running the IdP
   locally with the production signing key + a new admin endpoint — not a general
   answer.
2. **Cert issuance requires an authenticated session** (`/cert_key` needs a
   browserid assertion → mingo session). No headless path existed; we added
   `POST /admin/provision` (X-Admin-Token) to seed+issue in one call
   (`mingo-idp/src/routes.rs`). Still admin-gated, still mingo-specific.
3. **Assembling the on-chain identity is a multi-step ritual**: mint cert →
   capture DNSSEC evidence → build `identity.v1`/`identity.email.v1` with
   `Auth-Cert`+`Auth-Evidence` → submit. We added `sbo id create --cert`
   (+`--dry-run`) and a `claim_name_attributed` preset to do it without the
   broker password, but it's ad-hoc.
4. **Key-rooted vs email-rooted is a subtle, load-bearing choice** an agent must
   get right. We first created an email-rooted record and it couldn't authorize
   its own writes (it also hit a real resolver self-loop bug, now fixed —
   `mingo-w41d`). The "right" answer for a service is key-rooted, but nothing
   guides you there.
5. **Cert lifetime**: issued certs are short (24h). Fine for a one-time
   key-rooted claim; a pain for anything email-rooted that must re-attest per
   write.

## Directions to explore (for the fresh-context discussion)

- **A. First-class "agent/service identity" issuance.** Generalize
  `/admin/provision` into a real, authorized, non-SMTP path to a key-rooted
  handle: an agent presents a keypair (and some authorization — admin token,
  delegated capability, or a domain/DNS proof) and gets a claimable handle +
  cert. Decide the authorization model (who may mint, and how it's not just an
  admin backdoor).
- **B. Delegation / subordinate identities.** The IdP already tracks
  `subordinate_to` (a handle's external parent). Could a human grant an agent a
  **subordinate identity** (`agent.dan@mingo.place`?) that the agent controls by
  key, with the human's identity as the attributable parent? This gives
  agent identities provenance without the agent ever touching email.
- **C. DNS/DNSSEC-rooted self-issuance.** An agent that controls a domain (or a
  delegated subdomain) could root an identity in DNSSEC directly — no broker, no
  email. Overlaps with `mingo-n4gw` (DNSSEC-rooted attestors) and the existing
  `_browserid.<domain>` machinery. This may be the cleanest "no human" story.
- **D. Non-email verification challenges in the broker.** Add device-flow /
  proof-of-key / DNS-challenge verification alongside SMTP, so headless clients
  can be verified. Bigger change to browserid.me.
- **E. An SDK / one-shot command.** Whatever the model, collapse the ceremony
  into a single `sbo id provision-agent …` (or SDK call) so agents don't
  re-derive the 5-step ritual. We have the building blocks now.

Design tension to resolve up front: **how much do we want agent identities to be
key-rooted-and-cheap vs. continuously-attributable-to-a-human.** A/C favor
autonomous agents; B favors accountability/provenance. They're not exclusive.

## Pointers

- Code: `mingo-idp/src/routes.rs` (`/admin/provision`, `/cert_key`,
  `/session/from-assertion`, `/claim_handle`), `sbo-core/src/resolve.rs`
  (`resolve_controller`), `crates/sbo-daemon/src/validate.rs` (`name_lookup`,
  name-claim gate ~L714), `crates/sbo-cli/src/commands/identity.rs`
  (`create` / `create_domain_certified`, `--cert`), `sbo-core/src/presets.rs`
  (`claim_name_attributed`, `claim_email_identity`), `sbo-capture` (DNSSEC
  evidence).
- Beans: `mingo-sux8` (full identity model epic — parent for this),
  `mingo-n4gw` (DNSSEC-rooted attestors), `sbo-4arq` (bare key is not an
  identity — the guardrail this must not violate), `sbo-49su` (agent-native
  web-of-trust — sibling idea). This note is not yet a bean; file one under
  `mingo-sux8` when the direction is chosen.
- Precedent from this session: the attestor provisioning is the worked example of
  the current hard path (see `mingo-hqp2`, `mingo-acmx`).
