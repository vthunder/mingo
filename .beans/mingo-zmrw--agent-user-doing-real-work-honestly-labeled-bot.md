---
# mingo-zmrw
title: 'Community bot: on-chain-governed, warrant-authorized LLM poster'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T00:26:19Z
updated_at: 2026-07-16T11:23:42Z
parent: mingo-y9gb
---

A visible, honestly-labeled agent that does REAL work in the forum — demoing the agent-delegation machinery (warrants, agent certs) live, and providing genuine lived-in content WITHOUT fake identities (per the identity-honesty principle: no synthetic personas; a bot doing real work is honest).

## Candidates
- A digest bot that posts a weekly roundup / summarizes long threads. Real content (summaries of actual posts), clearly badged 🤖, acting under a real warrant.
- The bot posts under an agent identity (e.g. digest-bot@mingo.place) via an author-signed warrant — the same agent-write path mingo-poster uses; its receipt shows 'signed by digest-bot on behalf of <community/owner> under warrant …'.

## Why it fits now
- The provenance panel already renders the agent/warrant story; an agent user makes it live rather than hypothetical.
- Ties to warrants + passport (the bot could be vouched-for / carry a badge).
- Contrast with the wiped synthetic corpus: this is real work by a labeled agent, which is the honest way to get 'lived-in' + a live delegation demo. See memory identity-honesty-in-demo-tooling.
- Decide who the bot delegates FROM (a community owner? the app operator?) and what it's authorized to do (post digests only — narrow scopes).

## Autonomous-run note (2026-07-16) — deferred, needs you
Skipped overnight: standing up the agent needs a real author-signed WARRANT (who does the bot delegate from?), and warrant approval is an interactive consent step (the /consent Approve tap) — can not be done without you. Also little content to digest on the fresh chain yet. Recommend: once there is activity, decide the delegator + narrow scopes (post digests only) and approve the warrant together; the agent-write plumbing (agent cert + warrant) already exists and is proven.


## Refined scope (dan, 2026-07-16) — 'community bot', NOT a generic digest bot
A per-community bot that:
- runs automatically on a tick,
- uses an LLM,
- its PROMPTS live ON CHAIN and are GOVERNED BY THE COMMUNITY (the board admins control them),
- its posts are VERIFIABLY AUTHORIZED via a WARRANT signed by the board admin(s) — delegator = board owner/admin,
- ideally provides a GUARANTEE that the on-chain prompts were the ones actually used to generate the post,
- has UI affordances distinguishing the poster as a robot (🤖 tag on byline, distinct card treatment, receipt shows the agent+warrant+prompt provenance).

## Prerequisites (ordered)
1. **Explicit admins** — today board admin/ownership is hand-waved. Needs the boards + moderation work (mingo-gj9r, mingo-6phv): a board has an owner/issuer and moderator attestations. The bot delegates from the board admin, so admins must be real first.
2. **Prompts on chain** — a schema + path for a community's bot prompt/config (e.g. /communities/<id>/bot/config), writable only by board admins (policy grant). Governance = admins update it; history is auditable.
3. **Prompt-integrity guarantee** — the HARD open problem: prove the on-chain prompt was the one actually fed to the LLM. Options to research: (a) weakest — the post's provenance/receipt cites the on-chain prompt object hash it claims to have used (trust the operator, but tamper-evident vs the on-chain prompt); (b) the bot posts the (prompt-hash, model, params, output) tuple as a signed record so the community can re-run/audit; (c) TEE/remote-attestation of the inference (heavyweight); (d) accept 'operator-trusted, prompt-transparent' for v1 and note the limitation. Recommend starting at (a)+(b): fully transparent inputs + a re-runnable record, explicitly NOT claiming deterministic-inference proof.

## UI
- 🤖 badge on the bot's byline; a distinct 'community bot' card style; the receipt/provenance drawer shows: signed by <bot>@... under warrant from <board admin>, using prompt <on-chain object + hash>, model/params.
- The bot has its own Profile (agent identity).

## Delegator decision: BOARD OWNER (chosen). Each board's admin warrants that board's bot.

## Status: DESIGN — blocked on prerequisites (admins/boards + on-chain prompt schema). Do NOT build until boards+moderation land. Then: design the prompt schema + governance policy, the warrant issuance UX (admin approves the bot's warrant), the tick runner (a server/cron that reads prompts + activity, calls the LLM, submits agent-signed posts), and the provenance/robot UI.
