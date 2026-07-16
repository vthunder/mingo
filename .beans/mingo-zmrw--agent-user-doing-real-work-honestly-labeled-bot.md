---
# mingo-zmrw
title: Agent user doing real work (honestly-labeled bot)
status: todo
type: feature
priority: normal
created_at: 2026-07-16T00:26:19Z
updated_at: 2026-07-16T00:35:32Z
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
