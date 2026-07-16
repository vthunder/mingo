---
# mingo-ydiu
title: 'sbo-daemon: bootstrap repo identity via _sbo DNS discovery instead of baked-in config'
status: draft
type: feature
created_at: 2026-07-15T22:54:19Z
updated_at: 2026-07-15T22:54:19Z
---

Dan's idea (2026-07-16, after regenesis v3): da.sandmill.org should discover mingo.place's repo identity (anchor block, genesis hash) from the _sbo.mingo.place TXT record rather than having it baked into deploy/sbo-daemon/entrypoint.sh's repos.json heredoc. Not urgent — needs more thought.

## Why it's attractive
- Single source of truth: the DNS record IS the canonical identity; today it can silently drift from the daemon config (it was stale from v2 until today with zero visible effect — which proves it's currently decorative for our own infra).
- Regenesis becomes: submit genesis → update DNS → restart daemon (no entrypoint edit + image rebuild + reset-marker dance).
- Dogfooding: our own daemon would use the same discovery/verification path we tell third parties to trust.

## Things to think through
- Trust bootstrap: a poisoned TXT answer must not be able to re-seed the daemon onto an attacker's anchor. The record should be DNSSEC-validated (the stack already has RFC 9102 capture machinery) and/or pinned: e.g. discovery may only move the anchor FORWARD on the same app id, never change chain/app.
- State transitions: on genesis mismatch with local state, refuse-and-log by default; auto-wipe only behind an explicit operator flag (the current reset-marker is effectively manual consent — keep an equivalent).
- Availability: DNS down at boot must not brick the daemon — cache last-known-good discovery in /data and boot from it, re-checking in the background.
- Propagation races during a regenesis window (old TXT cached): TTL discipline, and the forward-only rule makes stale answers safe (they just delay the flip).
- Where: implementation in sbo repo (sbo-daemon config, e.g. `discover = "mingo.place"` replacing the repos.json seed); mingo side shrinks entrypoint to the wipe-consent logic. The sbo CLI's DNS dialect (pin cc207f8+) presumably has the TXT parsing to reuse.
