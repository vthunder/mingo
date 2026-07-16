---
# mingo-chzb
title: 'Passport: implement with vouch + badges surfaced'
status: completed
type: feature
priority: normal
created_at: 2026-07-15T19:57:49Z
updated_at: 2026-07-16T01:00:46Z
parent: mingo-y9gb
---

Make the passport real: vouch button on author names, badges next to authors in threads, memberships listed. Depends on seed data making passports non-empty. Stretch: a second tiny RP honoring mingo passports (reputation travels).

## Summary
Passport SHIPPED (overnight). Badges, Member-of as board pills (not raw roles), Vouched-by identicon rows. Vouch button on others' passports (writes vouch attestation.v1 mirroring joinHub, deterministic id). Author avatars+names across feed/thread/comments link to passports. Render verified live light/dark. AWAITS ON-DEVICE: the live vouch WRITE (needs signed-in session; assembly mirrors proven joinHub path).
