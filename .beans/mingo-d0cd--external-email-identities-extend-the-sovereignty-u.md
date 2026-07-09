---
# mingo-d0cd
title: 'External-email identities: extend the sovereignty upgrade so they can become key-rooted'
status: todo
type: feature
priority: normal
created_at: 2026-07-09T20:44:02Z
updated_at: 2026-07-09T20:44:02Z
parent: mingo-sux8
---

Users can now choose their external email (e.g. danmills@sandmill.org) as their public identity instead of a @mingo.place handle (shipped in the identity-chooser change). But the browserid->key sovereignty upgrade (resolve.rs email->name override + canonical-identity reverse edge) is scoped to the PRIMARY domain (@mingo.place), so an external email stays email-rooted FOREVER — a fresh browserid Auth-Cert per write, never graduating to cheap key-rooted writes.

Extension (user's idea, ~bounded): let an external-email identity pin a key via a name record keyed on the full email — e.g. /sys/names/<full@email.com> (or a /sys/external-names/** namespace) holding an identity.v1 key-rooted record. Then resolve_controller for a foreign-domain email would also consult that record and return Controller::Key when present, giving external emails the same graduation path.

Work:
- [ ] resolve_controller (sbo-core/resolve.rs): for a foreign-domain @-email, look up a name record keyed on the full email; key-rooted -> Controller::Key, else Controller::Email (browserid fallback). Currently foreign-domain emails skip name lookup entirely.
- [ ] name-claim gate (validate.rs ~714): claiming /sys/names/<full-email> requires browserid attribution to THAT email (the anti-hijack gate, generalized from <local>@<primary-domain> to the full email).
- [ ] Decide namespace: reuse /sys/names/ (keyed on the email string) vs a dedicated /sys/external-names/**. Consider collision with local-handle namespace + display.
- [ ] mingo-web: offer 'pin a key / go sovereign' for external-email users once supported.

Depends on the identity model (mingo-sux8). Relates to the 'require DNSSEC?' decision — if DNSSEC is universally required, the per-write cost is uniform and this is purely about the key-rooted cheap path.
