---
# mingo-c70r
title: browserid.me (dokku app 'id') has NO persistent storage — /data wiped every deploy
status: completed
type: bug
priority: high
created_at: 2026-07-01T21:47:09Z
updated_at: 2026-07-01T21:49:58Z
---

storage:list id is empty; /data lives inside the container, so every deploy/restart wipes:
- accounts (users lose their identities; observed: danmills@sandmill.org reverted to state:unknown, U1/U2 split gone)
- sessions (users signed out each deploy)
- broker-key.json — the broker's Ed25519 signing key REGENERATES each deploy, invalidating any certs/assertions it issued as an IdP.

Confirmed 2026-07-01: startup log 'migrations current=0' (fresh DB) after a deploy; /data files all dated at deploy time; ssh dokku storage:list id returns nothing.

## Fix
Add a dokku persistent mount for /data (mirror sbo-daemon, which maps /var/lib/dokku/data/storage/sbo-daemon -> /data):
- dokku storage:ensure-directory id
- dokku storage:mount id /var/lib/dokku/data/storage/id:/data
- dokku ps:restart id
First mount starts empty (current data already fresh), then persists across deploys.

## Follow-ups
- Verify broker-key.json is generated-once-then-persisted (not regenerated when present) so the key is stable once /data persists.
- Consider disabling zero-downtime checks (like sbo-daemon) if the DB is single-writer.

### FIXED 2026-07-01
- dokku storage:ensure-directory id → /var/lib/dokku/data/storage/id
- dokku storage:mount id /var/lib/dokku/data/storage/id:/data
- dokku ps:restart id
Verified: storage:report shows deploy+run mounts -v /var/lib/dokku/data/storage/id:/data; app serving (well-known 200); /data now host-backed. Accounts/sessions/broker-key.json persist going forward.
NOTE: the current DB is fresh (the pre-fix wipe already happened), so the old U1/U2 split is gone. Follow-up to verify next deploy: broker-key.json is generated-once-then-persisted (stable key across deploys), not regenerated when present.
