---
# mingo-n022
title: Deploy trustless-fast-sync + attestor fixes (merge sbo branch, deploy daemon + IdP /admin/provision)
status: todo
type: task
priority: high
created_at: 2026-07-07T21:56:56Z
updated_at: 2026-07-07T21:56:56Z
---

All validated e2e (mingo-hqp2) but on branches, not in prod. To land:
1. sbo branch fix/attestor-owner-and-evidence (5 commits: signature-rooted evidence, attestation owner, attest floor-lookup, email self-loop resolve fix, key-rooted claim+cert preset/CLI) -> merge to sbo main.
2. mingo: bump SBO_REV + sbo-core pin to the merged sbo commit -> CI image-deploy daemon (da.sandmill.org).
3. mingo /admin/provision (mingo-idp, committed 9c05f29) -> deploy to the 'mingo' dokku app (git push dokku-mingo) + set MINGO_ADMIN_TOKEN if enabling.
Note: da.sandmill.org full-replays so the client verifier + resolve fix are dormant there; deploy carries them into the image for actual fast-sync clients. Consider the sbo-4arq (bare-key owner) hardening before/with this.
