---
# mingo-3kyo
title: 'Followup: checkpointer as email identity + warrant (drop the baked checkpoint key)'
status: draft
type: task
created_at: 2026-07-17T11:37:01Z
updated_at: 2026-07-17T11:37:01Z
---

Same idea as email-rooted admin, applied to the checkpoint authority. Today the daemon signs checkpoint.v1 with a baked sys-checkpointer key (SBO_CHECKPOINT_KEY), granted create on /sys/checkpoints/** by pubkey in genesis. Could instead be an email identity + a warrant, so there's no baked checkpoint key either — the daemon holds an agent credential warranted to act as the checkpointer identity. Not on the critical path; capture so it isn't lost. Depends on the email-admin migration proving out the pattern first.
