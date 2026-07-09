---
# mingo-v0hw
title: turbo submit_raw has no timeout -> a slow DA submit stalls the entire sync loop
status: todo
type: bug
priority: normal
created_at: 2026-07-07T22:04:47Z
updated_at: 2026-07-07T22:04:47Z
---

Found 2026-07-07 during the mingo-hqp2 e2e test. sbo-daemon/src/turbo.rs uses reqwest::Client::new() with NO timeout. submit_raw().await is called inline in the single-threaded sync loop (attest_if_due, checkpoint_if_due, IPC submit). If the DA endpoint hangs, the whole sync task blocks indefinitely (observed: attestor appeared 'stalled' — HTTP alive, sync task blocked on a submit). Fix: build the reqwest client with a connect+request timeout (e.g. Client::builder().timeout(30s)), and/or move submits off the sync path. Low-risk, high-value robustness fix.
