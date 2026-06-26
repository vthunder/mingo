---
# mingo-lepc
title: 'Cleanup post-split: crates subfolder, READMEs'
status: in-progress
type: task
priority: normal
created_at: 2026-06-26T10:14:52Z
updated_at: 2026-06-26T10:23:48Z
parent: mingo-ii2i
---

Post-split tidy: (1) move sbo crates into a crates/ subfolder so the repo root isn't busy; (2) move the reference-impl README from mingo back to sbo (with the crates), fix drift; (3) amend sbo's top README note (impl now local; mingo is an example app); (4) write a new mingo app README.

- [x] Moved sbo crates -> crates/; Cargo.toml members=crates/* + path deps; builds green (sbo commit 8e1124c)
- [~] mingo git dep: stays pinned to pre-move 8d66ec7 (unaffected); post-move resolution is name-based (crates/sbo-core) but UNVERIFIED until sbo is pushed
- [x] crates/README.md: moved + drift-fixed (removed auth-demo/sbo-auth CLI, completed crate list, fixed paths, real sbo domain cmds, mingo pointer); sbo commit cc284b1
- [x] Amended sbo top README note (impl local in crates/; mingo is example app)
- [x] New mingo README describing the app; mingo commit 73d9c46
- [ ] BLOCKED: push both repos — SSH agent dropped its GitHub identity mid-session; needs ssh-add

## Status: local-complete, push blocked

All edits done + committed locally. Unpushed: sbo (8e1124c crates move, cc284b1 readme) and mingo (73d9c46 readme). Push blocked because the SSH agent lost its GitHub key (`ssh-add -l` = no identities; ~/.ssh/id_ed25519 is passphrase-protected). Resume: `ssh-add ~/.ssh/id_ed25519`, then `cd ~/src/sbo && git push origin main` and `cd ~/src/mingo && git push origin main`. Also moved docs/daemon-debugging.md from mingo to sbo (daemon-generic). Optional later: bump mingo sbo pin to the post-move rev (verify cargo resolves crates/sbo-core by name).
