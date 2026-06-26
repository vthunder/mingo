---
# mingo-lepc
title: 'Cleanup post-split: crates subfolder, READMEs'
status: in-progress
type: task
priority: normal
created_at: 2026-06-26T10:14:52Z
updated_at: 2026-06-26T10:14:52Z
parent: mingo-ii2i
---

Post-split tidy: (1) move sbo crates into a crates/ subfolder so the repo root isn't busy; (2) move the reference-impl README from mingo back to sbo (with the crates), fix drift; (3) amend sbo's top README note (impl now local; mingo is an example app); (4) write a new mingo app README.

- [ ] Move sbo crates -> crates/ in sbo; update Cargo.toml members + path deps; build green
- [ ] Verify mingo git dep still resolves with crates in subfolder
- [ ] Move + drift-fix reference-impl README into sbo (crates/README.md)
- [ ] Amend sbo top README note
- [ ] New mingo README (the app)
- [ ] Push both repos
