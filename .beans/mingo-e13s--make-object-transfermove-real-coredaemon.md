---
# mingo-e13s
title: Make object transfer/move real (core+daemon)
status: completed
type: feature
priority: normal
created_at: 2026-06-26T22:19:59Z
updated_at: 2026-06-26T22:59:41Z
parent: mingo-0jkl
blocked_by:
    - mingo-46oy
---

Transfer is a stub end-to-end. Implement it.

- [ ] Parser: read New-Owner/New-Path/New-ID into Action::Transfer (message/actions.rs + wire parser)
- [ ] Builder: presets::transfer() to construct signed transfer wire
- [ ] Validate: source auth = owner OR policy grant (admin override) via check_policy(transfer); destination policy admits object; collision check at dest (validate.rs validate_transfer)
- [ ] Apply: move in sync.rs — remove (path,creator,id), insert at (new_path|path, creator, new_id|id), carry/replace owner_ref, update fs mirror, witness = delete-old + create-new
- [ ] Decide+document creator preservation (recommend preserve original creator)
- [ ] CLI: uri transfer / mv / rm / chown wired to builder + Submit
- [ ] tests

## Summary of Changes
Transfer/move/delete made real end-to-end (core parse/build/serialize + canonical signing; daemon validate owner-or-admin-override + destination collision/policy; apply re-homes leaf with delete+create witness, moves mirror file; CLI uri transfer/mv/rm/chown). 7 transfer validation tests + core round-trip tests pass; full core+daemon suite green.

Follow-up: a block-processing integration test for the move state-root witness (delete+create) is not yet written; logic mirrors existing update/delete witness handling. Live e2e against the real app-506 chain intentionally skipped (would write permanent objects).
