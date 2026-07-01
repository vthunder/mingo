---
# mingo-9vck
title: Audit /sys/* lookups for hardcoded creator (genesis-mode bug class)
status: completed
type: task
priority: normal
created_at: 2026-06-30T22:05:51Z
updated_at: 2026-07-01T11:57:43Z
---

The genesis-mode regression (fixed in sbo 8c78a4c) was check_root_policy_exists looking up /sys/policies/root with a hardcoded creator "sys"; under Mode-B (domain-certified) genesis the sys identity is email-rooted (sys@mingo.place) so the object's creator is the email form, the lookup missed it, and the daemon silently disabled ALL policy enforcement. See [[genesis-mode-root-policy-creator-bug]].

## Tasks
- [x] grep the daemon/core for other get_object(...) calls with a hardcoded creator (esp. "sys") or other assumptions that sys is name-rooted, that would break under an email-rooted sys.
- [x] Add a regression/integration guard so a Mode-B genesis can't silently fall into genesis mode (e.g. assert enforcement after genesis). — sbo 5d5b4fa

## Audit findings (2026-07-01)

**Result: clean.** `check_root_policy_exists` (validate.rs:577, the sole genesis-mode gate) was the ONLY production call site of the hardcoded-creator class. It is now creator-agnostic (`get_first_object_at_path_id`) as of 8c78a4c. No other genuine bugs of the same class.

- All other `/sys/*` existence lookups use `get_first_object_at_path_id` (creator-agnostic): validate.rs:78/93/195/258/356/664, main.rs:273/322, sync.rs:1097, http.rs:395 (/v1/dnssec), db.rs:550.
- Update/transfer/collision lookups (validate.rs:255/602/806) resolve creator dynamically via `resolve_creator` then fall back to creator-agnostic — correct pattern, would have handled email-rooted sys.
- Policy index (`resolve_policy`/`put_policy`, db.rs:221/233) keys purely on path, never creator — enforcement write side is creator-independent.
- Remaining hardcoded "sys" literals are NOT creator lookups: `Id::new("sys")` is an object id under /sys/names (presets.rs); filesystem repo paths (main.rs); `extract_namespace_owner` returns "sys" for grant/path matching; rest are test fixtures.

**Flagged (out of scope):** name-claim→pubkey index (sync.rs:1166) is keyed on signing pubkey; under browserid key rotation an email-rooted identity's name↔key mapping could fragment. Different bug class — noted only.

## Regression guard plan (task 2)
1. Startup invariant (strongest): expose `pub fn root_policy_present(state)` wrapper over `check_root_policy_exists`; at repo load in main.rs assert that if any confirmed block > genesis exists then root policy Exists — else loud error/refuse. Directly catches the silent-genesis symptom.
2. Test guard: extend `dnssec_repro_tests` (validate.rs:859+) with an explicit assertion that after a `sys@<domain>`-created root policy, `check_root_policy_exists` == Exists AND a garbage /sys/dnssec write is denied. Locks the fix against a future hardcoded-creator reintroduction.

## Summary of Changes

Audit (task 1): clean — the fixed `check_root_policy_exists` was the only production call site of the hardcoded-creator class (details above).

Regression guard (task 2) — sbo commit 5d5b4fa:
- `validate::root_policy_present(state)` public wrapper over `check_root_policy_exists`.
- Startup invariant (main.rs, after DNS check): for each repo synced past genesis (head >= first_block), open state and assert root policy present; loud `tracing::error!` (operator-visible) if absent — the silent-genesis symptom. Non-fatal to avoid bricking on edge cases.
- Regression test `root_policy_present_finds_email_rooted_creator` (validate.rs): asserts the creator-agnostic lookup finds a `sys@mingo.place`-created root policy; reintroducing a hardcoded creator would fail it.

Not yet deployed: commits 420d192 + 5d5b4fa are on sbo branch `fix/stho-stable-repo-identity`, not pushed/pinned in mingo. Deploy tracked on [[mingo-stho]].
