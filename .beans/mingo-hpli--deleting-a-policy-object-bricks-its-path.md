---
# mingo-hpli
title: Deleting a policy object bricks its path
status: todo
type: bug
priority: high
created_at: 2026-09-18T23:09:12Z
updated_at: 2026-09-18T23:09:12Z
---

Deleting a policy object leaves its path governed by a policy that no longer exists. Every subsequent write there is denied `No matching grant`, and the path cannot be recovered without the daemon rebuilding its policy index.

**Observed 2026-09-18** while adding `mingo create-community`:

1. `/communities/agents/community` + `/communities/agents/root` created (descriptor + community policy). Both confirmed.
2. Both deleted with the sys key (`govern` on `/**` from the hub root).
3. Both reads return 404 — the objects are gone.
4. Every write under `/communities/agents/` is now denied:
   `Policy denied Create on /communities/agents/ by sys@mingo.place: No matching grant`
5. The identical command against an unused id (`agentsprobe`) succeeds immediately.

So the denial is path-specific and survives the objects' deletion. The ancestor walk still resolves a policy at `/communities/agents/` — one that is not there — instead of falling through to the hub root, where `admin` holds `post` on `/**` (and `post` does cover `Create`: `evaluate.rs` ~line 108).

**Not a mempool artifact.** `pending::DEFAULT_TTL_SECS` is 60s and the block persisted for many minutes.

**Impact.** A community id is effectively burned once its policy has been deleted — the path is bricked for writes even though it reads as empty. For a public forum that is a user-visible URL slug lost for good. More generally, "delete a policy to fall back to the parent" does not work, which is a reasonable thing to expect of a delegation model.

- [ ] clear the policy index entry when a `policy.v2` object is deleted
- [ ] confirm the ancestor walk falls through to the nearest *existing* ancestor policy
- [ ] decide the intended semantics explicitly: is deleting a policy meant to mean "inherit the parent" or "deny everything"? Denying everything with no way back is the worst of both
- [ ] a stale entry should at least log distinguishably — `No matching grant` gives no hint the governing policy is a ghost
- [ ] does a daemon resync rebuild the index and recover the path? (Likely, but unverified — the recovery story matters)
