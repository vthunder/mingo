---
# mingo-vzo1
title: 'v0.3 rollout: re-provision the live attestor with a constrained credential before deploying constraint-enforcing mingo-idp'
status: in-progress
type: task
priority: high
created_at: 2026-07-09T16:37:11Z
updated_at: 2026-07-09T16:44:04Z
---

The delegation-chain v0.3 (browserid-ng d1bb886, mingo-idp local) makes the P_cert constraint REQUIRED and enforced at mint: an empty/missing constraint authorizes nothing. The currently-LIVE attestor (attestor2@mingo.place, mingo-02ta) was provisioned pre-v0.3, so its credential (~/agent-credential.json) has no constraint. When mingo.place is redeployed with the v0.3 constraint-enforcing code, the attestor's ~24h cert re-mint will be refused (constraint authorizes nothing) and the attestor will stop once its cert expires.

Before deploying v0.3 to mingo.place:
- [ ] Create a new agent key at browserid.me/agents (v0.3 UI) delegated from dan@mingo.place with names:["attestor2"] (reserve is idempotent since the same account already owns attestor2)
- [ ] Update SBO_AGENT_CREDENTIAL on the da host with the new credential; re-run provision-agent if needed
- [ ] Then deploy v0.3 mingo.place + browserid.me

Alternative considered + rejected: grandfather empty constraints as authorize-all (reintroduces the unconstrained case the design deliberately disallows). Current live system is all v0.2 and unaffected until v0.3 is deployed.

## Rollout in progress (2026-07-09)
- [x] browserid.me broker deployed v0.3 (a3081d9): /provision/reserve live, /agents v0.3 UI live
- [x] mingo-idp CORS fix for cross-origin reserve (8717105)
- [ ] mingo.place deploying v0.3 (constraint enforcement — this is where the old empty-constraint attestor credential stops re-minting)
- [ ] User: revoke old attestor key, create new attestor2 key via /agents (names:[attestor2]), update SBO_AGENT_CREDENTIAL, re-test
