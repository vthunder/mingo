---
# mingo-2xnj
title: 'Domain self-cert: end-to-end daemon test'
status: todo
type: task
priority: normal
created_at: 2026-07-04T14:57:51Z
updated_at: 2026-07-04T14:57:51Z
---

Existing domain self-cert tests are offline/structural (sbo-core check_domain_binding with a directly-supplied key; mingo-app genesis ordering + Auth-Evidence ref with fake bytes). Add an END-TO-END daemon test: apply a genesis whose domain.v1 references a seeded dnssec.v1, and assert verify_domain_self_cert passes (Domain self-certified) at a genesis-time inclusion_time; tamper the seeded proof or the domain key and assert it fails. Needs a real (or fixture) RFC-9102 chain — capture one via 'sbo domain evidence' and commit as a test fixture, or gate on network like live_dnssec_end_to_end. Prereq for enabling hard-reject.
