---
# mingo-46oy
title: uri get/list/post CLI commands
status: completed
type: feature
priority: normal
created_at: 2026-06-26T22:19:59Z
updated_at: 2026-06-26T22:41:09Z
parent: mingo-0jkl
---

Wire the stubbed 'sbo uri get|list|post' commands to existing daemon IPC (GetObject, ListObjects, Submit). post builds+signs wire via presets::post/signed_object using a keyring key (--key). No core changes; create/update already validate+apply. Gives CLI read/write of arbitrary objects.

- [x] uri get <uri> [--proof] -> Request::GetObject
- [x] uri list <uri> [--schema] -> Request::ListObjects
- [x] uri post <uri> --file <f> [--content-type] [--schema] [--owner] [--key] -> build+sign+Request::Submit
- [x] tests: post_object wire roundtrip; uri get/list/--proof verified live against ~/.sbo daemon

## Summary of Changes
Implemented sbo uri get/list/post (were todo!() stubs).
- sbo-core: added presets::post_object (general post builder, optional schema, verbatim content-type) + roundtrip test.
- sbo-cli: wired get->GetObject, list->ListObjects (new parse_sbo_uri_prefix + factored resolve_repo_remainder helper), post->build+sign(keyring)+Submit. Added --proof/--schema/--owner/--key/--content-type args + guess_content_type.
- uri transfer left as explicit not-yet (Tier 2 / mingo-e13s).
Verified live: uri get + --proof (SBOQ) + list against running ~/.sbo daemon (app 506). Did NOT live-post to avoid writing test objects to the real chain; post builder covered by unit test.
Note: keyring is empty after the ~/.sbo move, so a real post needs `sbo key generate`/import first; api_key is present in config.
