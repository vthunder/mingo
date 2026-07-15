---
# mingo-6tsc
title: 'Poster-enable polish: freeze modal on return from consent hop'
status: completed
type: task
priority: normal
created_at: 2026-07-15T18:49:49Z
updated_at: 2026-07-15T18:57:24Z
---

Follow-up to mingo-hlka: after the same-tab consent round-trip, the bfcache-restored page still shows the enable modal with Continue active for the couple of seconds until pickupPoster confirms — a tap would bounce the user back to browserid. Freeze the modal (disable Continue, status 'checking…') on pageshow, thaw with a retry hint if the pickup comes back non-approved.

## Summary of Changes

posterModal (was posterModalClose) now exposes close/freeze/thaw. pageshow(persisted) freezes the modal (Continue aria-disabled + 'Checking whether your approval landed…') before pickupPoster runs; pickup thaws it with a retry hint on any non-approved outcome (including poll errors and giving up while pending), and close(true)s it on approval as before.
