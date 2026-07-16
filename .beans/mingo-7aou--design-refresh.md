---
# mingo-7aou
title: Design refresh
status: completed
type: feature
priority: normal
created_at: 2026-07-16T00:25:52Z
updated_at: 2026-07-16T01:00:46Z
parent: mingo-y9gb
---

A focused visual pass to lift perceived quality without a rewrite. The current single-file style.css is a decent base.

## Scope
- Typography + spacing rhythm; card and feed-row polish.
- Identity-derived identicons/avatars next to authors (free, and reinforces the identity theme — derive from the identity email/key).
- Dark mode (prefers-color-scheme; the receipt drawer and modals already need to look right in both).
- Community/board visual identity (color or glyph per board).
- Keep it a SKIN over the existing structure; don't restructure the SPA.
- Make sure new surfaces built this session (receipt drawer, poster modal, identity chooser) are covered by the refresh.

## Summary
Design refresh SHIPPED + live-verified (2026-07-16 overnight). Token-based CSS system, full dark mode across every surface, deterministic inline-SVG identicons per identity, per-board color dots/pills, gradient wordmark, receipt emoji to inline-SVG pill. Verified light/dark/mobile on live mingo.place across feed/thread/passport/receipt drawer; zero console errors. All app.js-wired ids/classes preserved.
