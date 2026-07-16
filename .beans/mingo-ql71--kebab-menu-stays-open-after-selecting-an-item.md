---
# mingo-ql71
title: Kebab menu stays open after selecting an item
status: completed
type: bug
priority: normal
created_at: 2026-07-16T23:52:12Z
updated_at: 2026-07-16T23:52:41Z
---

The post card kebab (⋮) menu did not close after selecting an item (Receipt/Edit/Delete). Item handlers (wireEditButtons/wireDeleteButtons/wireReceiptButtons) were wired independently of the popup dismissal model (closeAllMenus) and none of them closed the menu, so it lingered until an outside click or Escape.

## Todos
- [x] Find the menu open/close model and the item handlers
- [x] Add a single choke point that closes the menu on any item select
- [x] node --check passes

## Summary of Changes
Added a single choke point in `wireCardMenus` (mingo-web/app.js): a capture-phase click listener on each `.menu-pop` that calls `closeAllMenus()` when the click lands on a `.menu-item`. Capture phase ensures the menu closes before the item's own handler runs (Edit/Delete swap out the card body via beginEdit/beginDelete). Covers Receipt, Edit, Delete, and any future items without touching each handler.
