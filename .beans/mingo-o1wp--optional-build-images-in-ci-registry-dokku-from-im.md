---
# mingo-o1wp
title: 'Optional: build images in CI → registry → dokku from-image'
status: todo
type: feature
priority: deferred
tags:
    - deploy
created_at: 2026-06-25T19:12:29Z
updated_at: 2026-06-25T19:12:29Z
---

Currently dokku builds on the host via git push (cargo-chef Dockerfiles). Moving the build to GitHub Actions with a persistent registry cache + 'dokku git:from-image' removes build load/variance from the host. Deferred by choice.
