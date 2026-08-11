# syntax=docker/dockerfile:1
# mingo-idp (the mingo.place primary BrowserID IdP) → mingo.place. Also serves
# the static mingo-web SPA same-origin (so the IdP session cookie is first-party).
#
# cargo-chef layering caches the dependency compile (keyed on Cargo.lock). The
# SPA (mingo-web) is copied in the RUNTIME stage as the LAST layer, so an
# SPA-only change (app.js/css/html) reuses the cached binary entirely and
# deploys in seconds without touching Rust.
#
# Built in CI (.github/workflows/deploy-mingo.yml) and deployed by IMAGE via
# `dokku git:from-image mingo` — the host never compiles. Build context = repo
# root. (Legacy on-host path: `dokku builder-dockerfile:set mingo
# dockerfile-path deploy/mingo/Dockerfile` — cleared for image deploys, see the
# Makefile deploy-mingo-onhost note.)
# Base pinned to a specific toolchain (not the moving `rust:1` tag): a tag bump
# changes the image digest and invalidates every cached layer below — including
# the slow cargo-chef install and the dependency build. Bump deliberately on
# Rust upgrades (keep in sync with deploy/sbo-daemon/Dockerfile).
FROM rust:1.93-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
# Deps cook into an IMAGE LAYER (no target cache mount): `--mount=type=cache`
# contents persist in neither dokku nor GitHub's type=gha layer cache, so the
# cook must live in the layer itself to survive across builds (same pattern as
# ../sbo-daemon/Dockerfile, mingo-e1dd). Keyed only on recipe.json → re-cooks
# only when the dependency graph changes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release -p mingo-idp --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release -p mingo-idp \
    && cp target/release/mingo-idp /mingo-idp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /mingo-idp /usr/local/bin/mingo-idp
COPY mingo-idp/static /app/static
# SPA last → SPA-only deploys stop here, reusing every layer above.
COPY mingo-web /app/mingo-web
WORKDIR /app
ENV MINGO_IDP_BIND=0.0.0.0:5000 \
    MINGO_IDP_STATIC=/app/static \
    MINGO_SPA_DIR=/app/mingo-web
EXPOSE 5000
CMD ["mingo-idp"]
