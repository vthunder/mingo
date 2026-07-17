# syntax=docker/dockerfile:1
# sbo-daemon (the generic SBO DA gateway / read+submit API) → da.sandmill.org.
#
# The daemon is application-agnostic and lives in vthunder/sbo. This image builds
# it from that repo at a pinned rev (SBO_REV), then layers mingo's deploy config
# (the app-506 seed in entrypoint.sh + config.toml) on top — code in sbo, app
# config in mingo. Bump SBO_REV (keep in sync with the sbo-core git pin in
# ../../Cargo.toml) to adopt daemon changes.
#
# Bundled rocksdb (not system librocksdb): bookworm's 8.9.1 lacks C-API symbols
# librocksdb-sys 0.16 (rocksdb 8.10 bindings) needs, so linking system fails.
#
# Build context = mingo repo root (for config.toml + entrypoint.sh). The daemon
# source is cloned from git, so the context need not contain the sbo crates.
# Base pinned to a specific toolchain (not the moving `rust:1` tag) so the
# rocksdb dependency layer stays cached across deploys.
#
# Dependency caching (mingo-e1dd): the full third-party tree (rocksdb, risc0,
# frame-metadata, rustls…) is compiled with cargo-chef in a stage keyed ONLY on
# the dependency graph (recipe.json), so it becomes a durable Docker IMAGE LAYER.
# Dokku persists image layers across deploys (unlike BuildKit `--mount=type=cache`
# mounts, which it does NOT), so a code-only SBO_REV bump reuses the cooked deps
# and recompiles only the changed sbo workspace crates. recipe.json is a
# content-stable projection of the deps, so it changes (and re-cooks) only when
# Cargo.lock/manifests change, not on every source edit.
FROM rust:1.93-bookworm AS chef
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler git \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-chef --locked --version "^0.1"
WORKDIR /src

# Planner: clone the pinned source and distill the dependency graph to recipe.json.
FROM chef AS planner
ARG SBO_REV=65901c0
RUN git clone https://github.com/vthunder/sbo . \
    && git checkout "$SBO_REV"
RUN cargo chef prepare --recipe-path recipe.json

# Builder: cook deps (cached image layer, invalidated only by recipe.json), then
# build the daemon against the real source (only changed workspace crates rebuild).
FROM chef AS build
ARG SBO_REV=65901c0
COPY --from=planner /src/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --package sbo-daemon --recipe-path recipe.json
COPY --from=planner /src/ .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release -p sbo-daemon \
    && cp target/release/sbo-daemon /sbo-daemon

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /sbo-daemon /usr/local/bin/sbo-daemon
COPY deploy/sbo-daemon/config.toml /app/config.toml
COPY deploy/sbo-daemon/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
WORKDIR /app
# HOME=/data puts the RocksDB state index (Config::sbo_dir() = $HOME/.sbo) on the
# persistent dokku mount, so redeploys don't wipe state. See entrypoint self-heal.
ENV HOME=/data \
    SBO_HTTP_BIND=0.0.0.0:5000 \
    RUST_LOG=sbo_daemon=info,warn
EXPOSE 5000
CMD ["/app/entrypoint.sh"]
