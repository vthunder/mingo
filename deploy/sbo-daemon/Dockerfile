# syntax=docker/dockerfile:1
# sbo-daemon (the Mingo DA gateway / read+submit API) → da.sandmill.org.
#
# cargo-chef layering: the dependency compile (including the slow bundled rocksdb
# C++ build) lives in a layer keyed only on Cargo.toml/Cargo.lock, so an
# app-code change recompiles just our crates — never rocksdb. BuildKit cache
# mounts persist the cargo registry + target across deploys on top of that.
#
# Bundled rocksdb (not system librocksdb): bookworm's 8.9.1 lacks C-API symbols
# librocksdb-sys 0.16 (rocksdb 8.10 bindings) needs, so linking system fails.
#
# Build context = repo root. Selected per-app via:
#   dokku builder-dockerfile:set sbo-daemon dockerfile-path deploy/sbo-daemon/Dockerfile
# Base pinned to a specific toolchain (not the moving `rust:1` tag): a tag bump
# changes the image digest and invalidates every cached layer below — including
# the slow cargo-chef install and the bundled-rocksdb dependency build. Bump this
# deliberately when upgrading Rust.
FROM rust:1.93-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /src/recipe.json recipe.json
# Dependency layer — only rebuilds when Cargo.lock changes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo chef cook --release -p sbo-daemon --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
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
