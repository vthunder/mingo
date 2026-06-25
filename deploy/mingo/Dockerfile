# syntax=docker/dockerfile:1
# mingo-idp (the mingo.place primary BrowserID IdP) → mingo.place. Also serves
# the static mingo-web SPA same-origin (so the IdP session cookie is first-party).
#
# cargo-chef layering caches the dependency compile (keyed on Cargo.lock). The
# SPA (mingo-web) is copied in the RUNTIME stage as the LAST layer, so an
# SPA-only change (app.js/css/html) reuses the cached binary entirely and
# deploys in seconds without touching Rust.
#
# Build context = repo root. Selected per-app via:
#   dokku builder-dockerfile:set mingo dockerfile-path deploy/mingo/Dockerfile
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo chef cook --release -p mingo-idp --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
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
