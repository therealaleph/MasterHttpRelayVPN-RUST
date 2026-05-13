# Multi-stage build for the mhrv-tunnel-node service.
#
# Build stage compiles a release binary on a recent stable Rust.
# Dependency caching is done via `cargo-chef`: a separate layer cooks
# just the dependencies first, so warm rebuilds where only `src/`
# changes reuse that layer and skip recompiling crates.
#
# This intentionally avoids BuildKit `--mount=type=cache` directives so
# the Dockerfile builds on classic Docker daemons too — notably Cloud
# Run's `gcloud run deploy --source .` builder, which does not enable
# BuildKit (see issue #620).
#
# Runtime stage is `debian:bookworm-slim` for libc compatibility (the
# binary dynamically links against glibc) plus `ca-certificates` so HTTPS
# upstream URLs from `data` ops can do TLS handshake. Image stays under
# 100 MB end-to-end.
#
# Runs as a dedicated non-root `tunnel` user (uid 1000) — the service
# never needs to write outside its own process state, so no reason to
# give it root.
#
# Required env vars:
#   TUNNEL_AUTH_KEY   shared secret matching `const TUNNEL_AUTH_KEY` in
#                     CodeFull.gs. The service refuses every request
#                     without a matching key.
#   PORT              HTTP listen port. Defaults to 8080 if unset.
#
# Health: the service responds to `GET /` with a small status JSON. Add
# `--health-cmd 'curl -fsS http://localhost:8080/ || exit 1'` on the
# `docker run` if you want compose-level health gating.

FROM rust:1.90-slim AS chef
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN cargo build --release --bin tunnel-node && \
    cp /app/target/release/tunnel-node /usr/local/bin/tunnel-node

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 1000 --no-create-home --shell /usr/sbin/nologin tunnel

COPY --from=builder /usr/local/bin/tunnel-node /usr/local/bin/tunnel-node

USER tunnel
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["tunnel-node"]
