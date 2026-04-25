#
# Multi-stage build for the mhrv-tunnel-node service.
#
# Build stage compiles a release binary against rust 1.85 (matches MSRV in
# Cargo.toml). Cargo's incremental build cache is mounted via BuildKit
# `--mount=type=cache` so a `docker build` against an unchanged dependency
# tree skips re-downloading + re-compiling crates — first build ~6 min,
# warm builds ~30 s.
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

FROM rust:1.85-slim AS builder
WORKDIR /app
# Copy lockfile so cargo uses pinned versions identically to local builds.
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
# Plain build without BuildKit cache mounts — Google Cloud Build does not
# support BuildKit's `--mount=type=cache` syntax, and `gcloud run deploy
# --source .` uses Cloud Build under the hood. Local `docker build` with
# BuildKit still works (it just won't cache across builds).
RUN cargo build --release --bin tunnel-node && \
    cp /app/target/release/tunnel-node /usr/local/bin/tunnel-node

FROM debian:bookworm-slim
# `ca-certificates` for HTTPS upstream targets; nothing else needed at
# runtime since the binary is statically linked against musl-equivalents
# only for the parts that don't touch glibc.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. The service does no filesystem writes outside
# /tmp, so a static-uid unprivileged user is sufficient and prevents
# accidental host-FS writes if the container is volume-mounted.
RUN useradd --system --uid 1000 --no-create-home --shell /usr/sbin/nologin tunnel

COPY --from=builder /usr/local/bin/tunnel-node /usr/local/bin/tunnel-node

USER tunnel
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["tunnel-node"]
