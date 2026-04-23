FROM rust:1.85-slim AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY src/ ./src/
RUN cargo build --release --bin tunnel-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/tunnel-node /usr/local/bin/
ENV PORT=8080
EXPOSE 8080
CMD ["tunnel-node"]
