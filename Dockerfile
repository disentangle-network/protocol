# Multi-stage build for Disentangle Protocol node
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Copy the entire workspace
COPY . .

# Build the release binary
RUN cargo build --release --bin disentangle-node

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r disentangle && \
    useradd -r -g disentangle -u 1000 -d /data -m disentangle

COPY --from=builder /app/target/release/disentangle-node /usr/local/bin/

USER 1000
WORKDIR /data

EXPOSE 9000 8000

ENTRYPOINT ["disentangle-node"]
