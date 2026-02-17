# Multi-stage build for Disentangle Protocol node
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Copy the entire workspace
COPY . .

# Build the release binary
RUN cargo build --release --bin disentangle-node

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies (ca-certificates for TLS, curl for healthchecks)
RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from builder stage
COPY --from=builder /app/target/release/disentangle-node /usr/local/bin/

# Expose P2P and RPC ports (defaults 9000 and 8000)
EXPOSE 9000 8000

ENTRYPOINT ["disentangle-node"]
