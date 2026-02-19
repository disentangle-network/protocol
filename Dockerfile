# Multi-stage build for Disentangle Protocol node
FROM --platform=$BUILDPLATFORM rust:1.85-bookworm AS builder

ARG TARGETPLATFORM
ARG TARGETARCH

WORKDIR /app

# Install cross-compilation toolchains if needed
RUN case "$TARGETARCH" in \
        arm64) apt-get update && apt-get install -y gcc-aarch64-linux-gnu && \
               rustup target add aarch64-unknown-linux-gnu ;; \
        amd64) rustup target add x86_64-unknown-linux-gnu ;; \
    esac

# Copy the entire workspace
COPY . .

# Build the release binary for the target architecture
RUN case "$TARGETARCH" in \
        arm64) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc && \
               cargo build --release --bin disentangle-node --target aarch64-unknown-linux-gnu && \
               cp target/aarch64-unknown-linux-gnu/release/disentangle-node /app/disentangle-node ;; \
        amd64) cargo build --release --bin disentangle-node --target x86_64-unknown-linux-gnu && \
               cp target/x86_64-unknown-linux-gnu/release/disentangle-node /app/disentangle-node ;; \
    esac

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r disentangle && \
    useradd -r -g disentangle -u 1000 -d /data -m disentangle

COPY --from=builder /app/disentangle-node /usr/local/bin/

USER 1000
WORKDIR /data

EXPOSE 9000 8000

ENTRYPOINT ["disentangle-node"]
