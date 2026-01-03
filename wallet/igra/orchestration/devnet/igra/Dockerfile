# syntax=docker/dockerfile:1.4

FROM rust:1.90-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      git \
      clang \
      cmake \
      protobuf-compiler \
      pkg-config \
      libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Use the local build context (already contains the repo); avoids cloning a remote and ensures local changes are built.
COPY . /src

RUN cargo build --release -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/rusty-kaspa/target/release/kaspa-threshold-service /app/kaspa-threshold-service
COPY --from=builder /src/rusty-kaspa/target/release/fake_hyperlane_ism_api /app/fake-hyperlane-ism
COPY wallet/igra/orchestration/devnet/igra/entrypoint.sh /app/entrypoint.sh

ENV KASPA_DATA_DIR=/data/igra

EXPOSE 8088

ENTRYPOINT ["/app/entrypoint.sh"]
