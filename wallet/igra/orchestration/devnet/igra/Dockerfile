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

ARG IGRA_REPO=https://github.com/reshmem/rusty-kaspa.git
ARG IGRA_REF=devel
ARG CARGO_TARGET_DIR=/src/target

WORKDIR /src
RUN git clone --depth 1 --branch ${IGRA_REF} ${IGRA_REPO} /src/rusty-kaspa

ENV CARGO_BUILD_JOBS=1 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C codegen-units=1" \
    CARGO_TARGET_DIR=${CARGO_TARGET_DIR}

WORKDIR /src/rusty-kaspa
RUN mkdir -p ${CARGO_TARGET_DIR}

RUN cargo build --release -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api

FROM debian:bookworm-slim AS runtime
ARG CARGO_TARGET_DIR=/src/target

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder ${CARGO_TARGET_DIR}/release/kaspa-threshold-service /app/kaspa-threshold-service
COPY --from=builder ${CARGO_TARGET_DIR}/release/fake_hyperlane_ism_api /app/fake-hyperlane-ism
COPY wallet/igra/orchestration/devnet/igra/entrypoint.sh /app/entrypoint.sh

ENV KASPA_DATA_DIR=/data/igra

EXPOSE 8088

ENTRYPOINT ["/app/entrypoint.sh"]
