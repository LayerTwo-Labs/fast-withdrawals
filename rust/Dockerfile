# One image per service, selected with --target:
#   docker build --target api -t fastwithdraw-api .
#   docker build --target wallet -t fastwithdraw-wallet .
# Base images are pinned by digest; update the digest with the tag, eg. from
# `docker buildx imagetools inspect <image:tag>`. The rust digest is for
# RUST_VERSION 1.95.0, so changing the version means changing it too.
ARG RUST_VERSION=1.95.0

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS chef
# The Google Cloud SDK's HTTP client (the gcp-kms feature) links OpenSSL on
# Linux.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version 0.1.73
WORKDIR /workspace

# cargo-chef turns the workspace manifests into a dependency recipe, so
# source-only changes reuse the cached `cook` layer below.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Optional platform support, eg. for Google Cloud (KMS keys and Cloud
# Scheduler's ID tokens): --build-arg FEATURES="fastwithdraw-api/gcp-kms
# fastwithdraw-api/gcp-auth fastwithdraw-wallet/gcp-kms". By default the images
# have no cloud SDKs: PKCS#11 and local keys only.
ARG FEATURES=""
COPY --from=planner /workspace/recipe.json recipe.json
RUN cargo chef cook --locked --release --recipe-path recipe.json \
    --package fastwithdraw-api --package fastwithdraw-wallet --package fastwithdraw-signer \
    --features "$FEATURES"
COPY . .
# Same packages as `cook`, so test-only features (from integration_tests)
# aren't unified into the release binaries.
RUN cargo build --locked --release --bins \
    --package fastwithdraw-api --package fastwithdraw-wallet --package fastwithdraw-signer \
    --features "$FEATURES"

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS api
COPY --from=builder /workspace/target/release/fastwithdraw-api /bin/
ENV LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/bin/fastwithdraw-api"]

# Debian rather than distroless: vendor PKCS#11 modules are loaded at runtime
# and usually need glibc and OpenSSL. Mount the module and signer config.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS wallet
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --no-create-home wallet
COPY --from=builder /workspace/target/release/fastwithdraw-wallet /bin/
COPY --from=builder /workspace/target/release/fastwithdraw-pkcs11 /bin/
USER 65532
ENV LISTEN=0.0.0.0:8080
EXPOSE 8080
RUN ["/bin/fastwithdraw-pkcs11", "--help"]
ENTRYPOINT ["/bin/fastwithdraw-wallet"]
