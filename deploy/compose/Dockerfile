# SPDX-License-Identifier: AGPL-3.0-only
# The Rust image tag must equal the channel in rust-toolchain.toml. The build
# stage checks this, and rustup auto-install is off, so a mismatch fails the
# build instead of downloading a second toolchain. Move both together.
# Docker publishes the same Official Images to ECR Public:
# https://www.docker.com/blog/news-from-aws-reinvent-docker-official-images-on-amazon-ecr-public/
# Keep the manifest digests when changing the registry.
FROM public.ecr.aws/docker/library/rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS rust-base
ENV RUSTUP_AUTO_INSTALL=0

# cargo-about is built from its pinned crates.io release with its own lockfile.
# This stage does not depend on the ZROtext sources, so a source change reuses
# its cached layer, and BuildKit builds it in parallel with the server.
FROM rust-base AS cargo-about
RUN cargo install --locked --features cli --version 0.9.2 --root /opt/cargo-about cargo-about && \
    rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

FROM rust-base AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN channel="$(grep '^channel = ' rust-toolchain.toml | cut -d '"' -f 2)" && \
    if [ "$channel" != "$RUST_VERSION" ]; then \
      echo "rust-toolchain.toml pins $channel but the build image has $RUST_VERSION" >&2; exit 1; \
    fi && \
    cargo --version
COPY about.toml about.hbs ./
COPY crates ./crates
# Contact issuer compile-time guards also read the dormant schema proposal.
COPY protocol/v1/contact-reader-issuance-storage-proposal.sql ./protocol/v1/contact-reader-issuance-storage-proposal.sql
COPY web/owner ./web/owner
# Compile-time schema guards use the same migration sources as the migrator.
COPY deploy/compose/migrations ./deploy/compose/migrations
ARG GIT_COMMIT
ARG RELEASE_VERSION
ARG WEB_STATIC_SHA256
ARG DEVICE_STREAM_SCHEMA_SHA256
ARG MIGRATION_LAST
ENV GIT_COMMIT=${GIT_COMMIT} \
    RELEASE_VERSION=${RELEASE_VERSION} \
    WEB_STATIC_SHA256=${WEB_STATIC_SHA256} \
    DEVICE_STREAM_SCHEMA_SHA256=${DEVICE_STREAM_SCHEMA_SHA256} \
    MIGRATION_LAST=${MIGRATION_LAST}
RUN cargo build --locked --release -p zrotext-server -p zrotext-migrator
COPY --from=cargo-about /opt/cargo-about/bin/cargo-about /usr/local/cargo/bin/cargo-about
RUN mkdir -p /tmp/zrotext-notices && \
    cargo about generate --locked --fail --manifest-path crates/server/Cargo.toml \
      -o /tmp/zrotext-notices/SERVER about.hbs && \
    cargo about generate --locked --fail --manifest-path crates/migrator/Cargo.toml \
      -o /tmp/zrotext-notices/MIGRATOR about.hbs && \
    { printf 'ZROtext server image third-party notices\n\n'; \
      cat /tmp/zrotext-notices/SERVER /tmp/zrotext-notices/MIGRATOR; \
    } > /tmp/zrotext-notices/THIRD_PARTY_NOTICES && \
    test -s /tmp/zrotext-notices/THIRD_PARTY_NOTICES

FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates perl-base && \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' perl-base)" ge '5.36.0-7+deb12u4' && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 zrotext && \
    install -d -o 10001 -g 10001 -m 0700 /var/lib/zrotext/failover-store
COPY --from=build /src/target/release/zrotext-server /usr/local/bin/zrotext-server
COPY --from=build /src/target/release/zrotext-admin /usr/local/bin/zrotext-admin
COPY --from=build /src/target/release/zrotext-webhook-kek-rewrap /usr/local/bin/zrotext-webhook-kek-rewrap
COPY --from=build /src/target/release/zrotext-billing-risk-review /usr/local/bin/zrotext-billing-risk-review
COPY --from=build /src/target/release/zrotext-migrator /usr/local/bin/zrotext-migrator
COPY LICENSE /usr/share/doc/zrotext/LICENSE
COPY --from=build /tmp/zrotext-notices/THIRD_PARTY_NOTICES /usr/share/doc/zrotext/THIRD_PARTY_NOTICES
COPY deploy/compose/migrations /opt/zrotext/migrations
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/zrotext-server"]
