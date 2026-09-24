# SPDX-License-Identifier: AGPL-3.0-only
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY web/owner ./web/owner
ARG GIT_COMMIT
ENV GIT_COMMIT=${GIT_COMMIT}
RUN cargo build --locked --release -p zrotext-server -p zrotext-migrator

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 zrotext
COPY --from=build /src/target/release/zrotext-server /usr/local/bin/zrotext-server
COPY --from=build /src/target/release/zrotext-webhook-kek-rewrap /usr/local/bin/zrotext-webhook-kek-rewrap
COPY --from=build /src/target/release/zrotext-migrator /usr/local/bin/zrotext-migrator
COPY deploy/compose/migrations /opt/zrotext/migrations
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/zrotext-server"]
