# SPDX-License-Identifier: AGPL-3.0-only
FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p zrotext-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 zrotext
COPY --from=build /src/target/release/zrotext-server /usr/local/bin/zrotext-server
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/zrotext-server"]
