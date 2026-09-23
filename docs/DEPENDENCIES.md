# M0 dependency and provenance record

Toolchain pins: Rust 1.97.1 (`rust-toolchain.toml`), JDK 21, Android Gradle Plugin 8.13.0, Kotlin/Compose compiler 2.2.20, Gradle 8.13 with a distribution SHA-256, compile/target SDK 36, and PostgreSQL 18.6. `Cargo.lock` and `android/app/gradle.lockfile` fix resolved dependencies. CI actions use immutable commit SHAs. Docker build uses the official Rust image and Debian runtime; the Compose database uses the official PostgreSQL image. Production promotion must pin and verify image digests.

Direct Rust application dependencies: Axum (MIT), Tokio (MIT), tokio-postgres (MIT), Serde/serde_json (MIT or Apache-2.0), UUID (Apache-2.0 or MIT), and subtle (BSD-3-Clause). Android direct dependencies: AndroidX Activity/Compose/Core (Apache-2.0), Kotlin (Apache-2.0), and OkHttp (Apache-2.0). Transitive licenses and advisories still need a generated SBOM and review before a public release. No dependency code has been copied into application source.

The application source is `AGPL-3.0-only`; `LICENSE` is the SPDX license-list copy of the AGPLv3 text. The DCO preserves the Linux Foundation notice. Gradle wrapper files are generated upstream tooling; the Gradle distribution carries its own `LICENSE` and `NOTICE`. No SDK package is included yet; future SDK source will receive a separate permissive license and dependency boundary.

The M0 Rust/Android versions are build pins, not a claim that security advisories have been cleared. Update each pin with a compatibility build and dependency review. Official references: [Rust releases](https://blog.rust-lang.org/releases/), [Android Gradle plugin](https://developer.android.com/build/releases/gradle-plugin), [PostgreSQL supported versions](https://www.postgresql.org/support/versioning/).
