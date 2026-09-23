# Dependencies and provenance

Build tools and libraries are pinned in the source tree. Check these files for the current versions:

| Component | Version source |
|---|---|
| Rust toolchain | [`rust-toolchain.toml`](../rust-toolchain.toml) |
| Rust packages | [`Cargo.lock`](../Cargo.lock) |
| Android plugins | [`android/build.gradle.kts`](../android/build.gradle.kts) |
| Android SDK levels and libraries | [`android/app/build.gradle.kts`](../android/app/build.gradle.kts) |
| Gradle distribution and checksum | [`android/gradle/wrapper/gradle-wrapper.properties`](../android/gradle/wrapper/gradle-wrapper.properties) |
| Android resolved dependencies | [`android/app/gradle.lockfile`](../android/app/gradle.lockfile) |
| Container base images | [`deploy/compose/Dockerfile`](../deploy/compose/Dockerfile) and [`deploy/compose/compose.yaml`](../deploy/compose/compose.yaml) |

CI actions are pinned to commit hashes. The [dependency graph workflow](../.github/workflows/android-dependency-graph.yml) submits the Gradle dependency graph from the main branch. GitHub's dependency graph and SBOM provide resolved package inventories; license and advisory checks should use those inventories and the lockfiles.

Application source is licensed under [AGPL-3.0-only](../LICENSE). Third-party tools and libraries retain their own licenses; generated wrapper files and downloaded distributions are not relicensed as application code.
